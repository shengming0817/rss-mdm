#![allow(
    clippy::cognitive_complexity,
    reason = "sequential real transport failure and recovery assertions"
)]
//! Real product Router and embedded Identity; the native peer is supplied by Windows T2.
use super::*;
mod native;
use crate::identity_t2::Browser;
use anyhow::ensure;
use axum::{
    Router,
    http::{Method, StatusCode},
};
use serde_json::{Value, json};
use sqlx::Connection;
const TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const DEVICE: &str = "tls-device";
pub(crate) struct Client {
    browser: Browser,
    router: Router,
    server: tokio::task::JoinHandle<()>,
    app: Arc<crate::api::App>,
    operation: Uuid,
    rule: Uuid,
    rule_revision: u64,
    expiring: Option<Uuid>,
}
impl Drop for Client {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Client {
    pub(crate) async fn start(router: Router, app: Arc<crate::api::App>) -> anyhow::Result<Self> {
        let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse()?,
        )));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let serving = router.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, serving).await.unwrap();
        });
        let mut browser = Browser::default();
        browser.network = Some((
            reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(10))
                .build()?,
            format!("http://{address}"),
        ));
        let login = browser
            .call(
                &router,
                Method::POST,
                &format!("/api/v2/tenants/{TENANT}/login"),
                Some(json!({"login":"admin","password":crate::identity_fixture::PASSWORD})),
            )
            .await?;
        ensure!(
            login.0 == StatusCode::OK,
            "real management login: {:?}",
            login
        );
        Ok(Self {
            browser,
            router,
            server,
            app,
            operation: Uuid::new_v4(),
            rule: Uuid::new_v4(),
            rule_revision: 0,
            expiring: None,
        })
    }
    async fn call(
        &mut self,
        method: Method,
        suffix: &str,
        body: Option<Value>,
    ) -> anyhow::Result<(StatusCode, Value)> {
        self.browser
            .call(
                &self.router,
                method,
                &format!("/api/v1/devices/{DEVICE}/operations{suffix}"),
                body,
            )
            .await
    }
    pub(crate) async fn accept(&mut self) -> anyhow::Result<()> {
        self.set_authorized(true).await?;
        let request = json!({"operationId":self.operation,"field":"model","expectedValue":"Final-Model","deadline":self.app.clock.unix_seconds()?+300});
        let mut malformed = request.clone();
        malformed["unexpected"] = true.into();
        let rejected = self.call(Method::POST, "", Some(malformed)).await?;
        ensure!(
            rejected.0 == StatusCode::BAD_REQUEST && rejected.1["code"] == "malformed_request",
            "JSON contract: {rejected:?}"
        );
        // The complete transaction committed, but its ACK is withheld by the provider.
        #[cfg(feature = "integration")]
        {
            self.app.commands.inject_fault(
                rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            );
            ensure!(
                self.call(Method::POST, "", Some(request.clone())).await?.0
                    == StatusCode::SERVICE_UNAVAILABLE
            );
        }
        let accepted = self.call(Method::POST, "", Some(request.clone())).await?;
        ensure!(
            accepted.0 == StatusCode::ACCEPTED,
            "acceptance {:?}",
            accepted
        );
        let replay = self.call(Method::POST, "", Some(request.clone())).await?;
        ensure!(replay == accepted);
        let mut conflict = request.clone();
        conflict["expectedValue"] = "other".into();
        ensure!(self.call(Method::POST, "", Some(conflict)).await?.0 == StatusCode::CONFLICT);
        #[cfg(feature = "integration")]
        self.atomic_failure(&request).await?;
        self.admission_and_scope().await?;
        self.set_authorized(false).await?;
        let blocked = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        ensure!(blocked.0 == StatusCode::OK && blocked.1["authorization"] == "blocked");
        ensure!(
            self.call(Method::POST, "", Some(request.clone())).await?.0 == StatusCode::FORBIDDEN
        );
        self.set_authorized(true).await?;
        let approval = json!({"requestId":Uuid::new_v4(),"expectedRevision":1});
        let approved = self
            .call(
                Method::POST,
                &format!("/{}/approve", self.operation),
                Some(approval.clone()),
            )
            .await?;
        ensure!(approved.0 == StatusCode::OK && approved.1["revision"] == 2);
        ensure!(
            self.call(
                Method::POST,
                &format!("/{}/approve", self.operation),
                Some(approval)
            )
            .await?
                == approved
        );
        let audit = Audit::new(TENANT.into(), "management_read");
        #[cfg(feature = "integration")]
        self.retry_gateway().await?;
        #[cfg(feature = "integration")]
        self.crash_relay().await?;
        self.app.commands.relay_once().await?;
        // Drive the public bounded recovery seam without a competing fault consumer.
        let s = self.app.commands.clone();
        let id = self.operation;
        s.transact((s.as_ref(), id), &audit, |ctx, tx| {
            Box::pin(async move {
                let op = storage::load(tx, ctx.1).await?;
                let _page = ctx
                    .0
                    .store
                    .recover(tx, op.scope, dc::BatchLimit::new(64).unwrap(), None)
                    .await?;
                Ok(())
            })
        })
        .await?;
        audit.finalize(None);
        let read = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        ensure!(
            read.0 == StatusCode::OK
                && read.1["field"] == "model"
                && read.1["expectedValue"] == "Final-Model"
                && read.1["commandStatus"] == "published"
                && read.1["observation"]["result"] == "unknown",
            "published is not observed {:?}",
            read
        );
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        let counts: (i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_commands.operations WHERE id=$1::uuid),(SELECT count(*) FROM rss_device_command.commands WHERE command_id=$2),(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$3)").bind(self.operation.to_string()).bind(self.operation.to_string()).bind(format!("dispatch.{}",self.operation)).fetch_one(&mut pg).await?;
        ensure!(counts == (1, 1, 1));
        let concurrent = Uuid::new_v4();
        let mut body = request.clone();
        body["operationId"] = concurrent.to_string().into();
        let (mut one, mut two) = (self.browser.clone(), self.browser.clone());
        let path = format!("/api/v1/devices/{DEVICE}/operations");
        let (a, b) = tokio::join!(
            one.call(&self.router, Method::POST, &path, Some(body.clone())),
            two.call(&self.router, Method::POST, &path, Some(body))
        );
        let (a, b) = (a?, b?);
        ensure!(
            a == b && a.0 == StatusCode::ACCEPTED,
            "concurrent replay diverged"
        );
        ensure!(
            self.call(
                Method::POST,
                &format!("/{concurrent}/cancel"),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1}))
            )
            .await?
            .0 == StatusCode::OK
        );

        for different in [false, true] {
            let id = Uuid::new_v4();
            let mut first = request.clone();
            first["operationId"] = id.to_string().into();
            let mut second = first.clone();
            if different {
                second["expectedValue"] = "different-target".into();
            }
            let (a, b) = tokio::join!(
                one.call(&self.router, Method::POST, &path, Some(first)),
                two.call(&self.router, Method::POST, &path, Some(second))
            );
            let (a, b) = (a?, b?);
            if different {
                ensure!(
                    (a.0 == StatusCode::ACCEPTED && b.0 == StatusCode::CONFLICT)
                        || (b.0 == StatusCode::ACCEPTED && a.0 == StatusCode::CONFLICT)
                );
            } else {
                ensure!(a == b && a.0 == StatusCode::ACCEPTED);
            }
            let facts:(i64,i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_commands.operations WHERE id=$1::uuid),(SELECT count(*) FROM rss_device_command.commands WHERE command_id=$1),(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$2),(SELECT count(*) FROM mdm_access.audit WHERE operation_id=$1::uuid AND action='command_accept' AND result='success')").bind(id.to_string()).bind(format!("dispatch.{id}")).fetch_one(&mut pg).await?;
            ensure!(
                facts == (1, 1, 1, 1),
                "concurrent request duplicated facts {facts:?}"
            );
            ensure!(
                self.call(
                    Method::POST,
                    &format!("/{id}/cancel"),
                    Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1}))
                )
                .await?
                .0 == StatusCode::OK
            );
        }

        let successes:Vec<(String,i64)>=sqlx::query_as("SELECT action,count(*) FROM mdm_access.audit WHERE operation_id=$1::uuid AND result='success' AND action IN('command_accept','command_dispatch') GROUP BY action ORDER BY action").bind(self.operation.to_string()).fetch_all(&mut pg).await?;
        ensure!(
            successes == vec![("command_accept".into(), 1), ("command_dispatch".into(), 1)],
            "replay duplicated success audits {:?}",
            successes
        );

        pg.close().await?;
        Ok(())
    }

    #[cfg(feature = "integration")]
    async fn retry_gateway(&self) -> anyhow::Result<()> {
        use rss_transactional_messaging::outbox::OutboxRelayStore;
        use rss_transactional_messaging_postgres::PgTransactionFault;
        let service = &self.app.commands;
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        let mut fingerprint = None;
        for (index, fault) in [
            PgTransactionFault::CommitPending,
            PgTransactionFault::CommitUnknownAfterAck,
        ]
        .into_iter()
        .enumerate()
        {
            let claims = service
                .outbox
                .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
                .await?;
            ensure!(claims.len() == 1);
            for claim in claims {
                let message = PgOutboxStore::<()>::message(&claim);
                ensure!(message.message_id().as_str() == format!("dispatch.{}", self.operation));
                let digest = message.fingerprint().as_bytes().to_vec();
                if let Some(previous) = &fingerprint {
                    ensure!(previous == &digest);
                } else {
                    fingerprint = Some(digest.clone());
                }
                service.inject_fault(fault);
                ensure!(matches!(
                    service.relay_claim(claim).await,
                    Err(Error::CommitUnknown)
                ));
                let row:(String,i32,Vec<u8>)=sqlx::query_as("SELECT status,retry_count,fingerprint FROM rss_transactional_messaging.outbox WHERE message_id=$1").bind(format!("dispatch.{}",self.operation)).fetch_one(&mut pg).await?;
                ensure!(
                    row == ("pending".into(), index as i32 + 1, digest),
                    "unknown gateway acceptance was published or identity changed"
                );
                let accepted: bool = sqlx::query_scalar(
                    "SELECT gateway_accepted FROM mdm_commands.operations WHERE id=$1::uuid",
                )
                .bind(self.operation.to_string())
                .fetch_one(&mut pg)
                .await?;
                let successes:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.audit WHERE operation_id=$1::uuid AND action='command_dispatch' AND result='success'").bind(self.operation.to_string()).fetch_one(&mut pg).await?;
                ensure!(accepted == (index == 1) && successes == index as i64);
            }
            // Respect the provider's durable Retry schedule, without rewriting its clock/state.
            tokio::time::sleep(Duration::from_millis((1u64 << index) * 1000 + 100)).await;
        }
        pg.close().await?;
        Ok(())
    }
    #[cfg(feature = "integration")]
    async fn crash_relay(&self) -> anyhow::Result<()> {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(
            std::process::Command::new(std::env::current_exe()?)
                .args([
                    "commands::tests::relay_crash_child",
                    "--exact",
                    "--ignored",
                    "--nocapture",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?,
        );
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        tokio::time::timeout(Duration::from_secs(5),async {
            loop {
                ensure!(child.0.try_wait()?.is_none(),"relay child exited before durable acceptance");
                let accepted:bool=sqlx::query_scalar("SELECT gateway_accepted FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(TENANT).bind(self.operation.to_string()).fetch_one(&mut pg).await?;
                if accepted {return Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await??;
        child.0.kill()?;
        child.0.wait()?;
        // The dead process's opaque claim is never reconstructed. Wait for durable expiry,
        // then the production relay claims and replays the exact gateway acceptance.
        tokio::time::timeout(Duration::from_secs(15),async {
            loop {
                self.app.commands.relay_once().await?;
                let published:bool=sqlx::query_scalar("SELECT status='published' FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$2").bind(TENANT).bind(format!("dispatch.{}",self.operation)).fetch_one(&mut pg).await?;
                if published {return Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await??;
        pg.close().await?;
        Ok(())
    }
    async fn set_authorized(&mut self, enabled: bool) -> anyhow::Result<()> {
        let mut permissions = vec!["operation_read", "operation_cancel"];
        if enabled {
            permissions.push("state_verify");
        }
        let grants: Vec<_> = permissions
            .iter()
            .map(|p| json!({"operation":p,"scope":{"kind":"device","id":DEVICE}}))
            .collect();
        let value = json!({"subject":{"kind":"user","user":crate::identity_fixture::user(TENANT,crate::identity_fixture::ADMIN)},"grants":grants});
        let response=self.browser.call(&self.router,Method::PUT,&format!("/api/v1/authorization/rules/{}",self.rule),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":self.rule_revision,"value":value}))).await?;
        ensure!(response.0 == StatusCode::OK, "grant update {:?}", response);
        self.rule_revision += 1;
        Ok(())
    }
    async fn admission_and_scope(&mut self) -> anyhow::Result<()> {
        let other = self
            .browser
            .call(
                &self.router,
                Method::GET,
                &format!(
                    "/api/v1/devices/another-device/operations/{}",
                    self.operation
                ),
                None,
            )
            .await?;
        ensure!(other.0 == StatusCode::FORBIDDEN);
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        for (damage, restore) in [
            (
                "ALTER ROLE mdm_owner BYPASSRLS",
                "ALTER ROLE mdm_owner NOBYPASSRLS",
            ),
            (
                "CREATE POLICY widened ON mdm_access.registrations USING(true)",
                "DROP POLICY widened ON mdm_access.registrations",
            ),
            (
                "ALTER TABLE mdm_access.collection_runs DISABLE ROW LEVEL SECURITY",
                "ALTER TABLE mdm_access.collection_runs ENABLE ROW LEVEL SECURITY",
            ),
            (
                "CREATE FUNCTION rss_device_command.unexpected() RETURNS void LANGUAGE sql SECURITY DEFINER AS 'SELECT';",
                "DROP FUNCTION rss_device_command.unexpected()",
            ),
            (
                "ALTER FUNCTION rss_device_command.lock_authority(uuid,uuid) SECURITY INVOKER",
                "ALTER FUNCTION rss_device_command.lock_authority(uuid,uuid) SECURITY DEFINER",
            ),
            (
                "GRANT EXECUTE ON FUNCTION rss_device_command.lock_authority(uuid,uuid) TO PUBLIC",
                "REVOKE EXECUTE ON FUNCTION rss_device_command.lock_authority(uuid,uuid) FROM PUBLIC",
            ),
            (
                "GRANT UPDATE(fingerprint) ON mdm_commands.requests TO mdm_command_runtime",
                "REVOKE UPDATE(fingerprint) ON mdm_commands.requests FROM mdm_command_runtime",
            ),
            (
                "CREATE POLICY widened ON mdm_commands.operations USING(true)",
                "DROP POLICY widened ON mdm_commands.operations",
            ),
            (
                "ALTER TABLE mdm_commands.operations ADD CONSTRAINT unexpected_command_check CHECK(revision<100000)",
                "ALTER TABLE mdm_commands.operations DROP CONSTRAINT unexpected_command_check",
            ),
        ] {
            sqlx::raw_sql(damage).execute(&mut pg).await?;
            let response = self
                .call(Method::GET, &format!("/{}", self.operation), None)
                .await?;
            sqlx::raw_sql(restore).execute(&mut pg).await?;
            ensure!(
                response.0 == StatusCode::SERVICE_UNAVAILABLE,
                "command admission accepted drift {:?}",
                response
            );
            ensure!(
                self.call(Method::GET, &format!("/{}", self.operation), None)
                    .await?
                    .0
                    == StatusCode::OK
            );
        }
        sqlx::query("UPDATE rss_device_command.commands SET command_id=$2 WHERE command_id=$1")
            .bind(self.operation.to_string())
            .bind(Uuid::nil().to_string())
            .execute(&mut pg)
            .await?;
        let missing = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        sqlx::query("UPDATE rss_device_command.commands SET command_id=$2 WHERE command_id=$1")
            .bind(Uuid::nil().to_string())
            .bind(self.operation.to_string())
            .execute(&mut pg)
            .await?;
        ensure!(
            missing.0 == StatusCode::SERVICE_UNAVAILABLE
                && missing.1["code"] == "service_unavailable",
            "missing command misclassified {missing:?}"
        );
        let poison = self
            .app
            .commands
            .accept_dispatch(Uuid::new_v4(), vec![0; 32])
            .await;
        ensure!(matches!(
            poison,
            Err(Error::Unavailable(Failure::CommandInvariant))
        ));
        pg.close().await?;
        Ok(())
    }
    #[cfg(feature = "integration")]
    async fn atomic_failure(&mut self, request: &Value) -> anyhow::Result<()> {
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        // The provider loses the commit future after all business SQL has run.
        self.app
            .commands
            .inject_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
        let mut next = request.clone();
        let id = Uuid::new_v4();
        next["operationId"] = id.to_string().into();
        let result = self.call(Method::POST, "", Some(next)).await?;
        ensure!(result.0 == StatusCode::SERVICE_UNAVAILABLE);
        let count:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM mdm_commands.operations WHERE id=$1::uuid)+(SELECT count(*) FROM rss_device_command.commands WHERE command_id=$2)+(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$3)+(SELECT count(*) FROM mdm_access.audit WHERE operation_id=$1::uuid AND action='command_accept' AND result='success')").bind(id.to_string()).bind(id.to_string()).bind(format!("dispatch.{id}")).fetch_one(&mut pg).await?;
        ensure!(
            count == 0,
            "abandoned commit partially persisted command/outbox"
        );
        pg.close().await?;
        Ok(())
    }
    pub(crate) async fn received(&mut self) -> anyhow::Result<()> {
        let read = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        ensure!(
            read.1["commandStatus"] == "received" && read.1["observation"]["result"] == "unknown",
            "ACK became effect {:?}",
            read
        );
        Ok(())
    }
    pub(crate) async fn observed(&mut self) -> anyhow::Result<()> {
        let read = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        ensure!(
            read.0 == StatusCode::OK
                && read.1["commandStatus"] == "received"
                && read.1["observation"]["result"] == "mismatched",
            "mismatch lost {:?}",
            read
        );
        self.set_authorized(false).await?;
        Ok(())
    }
    pub(crate) async fn reobserve(
        &mut self,
        peer: &reqwest::Client,
        url: &str,
        initial: &rss_mdm_windows_mdm::syncml::Message,
        ack: &rss_mdm_windows_mdm::syncml::Message,
        old_results: &[u8],
    ) -> anyhow::Result<()> {
        use base64::Engine;
        use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};
        self.set_authorized(true).await?;
        let result = self
            .call(
                Method::POST,
                &format!("/{}/approve", self.operation),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":2})),
            )
            .await?;
        ensure!(result.0 == StatusCode::OK);
        let mut initial = initial.clone();
        initial.header.session_id = 900;
        async fn send(
            peer: &reqwest::Client,
            url: &str,
            message: &s::Message,
        ) -> anyhow::Result<s::Message> {
            let result = peer
                .post(url)
                .header("content-type", "application/vnd.syncml.dm+xml")
                .body(s::encode(message, &CodecLimits::default())?)
                .send()
                .await?;
            ensure!(
                result.status() == StatusCode::OK,
                "native task response {}",
                result.status()
            );
            Ok(s::decode(&result.bytes().await?, &CodecLimits::default())?)
        }
        send(peer, url, &initial).await?;
        let mut ack = ack.clone();
        ack.header.session_id = 900;
        if let s::Command::Status(status) = &mut ack.commands[0] {
            status.challenge.as_mut().unwrap().nonce = Some(Secret(
                base64::engine::general_purpose::STANDARD.encode([21u8; 16]),
            ));
        }
        let sent = send(peer, url, &ack).await?;
        let gets: Vec<_> = sent
            .commands
            .iter()
            .filter_map(|c| match c {
                s::Command::Get { id, items, .. } => Some((*id, items[0].target.clone().unwrap())),
                _ => None,
            })
            .collect();
        ensure!(gets.len() == 2);
        let before = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        let late = peer
            .post(url)
            .header("content-type", "application/vnd.syncml.dm+xml")
            .body(old_results.to_vec())
            .send()
            .await?;
        ensure!(
            matches!(late.status(), StatusCode::OK | StatusCode::CONFLICT),
            "old attempt response {}",
            late.status()
        );
        ensure!(
            self.call(Method::GET, &format!("/{}", self.operation), None)
                .await?
                == before,
            "old attempt changed current observation"
        );
        let header_status = |id, previous| {
            s::Command::Status(s::Status {
                id,
                message_ref: previous,
                command_ref: 0,
                command: s::CommandName::SyncHdr,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            })
        };
        let mut values = s::Message {
            header: s::Header {
                message_id: 3,
                credential: None,
                ..initial.header.clone()
            },
            commands: vec![header_status(1, 2)],
            final_message: true,
        };
        for (index, (id, uri)) in gets.iter().enumerate() {
            values.commands.push(s::Command::Results(s::Results {
                id: index as u32 + 2,
                message_ref: Some(2),
                command_ref: Some(*id),
                command: Some(s::CommandName::Get),
                meta: None,
                items: vec![s::Item {
                    source: Some(uri.clone()),
                    target: None,
                    meta: None,
                    data: Some(Secret(
                        if index == 0 {
                            "Final-Model"
                        } else {
                            "10.0.26100"
                        }
                        .into(),
                    )),
                }],
            }));
        }
        send(peer, url, &values).await?;
        let pending = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        ensure!(
            pending.1["commandStatus"] == "received"
                && pending.1["observation"]["result"] == "unknown"
        );
        let mut statuses = s::Message {
            header: s::Header {
                message_id: 4,
                credential: None,
                ..initial.header.clone()
            },
            commands: vec![header_status(1, 3)],
            final_message: true,
        };
        for (index, (id, _)) in gets.iter().enumerate() {
            statuses.commands.push(s::Command::Status(s::Status {
                id: index as u32 + 2,
                message_ref: 2,
                command_ref: *id,
                command: s::CommandName::Get,
                target_refs: vec![],
                source_refs: vec![],
                code: 200,
                items: vec![],
                challenge: None,
                credential: None,
            }));
        }
        #[cfg(feature = "integration")]
        self.app.commands.inject_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
        );
        #[cfg(feature = "integration")]
        {
            let result = peer
                .post(url)
                .header("content-type", "application/vnd.syncml.dm+xml")
                .body(s::encode(&statuses, &CodecLimits::default())?)
                .send()
                .await?;
            ensure!(result.status() == StatusCode::SERVICE_UNAVAILABLE);
        }
        send(peer, url, &statuses).await?;
        let applied = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        ensure!(
            applied.1["commandStatus"] == "applied"
                && applied.1["observation"]["result"] == "matched"
                && applied.1["observation"]["attempt"] == 2,
            "reobservation failed {:?}",
            applied
        );
        let rejected = peer
            .post(url)
            .header("content-type", "application/vnd.syncml.dm+xml")
            .body(s::encode(&ack, &CodecLimits::default())?)
            .send()
            .await?;
        ensure!(
            rejected.status() == StatusCode::FORBIDDEN,
            "completed Get replayed"
        );
        let id = Uuid::new_v4();
        let body = json!({"operationId":id,"field":"model","expectedValue":"never","deadline":self.app.clock.unix_seconds()?+60});
        ensure!(self.call(Method::POST, "", Some(body)).await?.0 == StatusCode::ACCEPTED);
        let request = json!({"requestId":Uuid::new_v4(),"expectedRevision":1});
        let cancel = self
            .call(
                Method::POST,
                &format!("/{id}/cancel"),
                Some(request.clone()),
            )
            .await?;
        ensure!(cancel.0 == StatusCode::OK);
        ensure!(
            self.call(Method::POST, &format!("/{id}/cancel"), Some(request))
                .await?
                == cancel
        );
        let read = self.call(Method::GET, &format!("/{id}"), None).await?;
        ensure!(
            read.1["commandStatus"] == "cancelled" && read.1["observation"]["result"] == "unknown"
        );
        ensure!(
            self.call(
                Method::POST,
                &format!("/{id}/approve"),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":2}))
            )
            .await?
            .0 == StatusCode::CONFLICT
        );
        self.other_native_outcomes(peer, url, &initial, &ack)
            .await?;
        let expiry = Uuid::new_v4();
        ensure!(self.call(Method::POST,"",Some(json!({"operationId":expiry,"field":"model","expectedValue":"after-deadline","deadline":self.app.clock.unix_seconds()?+1}))).await?.0==StatusCode::ACCEPTED);
        self.expiring = Some(expiry);
        Ok(())
    }
    pub(crate) async fn new_registration_operation(&mut self) -> anyhow::Result<Value> {
        let old = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        self.operation = Uuid::new_v4();
        ensure!(self.call(Method::POST,"",Some(json!({"operationId":self.operation,"field":"model","expectedValue":"new-registration","deadline":self.app.clock.unix_seconds()?+60}))).await?.0==StatusCode::ACCEPTED);
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        let generations: (i64, i64) = sqlx::query_as(
            "SELECT registration_generation,epoch FROM mdm_commands.operations WHERE id=$1::uuid",
        )
        .bind(self.operation.to_string())
        .fetch_one(&mut pg)
        .await?;
        ensure!(
            generations == (2, 2),
            "registration/authority did not advance {generations:?}"
        );
        ensure!(old.1["commandStatus"] == "applied");
        Ok(self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?
            .1)
    }
    pub(crate) async fn unchanged(&mut self, previous: &Value) -> anyhow::Result<()> {
        ensure!(
            &self
                .call(Method::GET, &format!("/{}", self.operation), None)
                .await?
                .1
                == previous,
            "stale registration changed current task"
        );
        Ok(())
    }
    pub(crate) async fn retained_and_recovered(&mut self) -> anyhow::Result<()> {
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        sqlx::query("UPDATE mdm_access.management_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND session_id='900'").bind(TENANT).execute(&mut pg).await?;
        ensure!(self.app.access.prune_management(TENANT).await? >= 1);
        let read = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        ensure!(
            read.1["commandStatus"] == "applied" && read.1["observation"]["result"] == "matched",
            "session GC removed operation evidence"
        );
        let config = crate::identity_fixture::config(TENANT)?;
        let restarted = Box::pin(Commands::open(&config)).await?;
        eprintln!("command T2: restarted runtime admitted");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let timer = recovery::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(2), &cancel);
        let policy = rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
            concurrency: 1,
            lease_ttl: Duration::from_secs(10),
            attempt_timeout: Duration::from_secs(1),
            scan_interval: Duration::from_millis(100),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(1),
            max_attempts: 3,
        })?;
        let scope = recovery_scope(restarted.tenant);
        let report = restarted.run_recovery(&scope, policy, &control).await?;
        ensure!(
            report.execution_failed == 0 && report.suspended == 0,
            "recovery did not complete {:?}",
            report
        );
        let read = self
            .call(Method::GET, &format!("/{}", self.expiring.unwrap()), None)
            .await?;
        ensure!(
            read.1["commandStatus"] == "timed_out" && read.1["observation"]["result"] == "unknown",
            "expiry or unknown effect lost {:?}",
            read
        );
        sqlx::raw_sql("COMMENT ON SCHEMA rss_reconcile IS 'damaged'")
            .execute(&mut pg)
            .await?;
        let fatal_timer = recovery::Timer::new();
        let fatal_control =
            rss_reconcile::Control::new(&fatal_timer, Duration::from_secs(2), &cancel);
        let fatal = restarted.run_recovery(&scope, policy, &fatal_control).await;
        sqlx::raw_sql("COMMENT ON SCHEMA rss_reconcile IS 'rss-reconcile-postgres:1'")
            .execute(&mut pg)
            .await?;
        ensure!(
            fatal.is_err_and(|error| error.kind() == rss_reconcile::ErrorKind::StorageContract),
            "fatal storage contract was not propagated"
        );
        // Exercise the same unbounded worker entry used by the runtime registration.
        // The expired operation has not been published; an autonomous relay must progress
        // without reviving the command, then stop via its normal cancellation signal.
        let message_id = format!("dispatch.{}", self.expiring.unwrap());
        let pending: String = sqlx::query_scalar(
            "SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1",
        )
        .bind(&message_id)
        .fetch_one(&mut pg)
        .await?;
        ensure!(pending == "pending");
        let worker_cancel = tokio_util::sync::CancellationToken::new();
        let mut worker = Box::pin(restarted.run_worker(&worker_cancel));
        tokio::select! {
            outcome=&mut worker => anyhow::bail!("production worker exited before publication: {outcome:?}"),
            observed=tokio::time::timeout(Duration::from_secs(5),async {
                loop {
                    let status:String=sqlx::query_scalar("SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1").bind(&message_id).fetch_one(&mut pg).await?;
                    if status=="published" {return Ok::<(),anyhow::Error>(());}
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }) => observed??,
        }
        worker_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), worker).await??;
        ensure!(
            self.call(Method::GET, &format!("/{}", self.expiring.unwrap()), None)
                .await?
                .1["commandStatus"]
                == "timed_out"
        );
        use rss_runtime::ManagedResource;
        config::Resource(restarted).shutdown().await?;
        pg.close().await?;
        Ok(())
    }
}

#[cfg(feature = "integration")]
#[tokio::test]
#[ignore = "subprocess killed by command T2 after confirmed PG acceptance"]
async fn relay_crash_child() -> anyhow::Result<()> {
    use rss_transactional_messaging::{outbox::OutboxRelayStore, policy::DeliveryBudget};
    let config = crate::identity_fixture::config(TENANT)?;
    let service = Box::pin(Commands::open(&config)).await?;
    let relay = PgOutboxStore::<()>::new(
        service.runtime.clone(),
        messaging_domain(),
        DeliveryBudget::new(
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )?,
    )?;
    let claims = relay
        .claim_partition_heads(std::num::NonZeroUsize::MIN, deadline())
        .await?;
    ensure!(claims.len() == 1);
    for claim in claims {
        let message = PgOutboxStore::<()>::message(&claim);
        let id = Uuid::parse_str(
            message
                .message_id()
                .as_str()
                .strip_prefix("dispatch.")
                .unwrap(),
        )?;
        let digest = message.fingerprint().as_bytes().to_vec();
        service.inject_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitAcknowledgedPending,
        );
        service.accept_dispatch(id, digest).await?;
    }
    anyhow::bail!("parent must kill before completion")
}
