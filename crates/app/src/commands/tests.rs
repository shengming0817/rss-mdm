#![allow(
    clippy::cognitive_complexity,
    reason = "sequential real transport failure and recovery assertions"
)]
//! Real product Router and embedded Identity; the native peer is supplied by Windows T2.
use super::*;
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
        pg.close().await?;
        Ok(())
    }
    async fn atomic_failure(&mut self, request: &Value) -> anyhow::Result<()> {
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        // The failure occurs after command/outbox admission, inside the success audit insert.
        sqlx::raw_sql("CREATE FUNCTION public.reject_command_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='command_accept' AND NEW.result='success' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$; REVOKE ALL ON FUNCTION public.reject_command_audit() FROM PUBLIC; CREATE TRIGGER reject_command_audit BEFORE INSERT ON mdm_access.audit FOR EACH ROW EXECUTE FUNCTION public.reject_command_audit();").execute(&mut pg).await?;
        let mut next = request.clone();
        let id = Uuid::new_v4();
        next["operationId"] = id.to_string().into();
        let result = self.call(Method::POST, "", Some(next)).await?;
        sqlx::raw_sql("DROP TRIGGER reject_command_audit ON mdm_access.audit; DROP FUNCTION public.reject_command_audit();").execute(&mut pg).await?;
        ensure!(result.0 == StatusCode::SERVICE_UNAVAILABLE);
        let count:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM mdm_commands.operations WHERE id=$1::uuid)+(SELECT count(*) FROM rss_device_command.commands WHERE command_id=$2)+(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$3)").bind(id.to_string()).bind(id.to_string()).bind(format!("dispatch.{id}")).fetch_one(&mut pg).await?;
        ensure!(
            count == 0,
            "audit failure partially committed command/outbox"
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
        let expiry = Uuid::new_v4();
        ensure!(self.call(Method::POST,"",Some(json!({"operationId":expiry,"field":"model","expectedValue":"after-deadline","deadline":self.app.clock.unix_seconds()?+1}))).await?.0==StatusCode::ACCEPTED);
        self.expiring = Some(expiry);
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
        let scope = rss_reconcile::Scope::new(restarted.tenant, "mdm.commands.v1")?;
        let report = Box::pin(rss_reconcile::run(
            &restarted.reconcile,
            restarted.as_ref(),
            &scope,
            policy,
            &control,
            |_| {},
        ))
        .await?;
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
    use rss_transactional_messaging::{
        message::MessagingDomain, outbox::OutboxRelayStore, policy::DeliveryBudget,
    };
    let config = crate::identity_fixture::config(TENANT)?;
    let service = Box::pin(Commands::open(&config)).await?;
    let relay = PgOutboxStore::<()>::new(
        service.runtime.clone(),
        MessagingDomain::parse("mdm.commands.v1")?,
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
