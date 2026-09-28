#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use crate::execution::test_support::native::{self, begin, post, report};
use crate::execution::test_support::*;
use crate::execution::*;
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use rss_mdm_windows_mdm::{CodecLimits, syncml as s};
use serde_json::{Value, json};
use sqlx::Connection;
#[tokio::test]
#[ignore = "make t2 MODULE=execution.commands.windows"]
async fn native_status_results_reobservation_and_generation_fences() -> anyhow::Result<()> {
    let mut host = crate::windows::test_support::Host::open().await?;
    host.listen().await?;
    let peer = host.peer().await?;
    let mut client = Client::start(host.browser.clone(), host.app.clone()).await?;
    client.accept_approved().await?;
    client.publish_operation(client.operation).await?;
    let exchange = native::begin(
        &peer.mutual,
        &peer.url,
        &peer.message,
        &peer.ack,
        1,
        Some("./DevInfo/Mod"),
    )
    .await?;
    let mut received = native::report(&exchange.first, &exchange.gets, "10.0.26100", 200);
    received
        .commands
        .retain(|c| !matches!(c, s::Command::Results(_)));
    ensure!(
        native::post(&peer.mutual, &peer.url, &received)
            .await?
            .status()
            == StatusCode::OK
    );
    client.received().await?;
    let mut observed = native::report(&exchange.first, &exchange.gets, "10.0.26100", 200);
    observed.header.message_id = 4;
    if let s::Command::Status(status) = &mut observed.commands[0] {
        status.message_ref = 3;
    }
    let old_results = s::encode(&observed, &CodecLimits::default())?;
    ensure!(
        native::post(&peer.mutual, &peer.url, &observed)
            .await?
            .status()
            == StatusCode::OK
    );
    let (revocation, replay) = tokio::join!(
        client.observed(),
        native::post(&peer.mutual, &peer.url, &exchange.ack)
    );
    revocation?;
    ensure!(matches!(
        replay?.status(),
        StatusCode::OK | StatusCode::FORBIDDEN
    ));
    ensure!(
        native::post(&peer.mutual, &peer.url, &exchange.ack)
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
    client
        .reobserve(
            &peer.mutual,
            &peer.url,
            &peer.message,
            &peer.ack,
            &old_results,
        )
        .await?;
    client.retained_evidence().await?;
    host.replace(&peer).await?;
    let current = client.new_registration_operation().await?;
    ensure!(
        native::post(&peer.mutual, &peer.url, &observed)
            .await?
            .status()
            == StatusCode::UNAUTHORIZED
    );
    client.unchanged(&current).await?;
    host.close().await?;
    Ok(())
}
impl Client {
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
        ensure!(gets.len() == 5);
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
                        if uri.ends_with("/Mod") {
                            "Final-Model"
                        } else if uri.ends_with("/Edition") {
                            "48"
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
        self.app.execution.inject_fault(
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
        let body = json!({"operationId":id,"task":{"kind":"state_verify","field":"model","expectedValue":"never"},"deadline":self.app.clock.unix_seconds()?+60});
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
        Ok(())
    }
    pub(crate) async fn new_registration_operation(&mut self) -> anyhow::Result<Value> {
        let old = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        self.operation = Uuid::new_v4();
        ensure!(self.call(Method::POST,"",Some(json!({"operationId":self.operation,"task":{"kind":"state_verify","field":"model","expectedValue":"new-registration"},"deadline":self.app.clock.unix_seconds()?+60}))).await?.0==StatusCode::ACCEPTED);
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
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
    pub(super) async fn other_native_outcomes(
        &mut self,
        peer: &reqwest::Client,
        url: &str,
        initial: &s::Message,
        ack: &s::Message,
    ) -> anyhow::Result<()> {
        // This ordinary Inventory Get was issued before the new operation exists.
        let historic = begin(peer, url, initial, ack, 901, None).await?;
        let os = Uuid::new_v4();
        ensure!(self.call(Method::POST,"",Some(json!({"operationId":os,"task":{"kind":"state_verify","field":"os_version","expectedValue":"11.0.10000"},"deadline":self.app.clock.unix_seconds()?+300}))).await?.0==StatusCode::ACCEPTED);
        self.publish_operation(os).await?;
        ensure!(post(peer, url, &historic.ack).await?.status() == StatusCode::OK);
        let before = self.call(Method::GET, &format!("/{os}"), None).await?;
        ensure!(
            before.1["commandStatus"] == "published"
                && before.1["observation"].get("attempt").is_none(),
            "cached pre-acceptance Get acquired a new task: {before:?}"
        );
        ensure!(
            post(
                peer,
                url,
                &report(&historic.first, &historic.gets, "11.0.10000", 200)
            )
            .await?
            .status()
                == StatusCode::OK
        );
        let stale = self.call(Method::GET, &format!("/{os}"), None).await?;
        ensure!(
            stale.1["commandStatus"] == "published"
                && stale.1["observation"]["result"] == "unknown",
            "pre-acceptance reading completed a new task: {stale:?}"
        );
        for (session, value, expected) in [
            (902, "10.0.26100", "mismatched"),
            (903, "11.0.10000", "matched"),
        ] {
            let exchange = begin(peer, url, initial, ack, session, Some("./DevDetail/SwV")).await?;
            ensure!(
                post(
                    peer,
                    url,
                    &report(&exchange.first, &exchange.gets, value, 200)
                )
                .await?
                .status()
                    == StatusCode::OK
            );
            let read = self.call(Method::GET, &format!("/{os}"), None).await?;
            ensure!(
                read.0 == StatusCode::OK
                    && read.1["task"]["field"] == "os_version"
                    && read.1["observation"]["value"] == value
                    && read.1["observation"]["result"] == expected,
                "OsVersion outcome {read:?}"
            );
            ensure!(
                read.1["commandStatus"]
                    == if expected == "matched" {
                        "applied"
                    } else {
                        "received"
                    }
            );
            ensure!(read.1["observation"]["attempt"] == session - 900);
        }
        let rejected = Uuid::new_v4();
        ensure!(self.call(Method::POST,"",Some(json!({"operationId":rejected,"task":{"kind":"state_verify","field":"model","expectedValue":"never"},"deadline":self.app.clock.unix_seconds()?+300}))).await?.0==StatusCode::ACCEPTED);
        self.publish_operation(rejected).await?;
        let exchange = begin(peer, url, initial, ack, 904, Some("./DevInfo/Mod")).await?;
        let packet = report(&exchange.first, &exchange.gets, "unused", 500);
        #[cfg(feature = "integration")]
        {
            self.app.execution.inject_fault(
                rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            );
            ensure!(post(peer, url, &packet).await?.status() == StatusCode::SERVICE_UNAVAILABLE);
        }
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let before: i64 = sqlx::query_scalar(
            "SELECT version FROM rss_device_command.commands WHERE command_id=$1",
        )
        .bind(rejected.to_string())
        .fetch_one(&mut pg)
        .await?;
        ensure!(post(peer, url, &packet).await?.status() == StatusCode::OK);
        let version: i64 = sqlx::query_scalar(
            "SELECT version FROM rss_device_command.commands WHERE command_id=$1",
        )
        .bind(rejected.to_string())
        .fetch_one(&mut pg)
        .await?;
        #[cfg(feature = "integration")]
        ensure!(
            before == version,
            "duplicate rejection changed canonical command"
        );
        #[cfg(not(feature = "integration"))]
        let _ = (before, version);
        let read = self
            .call(Method::GET, &format!("/{rejected}"), None)
            .await?;
        ensure!(
            read.1["commandStatus"] == "rejected"
                && read.1["observation"]["nativeStatus"] == 500
                && read.1["observation"]["quality"] == "failed"
                && read.1["observation"]["result"] == "unknown"
                && read.1["observation"]["attempt"] == 1,
            "rejection outcome {read:?}"
        );
        pg.close().await?;
        Ok(())
    }
    async fn retained_evidence(&mut self) -> anyhow::Result<()> {
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        sqlx::query("UPDATE mdm_access.management_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND session_id='900'").bind(TENANT).execute(&mut pg).await?;
        ensure!(
            crate::windows::retention::prune_management(
                &self.app.access,
                &self.app.audit_store,
                TENANT
            )
            .await?
                >= 1
        );
        let read = self
            .call(Method::GET, &format!("/{}", self.operation), None)
            .await?;
        ensure!(
            read.1["commandStatus"] == "applied" && read.1["observation"]["result"] == "matched",
            "session GC removed operation evidence"
        );
        pg.close().await?;
        Ok(())
    }
}
