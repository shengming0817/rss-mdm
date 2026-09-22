//! Additional real native status and OsVersion paths using the canonical Router.
use super::*;
use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};

async fn post(
    peer: &reqwest::Client,
    url: &str,
    message: &s::Message,
) -> anyhow::Result<reqwest::Response> {
    Ok(peer
        .post(url)
        .header("content-type", "application/vnd.syncml.dm+xml")
        .body(s::encode(message, &CodecLimits::default())?)
        .send()
        .await?)
}
pub(super) struct ReadExchange {
    pub(super) first: s::Message,
    pub(super) gets: Vec<(u32, String)>,
    pub(super) ack: s::Message,
}
pub(super) async fn begin(
    peer: &reqwest::Client,
    url: &str,
    initial: &s::Message,
    ack: &s::Message,
    session: u32,
) -> anyhow::Result<ReadExchange> {
    use base64::Engine;
    let mut first = initial.clone();
    first.header.session_id = session;
    ensure!(post(peer, url, &first).await?.status() == StatusCode::OK);
    let mut ack = ack.clone();
    ack.header.session_id = session;
    if let s::Command::Status(status) = &mut ack.commands[0] {
        status.challenge.as_mut().unwrap().nonce = Some(Secret(
            base64::engine::general_purpose::STANDARD.encode([session as u8; 16]),
        ));
    }
    let response = post(peer, url, &ack).await?;
    ensure!(response.status() == StatusCode::OK);
    let message = s::decode(&response.bytes().await?, &CodecLimits::default())?;
    let gets = message
        .commands
        .iter()
        .filter_map(|c| match c {
            s::Command::Get { id, items, .. } => Some((*id, items[0].target.clone().unwrap())),
            _ => None,
        })
        .collect::<Vec<_>>();
    ensure!(gets.len() >= 4 && gets[1].1.ends_with("/SwV"));
    Ok(ReadExchange { first, gets, ack })
}
pub(super) fn report(
    first: &s::Message,
    gets: &[(u32, String)],
    version: &str,
    status: u16,
) -> s::Message {
    let native_status = |id, command_ref, code, command| {
        s::Command::Status(s::Status {
            id,
            message_ref: 2,
            command_ref,
            command,
            target_refs: vec![],
            source_refs: vec![],
            code,
            items: vec![],
            challenge: None,
            credential: None,
        })
    };
    let mut packet = s::Message {
        header: s::Header {
            message_id: 3,
            credential: None,
            ..first.header.clone()
        },
        commands: vec![native_status(1, 0, 200, s::CommandName::SyncHdr)],
        final_message: true,
    };
    for (index, (id, uri)) in gets.iter().enumerate() {
        packet.commands.push(native_status(
            index as u32 * 2 + 2,
            *id,
            status,
            s::CommandName::Get,
        ));
        if status == 200 {
            packet.commands.push(s::Command::Results(s::Results {
                id: index as u32 * 2 + 3,
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
                            "Model-extra"
                        } else if uri.ends_with("/Edition") {
                            "48"
                        } else {
                            version
                        }
                        .into(),
                    )),
                }],
            }));
        }
    }
    packet
}
impl Client {
    pub(super) async fn publish_operation(&self, id: Uuid) -> anyhow::Result<()> {
        for _ in 0..16 {
            self.app.commands.relay_once().await?;
        }
        let audit = Audit::new(TENANT.into(), "management_read");
        let service = self.app.commands.as_ref();
        let result = service
            .transact((service, id), &audit, |ctx, tx| {
                Box::pin(async move {
                    let (service, id) = *ctx;
                    let operation = storage::load(tx, id).await?;
                    let _page = service
                        .store
                        .recover(tx, operation.scope, dc::BatchLimit::new(64).unwrap(), None)
                        .await?;
                    Ok(())
                })
            })
            .await;
        audit.finalize(None);
        result?;
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
        let historic = begin(peer, url, initial, ack, 901).await?;
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
            let exchange = begin(peer, url, initial, ack, session).await?;
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
        let exchange = begin(peer, url, initial, ack, 904).await?;
        let packet = report(&exchange.first, &exchange.gets, "unused", 500);
        #[cfg(feature = "integration")]
        {
            self.app.commands.inject_fault(
                rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            );
            ensure!(post(peer, url, &packet).await?.status() == StatusCode::SERVICE_UNAVAILABLE);
        }
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
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
        self.firewall_cycle(peer, url, initial, ack).await?;
        Ok(())
    }
}
