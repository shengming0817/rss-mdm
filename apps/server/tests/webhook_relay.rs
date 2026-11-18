//! The production fanout, target authorizer, TLS publisher and RSS settlements share one host.
use crate::{
    authority_t2_support::Context,
    command_runtime_t2_support::{Prepared, seed_transaction},
};
use anyhow::{Context as _, Result};
use rss_mdm_webhook_service::{events, materials, model::*};
use std::{sync::Arc, time::Duration};
use tokio::sync::{Notify, mpsc};
use uuid::Uuid;

async fn subscription(
    c: &Context,
    network: &crate::config::webhooks::Network,
    digest: &str,
    resources: &Prepared,
) -> Result<()> {
    let tenant = network.tenant;
    let id = Uuid::new_v4();
    let endpoint = format!("https://localhost:{}/events", network.port);
    let settings = Settings {
        presentation: serde_json::json!({"name":"receiver"})
            .as_object()
            .unwrap()
            .clone(),
        key_reference: "receiver-key".into(),
        network_reference: network.reference.clone(),
        endpoint: endpoint.clone(),
        event_types: vec![EventType::Registered],
        selection: Selection::AllDevices,
    };
    settings.validate()?;
    let mut tx = seed_transaction(c).await?;
    let material = materials::prepare(
        &mut tx,
        tenant,
        Uuid::new_v4(),
        &materials::Prepare {
            reference: settings.key_reference.clone(),
            expected_revision: 0,
            configuration_sha256: digest.into(),
            endpoint,
            network_reference: network.reference.clone(),
            source: materials::Source::Generate,
        },
        &resources.protection,
    )
    .await?;
    sqlx::query("UPDATE mdm_webhook.key_materials SET confirmed=true WHERE tenant_id=$1 AND operation_id=$2")
        .bind(tenant).bind(material.operation_id).execute(&mut *tx).await?;
    sqlx::query(
        "UPDATE mdm_webhook.key_heads SET active_revision=$3 WHERE tenant_id=$1 AND reference=$2",
    )
    .bind(tenant)
    .bind(&material.reference)
    .bind(material.revision)
    .execute(&mut *tx)
    .await?;
    let settings = serde_json::to_value(settings)?;
    sqlx::query("INSERT INTO mdm_webhook.subscriptions(tenant_id,id,revision,target_version,enabled,settings) VALUES($1,$2,1,1,true,$3)")
        .bind(tenant).bind(id).bind(&settings).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_webhook.versions(tenant_id,subscription,version,settings,activated_at) VALUES($1,$2,1,$3,clock_timestamp())")
        .bind(tenant).bind(id).bind(settings).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
async fn emit(c: &Context, id: Uuid) -> Result<()> {
    let device = rss_mdm_agent_wire::DeviceId::new_v4();
    let mut tx = seed_transaction(c).await?;
    let now = events::now_on(&mut tx).await?;
    events::emit_on(
        &mut tx,
        &Event {
            event_id: id,
            event_type: EventType::Registered,
            version: 1,
            occurred_at: now,
            tenant_id: c.tenant.to_string().parse()?,
            device_id: device,
            data: EventData::Registration {
                device_id: device,
                channel: "agent".into(),
                state: "active".into(),
            },
        },
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "T2: stalled HTTPS receipt permits both live fanout and another tenant's confirmed delivery"]
async fn stalled_receiver_allows_other_fanout_and_http_settlement() -> Result<()> {
    let first = Context::open("shared", &[]).await?;
    let second = Context::open("shared", &[]).await?;
    let resources = Prepared::open(&first, |_| {}).await?;
    // Generate only the test TLS material. Registration is unrelated to Webhook delivery.
    let name = Uuid::new_v4().to_string();
    let output = tokio::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../hack/native_protocol_materials.py"
        ))
        .arg(&first.inputs.directory)
        .args(["windows", &name, &name, &name])
        .output()
        .await?;
    anyhow::ensure!(output.status.success(), "receiver TLS fixture failed");
    let files: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let dir = std::path::Path::new(files["directory"].as_str().context("TLS directory")?);
    let listener = crate::provider_http_t2_support::Listener::open(dir).await?;
    let addr = listener.address()?;
    let ca = std::path::PathBuf::from(files["root"].as_str().context("TLS root")?);
    let mut config = resources.config.webhooks.clone();
    config.recovery_database = first.inputs.database("shared", "mdm_webhook_operator");
    config.networks = [&first, &second]
        .map(|c| {
            Ok::<_, anyhow::Error>(crate::config::webhooks::Network {
                tenant: c.tenant.to_string().parse()?,
                reference: "receiver".into(),
                hostname: "localhost".into(),
                port: addr.port(),
                addresses: vec![addr],
                cidrs: vec!["127.0.0.1/32".parse()?],
                ca_files: vec![ca.clone()],
            })
        })
        .into_iter()
        .collect::<Result<_>>()?;
    let digest = config.material_configuration()?;
    for (c, net) in [&first, &second].into_iter().zip(&config.networks) {
        subscription(c, net, &digest, &resources).await?;
    }
    let service = super::webhooks::open(
        config,
        resources.storage.runtime.clone(),
        first.database.archive_pool(),
        first.audit.clone(),
        Arc::new(crate::clock::SystemClock),
        resources.protection.clone(),
        first.execution(),
        rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            &[2; 32],
        )),
    )
    .await?;
    let (a, b, a2) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let release = Arc::new(Notify::new());
    let (sender, mut receipts) = mpsc::unbounded_channel();
    let handler = {
        let release = release.clone();
        move |axum::Json(event): axum::Json<Event>| {
            let release = release.clone();
            let sender = sender.clone();
            async move {
                let _ = sender.send(event.event_id);
                if event.event_id == a {
                    release.notified().await;
                }
                axum::http::StatusCode::NO_CONTENT
            }
        }
    };
    let server = tokio::spawn(
        axum::serve(
            listener,
            axum::Router::new().route("/events", axum::routing::post(handler)),
        )
        .into_future(),
    );
    emit(&first, a).await?;
    let token = tokio_util::sync::CancellationToken::new();
    let runner = tokio::spawn(service.clone().run(token.clone()));
    let result=tokio::time::timeout(Duration::from_secs(12),async {
        assert_eq!(receipts.recv().await,Some(a));
        emit(&second,b).await?;
        emit(&first,a2).await?;
        assert_eq!(receipts.recv().await,Some(b));
        loop {
            let state:(bool,bool,bool)=sqlx::query_as("SELECT
                EXISTS(SELECT FROM mdm_webhook.fanout WHERE id=$1 AND complete),
                EXISTS(SELECT FROM mdm_webhook.deliveries d JOIN rss_transactional_messaging.outbox o ON o.tenant_id=d.tenant_id AND o.message_id=d.id::text AND o.domain='mdm-webhook-delivery' WHERE d.event_id=$2 AND d.attempts=1 AND d.last_outcome='received' AND o.status='published'),
                EXISTS(SELECT FROM mdm_webhook.deliveries WHERE event_id=$3 AND attempts=1 AND last_outcome='unknown')")
                .bind(a2).bind(b).bind(a).fetch_one(&first.operator).await?;
            if state==(true,true,true) {break;}
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_,anyhow::Error>(())
    }).await;
    token.cancel();
    release.notify_one();
    runner.await??;
    server.abort();
    let _stopped = server.await;
    service.close_recovery().await;
    resources.close().await?;
    first.close().await;
    second.close().await;
    result?
}
