//! A controlled TLS provider exercises both Apple worker registrations on the same database.
use super::*;
use crate::provider_http_t2_support::Listener;
use axum::{
    Json, Router,
    http::HeaderMap,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::Notify;

async fn pending(
    c: &Context,
    n: &identity::Native,
    key: &rss_mdm_native_protection::Protector,
) -> Result<Uuid> {
    let task: Task = serde_json::from_value(
        json!({"platform":"macos","request":{"kind":"command","command":{"requestType":"RestartDevice","fields":{}}}}),
    )?;
    let input = Create {
        operation_id: Uuid::new_v4(),
        input_version: "device-control-v1".into(),
        target: NativeTarget::Device,
        task,
        deadline: time::OffsetDateTime::now_utc().unix_timestamp() + 300,
    };
    let account = c
        .account(&[rss_mdm_authorization_service::Permission::DeviceControl])
        .await?;
    let authority = Authority::DeviceControl {
        action: rss_mdm_device_service::control::device_control::Kind::Restart,
        confirmation: false,
        required: input.task.permissions()?,
        actor: c.authenticate(&account).await?.actor(),
    };
    support::operation(c, n, key, &input, authority, None).await?;
    let org = Uuid::new_v4();
    let aad = rss_mdm_native_protection::ProtectionContext::new(
        c.tenant,
        &format!("{org}:1"),
        "apple.ade.token",
        1,
    )?
    .derive();
    let token=key.seal_bytes(&serde_json::to_vec(&json!({"consumer_key":"fixture","consumer_secret":"unit-secret",
        "access_token":org.to_string(),"access_secret":"test-secret","access_token_expiry":"2099-01-01T00:00:00Z"}))?,&aad)?;
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_apple.organizations(tenant_id,id) VALUES($1::uuid,$2)")
        .bind(c.tenant.to_string())
        .bind(org)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO mdm_apple.ade_servers(tenant_id,organization,revision,enabled,server_uuid,org_id,key_id,certificate,private_key,token,token_revision,token_expires,verified)
        VALUES($1::uuid,$2,1,true,$3,'fixture',$4,$5,$6,$7,1,4070908800,true)")
        .bind(c.tenant.to_string()).bind(org).bind(Uuid::new_v4()).bind(Uuid::new_v4()).bind(&n.root).bind(&token).bind(&token)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(org)
}
#[tokio::test]
#[ignore = "T2: APNs and multipage ADE commit for an independent tenant while the first provider response is held"]
async fn independent_tenants_progress_through_live_apple_workers() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let other = Context::open("shared", &[]).await?;
    let a = Fixture::open(&c).await?;
    let n = identity::seed(&c, "apple").await?;
    let other_n = identity::seed(&other, "apple").await?;
    let key = a.resources.protection.clone();
    let first = (&c, &n);
    let second = (&other, &other_n);
    for (ctx, native) in [first, second] {
        support::apple(ctx, native, key.clone(), &[]).await?;
    }
    let sibling=identity::seed(&c,"apple").await?;
    support::seed_channels(&c,&sibling,&key,&[]).await?;
    let org = pending(first.0, first.1, &key).await?;
    let mut skew = command::seed_transaction(&c).await?;
    sqlx::query(
        "UPDATE mdm_apple.ade_servers SET token_expires=101,next_sync=100 WHERE organization=$1",
    )
    .bind(org)
    .execute(&mut *skew)
    .await?;
    for (clock, expected) in [(100_i64, true), (101, false)] {
        let eligible: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_apple.ade_work_scopes(NULL,NULL,NULL,1,$1) WHERE tenant_id=$2::uuid)")
            .bind(clock).bind(c.tenant.to_string()).fetch_one(&mut *skew).await?;
        assert_eq!(eligible, expected);
    }
    skew.rollback().await?;
    let token = Uuid::new_v4();
    let aad = rss_mdm_native_protection::ProtectionContext::new(
        c.tenant,
        &serde_json::to_string(&(n.device, "", 1i64))?,
        "apple.push.material",
        1,
    )?
    .derive();
    let bytes = serde_json::to_vec(&json!({"token":token.as_bytes(),"magic":"native-t2"}))?;
    let compare = rss_mdm_native_protection::ProtectionContext::new(
        c.tenant,
        &serde_json::to_string(&(n.device, "", 0i64))?,
        "apple.push.compare",
        1,
    )?
    .derive();
    let mut tx = command::seed_transaction(&c).await?;
    sqlx::query("UPDATE mdm_apple.channels SET material=$3,material_digest=$4 WHERE tenant_id=$1::uuid AND device=$2 AND user_key=''")
        .bind(c.tenant.to_string()).bind(n.device.into_uuid()).bind(key.seal_bytes(&bytes,&aad)?)
        .bind(key.mac(&bytes,&compare)?.to_vec()).execute(&mut *tx).await?;
    tx.commit().await?;
    let gate = Arc::new(Notify::new());
    let apns_waiting = Arc::new(Notify::new());
    let ade_waiting = Arc::new(Notify::new());
    let blocked_push_id = Arc::new(std::sync::OnceLock::new());
    let apns = {
        let gate = gate.clone();
        let waiting = apns_waiting.clone();
        let blocked = blocked_push_id.clone();
        move |axum::extract::Path(target): axum::extract::Path<String>, headers: HeaderMap| {
            let gate = gate.clone();
            let waiting = waiting.clone();
            let blocked = blocked.clone();
            async move {
                let id = headers["apns-id"]
                    .to_str()
                    .unwrap()
                    .parse::<Uuid>()
                    .unwrap();
                if target == token.simple().to_string() && blocked.set(id).is_ok() {
                    waiting.notify_one();
                    gate.notified().await;
                }
                axum::http::StatusCode::OK
            }
        }
    };
    let session = move |headers: HeaderMap| async move {
        let auth = headers["authorization"].to_str().unwrap();
        Json(
            json!({"auth_session_token":if auth.contains(&org.to_string()) {"blocked"}else{"ready"}}),
        )
    };
    let pages = {
        let gate = gate.clone();
        let waiting = ade_waiting.clone();
        move |headers: HeaderMap, Json(request): Json<Value>| {
            let gate = gate.clone();
            let waiting = waiting.clone();
            async move {
                if headers["x-adm-auth-session"] == "blocked" && request.get("cursor").is_none() {
                    waiting.notify_one();
                    gate.notified().await;
                }
                let more = request.get("cursor").is_none();
                Json(
                    json!({"devices":[{"serial_number":if more{"first"}else{"second"},"device_assigned_date":"2026-01-01T00:00:00Z"}],
                "cursor":if more{"continued"}else{"complete"},"more_to_follow":more}),
                )
            }
        }
    };
    let listener = Listener::open(&n.directory).await?;
    let port = listener.address()?.port();
    let router = Router::new()
        .route("/3/device/{token}", post(apns))
        .route("/session", get(session))
        .route("/server/devices", post(pages));
    let server = tokio::spawn(axum::serve(listener, router).into_future());
    let mut state = super::renewal::state(
        &c,
        &a,
        Arc::new(rss_mdm_pki_service::providers::Providers::new(vec![])?),
    )
    .await?;
    let root = std::fs::read(c.inputs.directory.join("task-trust-ca/ca.pem"))?;
    state.material_roots = Arc::new(vec![root.clone()]);
    state.apple = Some(Arc::new(
        rss_mdm_apple_channel::runtime_materials::runtime::Runtime::new(
            "https://localhost".into(),
            None,
        )
        .with_loopback_provider(port, reqwest::Certificate::from_pem(&root)?),
    ));
    let state = Arc::new(state);
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    let push_hint = Arc::new(Notify::new());
    let ade_hint = Arc::new(Notify::new());
    launch.stage_deferred_task_with_token(
        rss_mdm_apple_channel::push::registration(state.clone(), rss_mdm_work_page::external::Limits::new(8.try_into()?,7.try_into()?).unwrap(), push_hint.clone()).critical(),
    );
    launch.stage_deferred_task_with_token(
        rss_mdm_apple_channel::ade::registration(state.clone(), 8.try_into()?, ade_hint.clone()).critical(),
    );
    launch.finish();
    let result=tokio::time::timeout(Duration::from_secs(15),async {
        tokio::join!(apns_waiting.notified(),ade_waiting.notified());
        let sibling_org=pending(&c,&sibling,&key).await?;
        let second_org = pending(second.0, second.1, &key).await?;
        push_hint.notify_one();
        ade_hint.notify_one();
        loop {
            let (pushed,synced,blocked):(bool,bool,bool)=sqlx::query_as("SELECT
                EXISTS(SELECT FROM mdm_apple.channels WHERE tenant_id=$2::uuid AND device=$6 AND push_outcome='accepted')
                    AND EXISTS(SELECT FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND device=$7 AND push_id=$3 AND push_lease_until>statement_timestamp()),
                EXISTS(SELECT FROM mdm_apple.ade_servers WHERE organization=$4 AND cursor='complete')
                    AND (SELECT count(*) FROM mdm_apple.ade_devices WHERE organization=$4)=2,
                EXISTS(SELECT FROM mdm_apple.ade_operations WHERE organization=$5 AND state='running')")
                .bind(c.tenant.to_string()).bind(other.tenant.to_string()).bind(blocked_push_id.get().copied().unwrap())
                .bind(second_org).bind(org).bind(other_n.device.into_uuid()).bind(n.device.into_uuid()).fetch_one(&c.operator).await?;
            let siblings:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND device=$2 AND push_outcome='accepted') AND EXISTS(SELECT FROM mdm_apple.ade_servers WHERE tenant_id=$1::uuid AND organization=$3 AND cursor='complete')").bind(c.tenant.to_string()).bind(sibling.device.into_uuid()).bind(sibling_org).fetch_one(&c.operator).await?;
            if pushed && synced && blocked && siblings {break;}
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_,anyhow::Error>(())
    }).await;
    gate.notify_waiters();
    assert!(stack.shutdown().join().await?.is_clean());
    server.abort();
    let _stopped = server.await;
    a.close().await?;
    other.close().await;
    c.close().await;
    result?
}
