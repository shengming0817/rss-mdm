mod applicability;
mod fixture;
mod reads;
use crate::{
    authority_t2_support::Context, command_runtime_t2_support as command,
    native_identity_t2_support as native,
};
use anyhow::Result;
use fixture::Fixture;
use std::sync::Arc;
use uuid::Uuid;

async fn post(
    c: &Context,
    a: &Fixture,
    proof: &Arc<rss_mdm_authorization_service::context::AuthorizedPrincipal>,
    path: &str,
    body: serde_json::Value,
) -> Result<(u16, serde_json::Value)> {
    use tower::ServiceExt;
    let state = Arc::new(rss_mdm_management_http::device_control::Services {
        device_control: a.service.clone(),
        changes: Arc::new(crate::assembly::device_control::Changes {
            snapshot: a.policy_task_reads.snapshot.clone(),
            device_control: a.service.clone(),
        }),
    });
    let routes = rss_mdm_management_http::device_control::routes()
        .with_state::<()>(state)
        .layer(axum::Extension(c.request(proof)?))
        .layer(axum::Extension(c.read_auth(proof.clone())))
        .into_axum();
    let response = axum::Router::new()
        .nest("/api/v1/tenants/{tenant}", routes)
        .oneshot(
            axum::http::Request::post(format!("/api/v1/tenants/{}/{path}", c.tenant))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?;
    let status = response.status().as_u16();
    Ok((
        status,
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 262144).await?)?,
    ))
}

#[tokio::test]
#[ignore = "T2 #3121-1: missing dangerous-action confirmation has no command effects; current confirmation binds exact device"]
async fn current_confirmation_is_atomic() -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    use rss_mdm_device_service::control::device_control::{Action, Input};
    let c = Context::open("shared", &[]).await?;
    let identity = native::seed(&c, "windows").await?;
    let account = c
        .account(&[
            Permission::DeviceWipe,
            Permission::OperationRead,
            Permission::OperationCancel,
        ])
        .await?;
    let proof = Arc::new(c.authenticate(&account).await?);
    let a = Fixture::open(&c).await?;
    let mut tx = command::seed_transaction(&c).await?;
    sqlx::query("INSERT INTO mdm_windows.capabilities (tenant_id, device, protocol_epoch, os_version, edition, session, observed_at) VALUES (CAST($1 AS uuid), $2, $3, '10.0.22631.0', 4, 1, CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS bigint))").bind(c.tenant.to_string()).bind(identity.device.into_uuid()).bind(identity.epoch).execute(&mut *tx).await?;
    tx.commit().await?;
    let id = Uuid::new_v4();
    let mut input = Input {
        operation_id: id,
        deadline: time::OffsetDateTime::now_utc().unix_timestamp() + 300,
        action: Action::Wipe { confirmed: false },
    };
    let path = format!("devices/{}/operations", identity.device);
    assert_eq!(
        post(&c, &a, &proof, &path, serde_json::to_value(&input)?)
            .await?
            .0,
        400
    );
    let count:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND id=$2)+(SELECT count(*) FROM mdm_devices.control_requests WHERE tenant_id=$1::uuid AND id=$2)+(SELECT count(*) FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2::text)").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
    assert_eq!(count, 0);
    input.action = Action::Wipe { confirmed: true };
    let (status, receipt) = post(&c, &a, &proof, &path, serde_json::to_value(&input)?).await?;
    assert_eq!(status, 202);
    assert_eq!(receipt["operationId"], id.to_string());
    assert_eq!(
        post(&c, &a, &proof, &path, serde_json::to_value(&input)?).await?,
        (202, receipt.clone())
    );

    let change =
        serde_json::json!({"requestId":Uuid::new_v4(),"expectedRevision":receipt["revision"]});
    let reader = c.account(&[Permission::OperationRead]).await?;
    let reader = Arc::new(c.authenticate(&reader).await?);
    assert_eq!(
        post(
            &c,
            &a,
            &reader,
            &format!("{path}/{id}/cancel"),
            change.clone()
        )
        .await?
        .0,
        403
    );
    let (status, changed) = post(&c, &a, &proof, &format!("{path}/{id}/cancel"), change).await?;
    assert_eq!(status, 200, "{changed:?}");
    assert_eq!(changed["operationId"], id.to_string());
    let reauthorize = serde_json::json!({"requestId":Uuid::new_v4(),"expectedRevision":changed["revision"],"confirmation":null});
    let (status, _) = post(
        &c,
        &a,
        &proof,
        &format!("{path}/{id}/reauthorize"),
        reauthorize,
    )
    .await?;
    assert_eq!(status, 409);
    let stored:Uuid=sqlx::query_scalar("SELECT device FROM mdm_devices.control_operations WHERE tenant_id = CAST($1 AS uuid) AND id = $2").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
    assert_eq!(stored, identity.device.into_uuid());
    Fixture::close(a).await?;
    c.close().await;
    Ok(())
}
