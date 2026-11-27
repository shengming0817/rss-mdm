mod applicability;
mod fixture;
mod reads;
use crate::{
    authority_t2_support::Context, command_runtime_t2_support as command,
    native_identity_t2_support as native,
};
use anyhow::Result;
use fixture::Fixture;
use uuid::Uuid;

async fn post(
    client: &reqwest::Client,
    account: &crate::authority_t2_support::Account,
    url: &str,
    body: serde_json::Value,
) -> Result<(u16, serde_json::Value)> {
    use rss_mdm_authorization_service::credential::RequestCredential;
    let RequestCredential::Cookie(cookie) = account.credential()? else {
        anyhow::bail!("expected a browser session")
    };
    let response = client
        .post(url)
        .header(
            "cookie",
            format!("__Host-identity-session={}", cookie.expose()),
        )
        .header("origin", "https://mdm.example.test")
        .header("x-identity-request", "1")
        .header("x-csrf-token", cookie.csrf())
        .json(&body)
        .send()
        .await?;
    Ok((response.status().as_u16(), response.json().await?))
}

#[tokio::test]
#[ignore = "T2 #3121-1: missing dangerous-action confirmation has no command effects; current confirmation binds exact device"]
async fn current_confirmation_is_atomic() -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    let c = Context::open("device_control_host", &[]).await?;
    let identity = native::seed(&c, "windows").await?;
    let account = c
        .account(&[
            Permission::DeviceWipe,
            Permission::OperationRead,
            Permission::OperationCancel,
        ])
        .await?;
    let reader = c.account(&[Permission::OperationRead]).await?;
    let mut tx = command::seed_transaction(&c).await?;
    sqlx::query("INSERT INTO mdm_windows.capabilities (tenant_id, device, protocol_epoch, os_version, edition, session, observed_at) VALUES (CAST($1 AS uuid), $2, $3, '10.0.22631.0', 4, 1, CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS bigint))").bind(c.tenant.to_string()).bind(identity.device.into_uuid()).bind(identity.epoch).execute(&mut *tx).await?;
    tx.commit().await?;
    let address = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let config =
        crate::host_t2_support::configuration(&c.inputs, &c.profile, address, Uuid::new_v4())
            .await?;
    let context = &c;
    let result = crate::host_t2_support::run(config, |client, base| async move {
        confirm_and_cancel(context, &client, &base, identity.device, &account, &reader).await
    })
    .await;
    c.close().await;
    result
}

async fn confirm_and_cancel(
    c: &Context,
    client: &reqwest::Client,
    base: &str,
    device: rss_mdm_agent_wire::DeviceId,
    account: &crate::authority_t2_support::Account,
    reader: &crate::authority_t2_support::Account,
) -> Result<()> {
    let id = Uuid::new_v4();
    let path = format!(
        "{base}/api/v1/tenants/{}/devices/{}/operations",
        c.tenant, device
    );
    let receipt = create_confirmed(c, client, account, &path, id).await?;
    let change =
        serde_json::json!({"requestId":Uuid::new_v4(),"expectedRevision":receipt["revision"]});

    assert_eq!(
        post(
            client,
            reader,
            &format!("{path}/{id}/cancel"),
            change.clone()
        )
        .await?
        .0,
        403
    );
    let (status, changed) = post(client, account, &format!("{path}/{id}/cancel"), change).await?;
    assert_eq!(status, 200, "{changed:?}");
    assert_eq!(changed["operationId"], id.to_string());
    assert_eq!(
        changed["revision"].as_i64(),
        receipt["revision"].as_i64().map(|value| value + 1)
    );
    let reauthorize = |confirmation: serde_json::Value| {
        serde_json::json!({
            "requestId": Uuid::new_v4(), "expectedRevision": changed["revision"], "confirmation": confirmation
        })
    };
    let (status, _) = post(
        client,
        account,
        &format!("{path}/{id}/reauthorize"),
        reauthorize(serde_json::Value::Null),
    )
    .await?;
    assert_eq!(status, 409);
    let (status, _) = post(
        client,
        account,
        &format!("{path}/{id}/reauthorize"),
        reauthorize(serde_json::json!({"confirmed": true})),
    )
    .await?;
    assert_eq!(status, 409);
    let stored: (Uuid, String) = sqlx::query_as(
        "SELECT o.device, c.status FROM mdm_devices.control_operations o
         JOIN rss_device_command.commands c ON c.tenant_id=o.tenant_id AND c.command_id=o.id::text
         WHERE o.tenant_id=$1::uuid AND o.id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(stored, (device.into_uuid(), "cancelled".to_owned()));
    Ok(())
}

async fn create_confirmed(
    c: &Context,
    client: &reqwest::Client,
    account: &crate::authority_t2_support::Account,
    path: &str,
    id: Uuid,
) -> Result<serde_json::Value> {
    use rss_mdm_device_service::control::device_control::{Action, Input};
    let mut input = Input {
        operation_id: id,
        deadline: time::OffsetDateTime::now_utc().unix_timestamp() + 300,
        action: Action::Wipe { confirmed: false },
    };
    assert_eq!(
        post(client, account, path, serde_json::to_value(&input)?)
            .await?
            .0,
        400
    );
    let count:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND id=$2)+(SELECT count(*) FROM mdm_devices.control_requests WHERE tenant_id=$1::uuid AND id=$2)+(SELECT count(*) FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2::text)").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
    assert_eq!(count, 0);
    input.action = Action::Wipe { confirmed: true };
    let (status, receipt) = post(client, account, path, serde_json::to_value(&input)?).await?;
    assert_eq!(status, 202);
    assert_eq!(receipt["operationId"], id.to_string());
    assert_eq!(
        post(client, account, path, serde_json::to_value(&input)?).await?,
        (202, receipt.clone())
    );

    Ok(receipt)
}
