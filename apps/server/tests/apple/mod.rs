//! Apple owns receipt correlation and exact DDM scope/version persistence, independently of OS effect claims.
mod fixture;
use fixture::Fixture;
mod support;
use crate::{
    authority_t2_support::Context, command_runtime_t2_support as command,
    native_identity_t2_support as identity,
};
use anyhow::Result;
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_device_service::control::{Create, NativeTarget, Task, authority::Authority};
use std::sync::Arc;
use uuid::Uuid;
fn audit(c: &Context) -> RequestAudit {
    RequestAudit::new(
        c.tenant.to_string(),
        "apple_management",
        AuditIntent::Management,
    )
}
async fn delivery(c: &Context, a: &Fixture) -> Result<rss_mdm_apple_channel::delivery::Delivery> {
    Ok(rss_mdm_apple_channel::delivery::Delivery {
        runtime: a.resources.storage.runtime.clone(),
        tenant: c.tenant,
        audit: Arc::new(
            c.audit
                .on_runtime(
                    a.resources.storage.runtime.clone(),
                    c.tenant,
                    &rss_mdm_audit_integration::budget::AuditBudget::new(
                        std::time::Duration::from_secs(5),
                    )
                    .control(),
                )
                .await?,
        ),
        business: Arc::new(crate::assembly::apple_business::AppleBusiness(
            a.service.clone(),
            a.configuration.clone(),
            a.collections.clone(),
            a.software.service.clone(),
            a.registration.native.clone(),
            None,
            a.access_execution.service.clone(),
        )),
        facts: Arc::new(rss_mdm_apple_channel::flow_store::Store {
            protection: a.resources.protection.clone(),
        }),
    })
}
fn receipt(udid: &str, command: Uuid, user: Option<&str>) -> Result<Vec<u8>> {
    let mut d = plist::Dictionary::new();
    d.insert("UDID".into(), udid.into());
    d.insert("Status".into(), "Acknowledged".into());
    d.insert("CommandUUID".into(), command.to_string().into());
    if let Some(user) = user {
        d.insert("UserID".into(), user.into());
    }
    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, &d)?;
    Ok(bytes)
}
async fn manage(
    d: &rss_mdm_apple_channel::delivery::Delivery,
    apple: &Arc<rss_mdm_apple_channel::Apple>,
    p: &rss_mdm_registration_service::DevicePrincipal,
    c: &Context,
    bytes: Vec<u8>,
) -> Result<Vec<u8>> {
    let dictionary = rss_mdm_apple_mdm::protocol::decode(&bytes)?;
    let exchange =
        rss_mdm_apple_channel::exchange::prepare(apple.clone(), dictionary, bytes, None)?;
    d.management(apple.clone(), p, exchange, &audit(c))
        .await
        .map_err(|e| anyhow::anyhow!("Apple management: {e:?}"))
}
#[tokio::test]
#[ignore = "T2: verified native certificate, real CommandUUID receipt and wrong-user rollback"]
async fn command_receipt_matches_device_and_user_without_inventing_os_effect() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let n = identity::seed(&c, "apple").await?;
    let key = crate::device_material_support::protection(&c)?;
    let user = Uuid::new_v4().to_string();
    let (apple, p) = support::apple(&c, &n, key.clone(), std::slice::from_ref(&user)).await?;
    let operation = Uuid::new_v4();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let task: Task = serde_json::from_value(
        serde_json::json!({"platform":"macos","request":{"kind":"command","command":{"requestType":"RestartDevice","fields":{}}}}),
    )?;
    let input = Create {
        operation_id: operation,
        input_version: "device-control-v1".into(),
        target: NativeTarget::Device,
        task,
        deadline: now + 300,
    };
    let account = c
        .account(&[rss_mdm_authorization_service::Permission::DeviceControl])
        .await?;
    let proof = c.authenticate(&account).await?;
    let authority = Authority::DeviceControl {
        action: rss_mdm_device_service::control::device_control::Kind::Restart,
        confirmation: None,
        required: input.task.permissions()?,
        actor: proof.actor(),
    };
    support::operation(&c, &n, &key, &input, authority, None).await?;
    let attempt = support::dispatched(&c, &n, &key, operation).await?;
    let a = Fixture::open(&c, false).await?;
    let d = delivery(&c, &a).await?;
    let state = || {
        sqlx::query_as::<_,(String,bool,Option<Vec<u8>>)>("SELECT state,accepted,response FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(attempt).fetch_one(&c.operator)
    };
    let before = state().await?;
    assert_eq!(before, ("sent".into(), false, None));
    assert!(
        manage(
            &d,
            &apple,
            &p,
            &c,
            receipt(&n.device, attempt, Some(&user))?
        )
        .await
        .is_err()
    );
    assert_eq!(state().await?, before);
    assert!(
        manage(
            &d,
            &apple,
            &p,
            &c,
            receipt(&n.device, Uuid::new_v4(), None)?
        )
        .await
        .is_err()
    );
    assert_eq!(state().await?, before);
    let ack = receipt(&n.device, attempt, None)?;
    manage(&d, &apple, &p, &c, ack.clone()).await?;
    let settled = state().await?;
    assert_eq!(settled.0, "acknowledged");
    assert!(settled.1);
    assert!(settled.2.is_some());
    let status: String = sqlx::query_scalar(
        "SELECT status FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(operation.to_string())
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(
        status, "received",
        "ACK records delivery, never a Restart OS effect"
    );
    manage(&d, &apple, &p, &c, ack).await?;
    assert_eq!(state().await?, settled);
    drop(d);
    Fixture::close(a).await?;
    c.close().await;
    Ok(())
}
fn ddm(udid: &str, user: &str, token: &str) -> Result<plist::Dictionary> {
    let report = serde_json::json!({"FullReport":true,"Errors":[],"StatusItems":{"management":{"declarations":{"activations":[],"configurations":[{"identifier":"subscriptions","server-token":token,"active":true,"valid":"valid"}],"assets":[],"management":[]}}}});
    let mut d = plist::Dictionary::new();
    d.insert("MessageType".into(), "DeclarativeManagement".into());
    d.insert("UDID".into(), udid.into());
    d.insert("UserID".into(), user.into());
    d.insert("Endpoint".into(), "status".into());
    d.insert(
        "Data".into(),
        plist::Value::Data(serde_json::to_vec(&report)?),
    );
    Ok(d)
}
#[tokio::test]
#[ignore = "T2: true DDM status exchange, committed synchronization and exact user/version"]
async fn ddm_sync_returns_only_committed_current_user_and_publication() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let mut seed = command::seed_transaction(&c).await?;
    sqlx::query("SELECT mdm.seed_tenant_catalog($1::uuid)")
        .bind(c.tenant.to_string())
        .execute(&mut *seed)
        .await?;
    seed.commit().await?;
    let n = identity::seed(&c, "apple").await?;
    let key = crate::device_material_support::protection(&c)?;
    let user = Uuid::new_v4().to_string();
    let other = Uuid::new_v4().to_string();
    let (apple, p) = support::apple(&c, &n, key.clone(), &[user.clone(), other.clone()]).await?;
    let (id, version, token) = support::publication(&c, &n, &key, &user).await?;
    let (sentinel, _, old_token) = support::publication(&c, &n, &key, &other).await?;
    let a = Fixture::open(&c, false).await?;
    let d = delivery(&c, &a).await?;
    let stale = rss_mdm_apple_channel::ddm::prepare(
        apple.clone(),
        &ddm(&n.device, &user, &old_token)?,
        None,
    )?;
    let reply = d
        .ddm(&p, stale, &audit(&c))
        .await
        .map_err(|e| anyhow::anyhow!("Apple stale DDM: {e:?}"))?;
    assert!(reply.synchronized.is_empty());
    let exchange =
        rss_mdm_apple_channel::ddm::prepare(apple.clone(), &ddm(&n.device, &user, &token)?, None)?;
    let reply = d
        .ddm(&p, exchange, &audit(&c))
        .await
        .map_err(|e| anyhow::anyhow!("Apple DDM: {e:?}"))?;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.synchronized.len(), 1);
    let fact = &reply.synchronized[0];
    assert_eq!(fact.operation, id);
    assert_eq!(fact.registration, n.registration);
    assert_eq!(fact.generation, 1);
    assert_eq!(fact.user, user);
    assert_eq!(fact.input_version, version);
    assert_eq!(fact.publication_version, id.to_string());
    let rows:Vec<(String,String)>=sqlx::query_as("SELECT command_id,status FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=ANY($2) ORDER BY command_id").bind(c.tenant.to_string()).bind(vec![id.to_string(),sentinel.to_string()]).fetch_all(&c.operator).await?;
    assert_eq!(rows.len(), 2);
    assert!(rows.contains(&(id.to_string(), "applied".into())));
    assert!(rows.contains(&(sentinel.to_string(), "published".into())));
    let projection:Vec<u8>=sqlx::query_scalar("SELECT projection FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND operation=$2 AND user_key=$3 AND generation=1").bind(c.tenant.to_string()).bind(id).bind(&user).fetch_one(&c.operator).await?;
    assert!(!projection.is_empty());
    let untouched: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT projection FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND operation=$2",
    )
    .bind(c.tenant.to_string())
    .bind(sentinel)
    .fetch_one(&c.operator)
    .await?;
    assert!(untouched.is_none());
    let reports:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_apple.status_reports WHERE tenant_id=$1::uuid AND registration=$2 AND generation=1 AND user_key=$3").bind(c.tenant.to_string()).bind(n.registration).bind(&user).fetch_one(&c.operator).await?;
    assert_eq!(reports, 2);
    let replay =
        rss_mdm_apple_channel::ddm::prepare(apple.clone(), &ddm(&n.device, &user, &token)?, None)?;
    let replay = d.ddm(&p, replay, &audit(&c)).await?;
    assert_eq!(replay.bytes, reply.bytes);
    drop(d);
    Fixture::close(a).await?;
    c.close().await;
    Ok(())
}
