mod applicability;
mod fixture;
use crate::{
    authority_t2_support::Context, command_runtime_t2_support as command,
    native_identity_t2_support as native,
};
use anyhow::Result;
use fixture::Fixture;
use uuid::Uuid;
#[tokio::test]
#[ignore = "T2 #3121-1: stale dangerous-action confirmation has no command effects; current confirmation binds exact generation"]
async fn current_confirmation_is_atomic() -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    use rss_mdm_device_service::control::device_control::{Action, Input};
    let c = Context::open("shared", &[]).await?;
    let identity = native::seed(&c, "windows").await?;
    let account = c.account(&[Permission::DeviceWipe]).await?;
    let proof = c.authenticate(&account).await?;
    let a = Fixture::open(&c, false).await?;
    let mut tx = command::seed_transaction(&c).await?;
    sqlx::query("INSERT INTO mdm_windows.capabilities(tenant_id,registration,generation,os_version,edition,session,observed_at) VALUES($1::uuid,$2,1,'10.0.22631.0',4,1,extract(epoch FROM clock_timestamp())::bigint)").bind(c.tenant.to_string()).bind(identity.registration).execute(&mut *tx).await?;
    tx.commit().await?;
    let id = Uuid::new_v4();
    let mut input = Input {
        operation_id: id,
        deadline: time::OffsetDateTime::now_utc().unix_timestamp() + 300,
        action: Action::Wipe {
            confirmed: true,
            expected_registration_id: identity.registration,
            expected_generation: 2,
        },
    };
    assert!(matches!(
        a.service
            .create_control(&proof, &identity.device, &input, &c.request(&proof)?)
            .await,
        Err(rss_mdm_device_service::control::Error::Conflict)
    ));
    let count:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND id=$2)+(SELECT count(*) FROM mdm_devices.control_requests WHERE tenant_id=$1::uuid AND id=$2)+(SELECT count(*) FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2::text)").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
    assert_eq!(count, 0);
    input.action = Action::Wipe {
        confirmed: true,
        expected_registration_id: identity.registration,
        expected_generation: 1,
    };
    a.service
        .create_control(&proof, &identity.device, &input, &c.request(&proof)?)
        .await?;
    a.service
        .create_control(&proof, &identity.device, &input, &c.request(&proof)?)
        .await?;
    let stored:(Uuid,i64)=sqlx::query_as("SELECT registration,registration_generation FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
    assert_eq!(stored, (identity.registration, 1));
    Fixture::close(a).await?;
    c.close().await;
    Ok(())
}
