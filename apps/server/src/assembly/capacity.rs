//! The one device capacity boundary sums concrete business owners on the original connection.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
pub(crate) struct Capacity;
async fn available(tx: &mut PgTransaction<'_>, device: &str, now: i64) -> Result<bool, PgError> {
    let tenant = tx.tenant_id();
    tx.with_connection_context(&mut (device,), |(device,), c| {
        Box::pin(async move { available_on(c, tenant, device, now).await })
    })
    .await
}
pub(crate) async fn available_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    device: &str,
    now: i64,
) -> Result<bool, PgError> {
    let execution =
        rss_mdm_device_service::control::capacity::active_count_on(c, tenant, device, now).await?;
    let script = rss_mdm_script_service::storage::active_count_on(c, tenant, device, now).await?;
    let collection = rss_mdm_inventory_service::collection::execution::storage::active_count_on(
        c, tenant, device, now,
    )
    .await?;
    let software =
        rss_mdm_software_service::deployment::capacity::active_count_on(c, tenant, device, now)
            .await?;
    let registration = rss_mdm_registration_service::enrollment::tasks::storage::active_count_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        tenant,
        device,
        now,
    )
    .await?;
    let access =
        rss_mdm_device_access_postgres::device_access::execution::storage::active_count_on(
            c, tenant, device, now,
        )
        .await?;
    let credential_native =
        rss_mdm_recovery_credentials::native::storage::active_count_on(c, tenant, device).await?;
    let credential = rss_mdm_recovery_credentials::tasks::storage::active_count_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        tenant,
        device,
        now,
    )
    .await?;
    let da_credential = rss_mdm_recovery_credentials::tasks::storage::active_count_on(
        rss_mdm_install_support::StorageProfile::Da,
        c,
        tenant,
        device,
        now,
    )
    .await?;
    Ok(execution
        + da_credential
        + script
        + collection
        + software
        + registration
        + access
        + credential_native
        + credential
        < 128)
}

impl rss_mdm_device_service::control::capacity::DeviceCapacity for Capacity {
    fn available_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        device: &'a str,
        now: i64,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = rss_mdm_device_service::control::Result<bool>> + Send + 'a>,
    > {
        Box::pin(async move { Ok(available(tx, device, now).await?) })
    }
}
impl rss_mdm_script_service::DeviceCapacity for Capacity {
    fn available_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        device: &'a str,
        now: i64,
    ) -> std::pin::Pin<Box<dyn Future<Output = rss_mdm_script_service::Result<bool>> + Send + 'a>>
    {
        Box::pin(async move { Ok(available(tx, device, now).await?) })
    }
}
impl rss_mdm_inventory_service::collection::execution::participants::DeviceCapacity for Capacity {
    fn available_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        device: &'a str,
        now: i64,
    ) -> rss_mdm_inventory_service::collection::execution::participants::Pending<'a, bool> {
        Box::pin(async move { Ok(available(tx, device, now).await?) })
    }
}

impl rss_mdm_software_service::deployment::capacity::DeviceCapacity for Capacity {
    fn available_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        device: &'a str,
        now: i64,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = rss_mdm_software_service::deployment::Result<bool>> + Send + 'a>,
    > {
        Box::pin(async move { Ok(available(tx, device, now).await?) })
    }
}

impl rss_mdm_registration_service::participants::capacity::DeviceCapacity for Capacity {
    fn available_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        device: &'a str,
        now: i64,
    ) -> std::pin::Pin<
        Box<
            dyn Future<Output = Result<bool, rss_mdm_registration_service::participants::Error>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move { Ok(available(tx, device, now).await?) })
    }
}
