//! Static identity composition; missing or duplicate ownership never falls through authorization.
use sqlx::PgConnection;
use uuid::Uuid;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Owner {
    Execution,
    Access,
    Credential,
    Script,
    Collection,
    Software,
    Registration,
}
pub(crate) async fn on(
    c: &mut PgConnection,
    tenant: rss_request_context::TenantId,
    id: Uuid,
) -> Result<Owner, sqlx::Error> {
    let mut owners = Vec::with_capacity(7);
    if !rss_mdm_execution_service::capacity::owned_ids_on(c, tenant, &[id])
        .await?
        .is_empty()
    {
        owners.push(Owner::Execution);
    }
    if !rss_mdm_script_service::storage::owned_ids_on(c, tenant, &[id])
        .await?
        .is_empty()
    {
        owners.push(Owner::Script);
    }
    if !rss_mdm_inventory_service::collection::execution::storage::owned_ids_on(c, tenant, &[id])
        .await?
        .is_empty()
    {
        owners.push(Owner::Collection);
    }
    if !rss_mdm_software_service::deployment::capacity::owned_ids_on(c, tenant, &[id])
        .await?
        .is_empty()
    {
        owners.push(Owner::Software);
    }
    if !rss_mdm_registration_service::enrollment::tasks::storage::owned_ids_on(c, tenant, &[id])
        .await?
        .is_empty()
    {
        owners.push(Owner::Registration);
    }
    if !rss_mdm_registration_service::device_access::execution::storage::owned_ids_on(
        c,
        tenant,
        &[id],
    )
    .await?
    .is_empty()
    {
        owners.push(Owner::Access);
    }
    if !rss_mdm_recovery_credentials::tasks::storage::owned_ids_on(c, tenant, &[id])
        .await?
        .is_empty()
    {
        owners.push(Owner::Credential);
    }
    match owners.as_slice() {
        [owner] => Ok(*owner),
        [] => Err(sqlx::Error::RowNotFound),
        _ => Err(sqlx::Error::Protocol("ambiguous task owner".into())),
    }
}
