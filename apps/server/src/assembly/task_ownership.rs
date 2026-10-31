//! Static identity composition; missing or duplicate ownership never falls through authorization.
use sqlx::PgConnection;
use uuid::Uuid;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Owner {
    Execution,
    Script,
    Collection,
}
pub(crate) async fn on(
    c: &mut PgConnection,
    tenant: rss_request_context::TenantId,
    id: Uuid,
) -> Result<Owner, sqlx::Error> {
    let mut owners = Vec::with_capacity(3);
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
    match owners.as_slice() {
        [owner] => Ok(*owner),
        [] => Err(sqlx::Error::RowNotFound),
        _ => Err(sqlx::Error::Protocol("ambiguous task owner".into())),
    }
}
