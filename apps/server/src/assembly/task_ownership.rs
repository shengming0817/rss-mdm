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
    let owners = [
        (
            Owner::Execution,
            rss_mdm_execution_service::capacity::owned_ids_on(c, tenant, &[id]).await?,
        ),
        (
            Owner::Script,
            rss_mdm_script_service::storage::owned_ids_on(c, tenant, &[id]).await?,
        ),
        (
            Owner::Collection,
            rss_mdm_inventory_service::collection::execution::storage::owned_ids_on(
                c,
                tenant,
                &[id],
            )
            .await?,
        ),
        (
            Owner::Software,
            rss_mdm_software_service::deployment::capacity::owned_ids_on(c, tenant, &[id]).await?,
        ),
        (
            Owner::Registration,
            rss_mdm_registration_service::enrollment::tasks::storage::owned_ids_on(
                c,
                tenant,
                &[id],
            )
            .await?,
        ),
        (
            Owner::Access,
            rss_mdm_registration_service::device_access::execution::storage::owned_ids_on(
                c,
                tenant,
                &[id],
            )
            .await?,
        ),
        (
            Owner::Credential,
            rss_mdm_recovery_credentials::tasks::storage::owned_ids_on(c, tenant, &[id]).await?,
        ),
    ];
    let mut found = owners
        .into_iter()
        .filter_map(|(owner, ids)| (!ids.is_empty()).then_some(owner));
    match (found.next(), found.next()) {
        (Some(owner), None) => Ok(owner),
        (None, _) => Err(sqlx::Error::RowNotFound),
        _ => Err(sqlx::Error::Protocol("ambiguous task owner".into())),
    }
}
