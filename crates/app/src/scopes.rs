//! Scope composition; all business decisions remain in their owners.
use std::sync::Arc;
pub(crate) async fn open(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    tenant: rss_request_context::TenantId,
    clock: Arc<dyn crate::clock::Clock>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    cursor_key: Vec<u8>,
) -> Result<Arc<rss_mdm_scope_service::Scopes>, crate::Error> {
    let deadline = rss_mdm_scope_service::transaction::deadline();
    let groups = rss_mdm_group_postgres::GroupStore::new(runtime.clone(), tenant, deadline)
        .await
        .map_err(|_| {
            crate::Error::Scope(rss_mdm_scope_service::Error::Unavailable(
                rss_mdm_scope_service::Failure::Admission,
            ))
        })?;
    let reconcile_messaging =
        rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), tenant, deadline)
            .await
            .map_err(|_| {
                crate::Error::Scope(rss_mdm_scope_service::Error::Unavailable(
                    rss_mdm_scope_service::Failure::Admission,
                ))
            })?;
    let dependencies = rss_mdm_scope_service::Dependencies {
        objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(
            audit.clone(),
        )),
        groups: Arc::new(groups),
        projection: Arc::new(rss_mdm_execution_service::scope::ScopeProjection::new(
            runtime.clone(),
            tenant,
        )),
        dependents: Arc::new(crate::policy_assembly::ScopeDependents(
            rss_mdm_policy_service::management::scope_changes::ScopeChanges::new(
                runtime.clone(),
                tenant,
            ),
        )),
        reconcile_messaging,
        audit_store: audit,
        cursor_key,
    };
    Ok(Arc::new(
        rss_mdm_scope_service::Scopes::new(
            runtime,
            tenant,
            Arc::new(crate::clock::ScopeClock(clock)),
            dependencies,
        )
        .await?,
    ))
}
