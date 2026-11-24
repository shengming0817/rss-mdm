//! Scope composition; all business decisions remain in their owners.
use std::sync::Arc;
pub(crate) async fn open(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    probe: rss_transactional_messaging::fence::ExecutionBinding,
    clock: Arc<dyn crate::clock::Clock>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    cursor_key: Vec<u8>,
    read_pool: sqlx::PgPool,
) -> Result<Arc<rss_mdm_scope_service::Scopes>, crate::Error> {
    bind(runtime, probe, clock, audit, cursor_key, read_pool, false).await
}
pub(crate) async fn editor(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    probe: rss_transactional_messaging::fence::ExecutionBinding,
    clock: Arc<dyn crate::clock::Clock>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    cursor_key: Vec<u8>,
    read_pool: sqlx::PgPool,
) -> Result<Arc<rss_mdm_scope_service::Scopes>, crate::Error> {
    bind(runtime, probe, clock, audit, cursor_key, read_pool, true).await
}
async fn bind(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    probe: rss_transactional_messaging::fence::ExecutionBinding,
    clock: Arc<dyn crate::clock::Clock>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    cursor_key: Vec<u8>,
    read_pool: sqlx::PgPool,
    editing: bool,
) -> Result<Arc<rss_mdm_scope_service::Scopes>, crate::Error> {
    let deadline = rss_mdm_scope_service::transaction::deadline();
    let groups = rss_mdm_group_postgres::GroupSources::bind(runtime.clone(), probe, deadline)
        .await
        .map_err(|_| {
            crate::Error::Scope(rss_mdm_scope_service::Error::Unavailable(
                rss_mdm_scope_service::Failure::Admission,
            ))
        })?
        .with_input_validity(crate::administration::user_profiles::device_fields::group_current);
    let reconcile_messaging = Box::pin(rss_reconcile_postgres::PgMessagingStore::new(
        runtime.clone(),
        probe,
        deadline,
    ))
    .await
    .map_err(|_| {
        crate::Error::Scope(rss_mdm_scope_service::Error::Unavailable(
            rss_mdm_scope_service::Failure::Admission,
        ))
    })?;
    let dependencies = rss_mdm_scope_service::Dependencies {
        objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects),
        groups: Arc::new(groups),
        dependents: Arc::new(crate::assembly::policy::ScopeDependents(
            rss_mdm_policy_service::management::scope_changes::ScopeChanges::new(
                rss_mdm_install_support::StorageProfile::Mdm,
                runtime.clone(),
                reconcile_messaging.clone(),
            ),
        )),
        reconcile_messaging,
        audit_store: audit,
        cursor_key,
        read_pool,
    };
    let clock: Arc<dyn rss_mdm_scope_service::clock::Clock> =
        Arc::new(crate::clock::ScopeClock(clock));
    let scopes = if editing {
        rss_mdm_scope_service::Scopes::bind_policy(
            rss_mdm_install_support::StorageProfile::Mdm,
            runtime,
            probe,
            clock,
            dependencies,
        )
        .await?
    } else {
        rss_mdm_scope_service::Scopes::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            runtime,
            probe,
            clock,
            dependencies,
        )
        .await?
    };
    Ok(Arc::new(scopes))
}
