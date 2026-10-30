//! Explicit Policy transaction bindings and foreign-owner adapters.
use rss_mdm_policy_service::{application::Application, events::Events};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransaction;
use std::sync::Arc;
pub(crate) async fn application(
    owner: &crate::owner_storage::OwnerRuntime,
    tenant: TenantId,
    key: &[u8],
    clock: Arc<dyn crate::clock::Clock>,
) -> Result<Arc<Application>, crate::Error> {
    Ok(Arc::new(
        Application::new(
            owner.audit.clone(),
            owner.runtime.clone(),
            tenant,
            Arc::new(crate::clock::PolicyClock(clock)),
            key,
            Arc::new(rss_mdm_device_service::planning::PlanningObjects),
        )
        .await?,
    ))
}
pub(crate) async fn events(
    application: Arc<Application>,
    materials: Arc<rss_mdm_execution_service::ExecutionMaterials>,
) -> Result<Arc<Events>, crate::Error> {
    let execution = Arc::new(
        rss_mdm_execution_service::policy_events::PolicyEvents::bind(
            application.runtime.clone(),
            application.tenant,
            application.audit_store.clone(),
            materials,
        )
        .await?,
    );
    Ok(Arc::new(Events {
        application,
        execution,
    }))
}
pub(crate) async fn management(
    application: &Arc<Application>,
    inputs: Arc<rss_mdm_execution_service::Inputs>,
    key: &[u8],
) -> Result<Arc<rss_mdm_policy_service::management::Policies>, crate::Error> {
    let store = Arc::new(
        rss_mdm_policy_postgres::PolicyStore::new(
            application.runtime.clone(),
            application.tenant,
            rss_mdm_policy_service::transaction::deadline(),
        )
        .await
        .map_err(|_| crate::Error::Unavailable(crate::Failure::PlanningStorage))?,
    );
    Ok(Arc::new(rss_mdm_policy_service::management::Policies::new(
        rss_mdm_policy_service::management::Dependencies {
            profile_validator: Arc::new(
                rss_mdm_telemetry_service::profile_validation::ProfileValidator,
            ),
            cursor_key: key.to_vec(),
            runtime: application.runtime.clone(),
            reconcile_messaging: application.reconcile_messaging.clone(),
            audit_store: application.audit_store.clone(),
            tenant: application.tenant,
            policy_store: store,
            inputs,
        },
    )))
}
pub(crate) struct ScopeDependents(
    pub rss_mdm_policy_service::management::scope_changes::ScopeChanges,
);
fn scope_error(
    e: rss_mdm_policy_service::transaction::Fault,
) -> rss_mdm_scope_service::transaction::Fault {
    use rss_mdm_policy_service::{Error as E, transaction::Fault as F};
    use rss_mdm_scope_service::{Error as S, Failure, transaction::Fault};
    match e {
        F::Storage(e) => Fault::Storage(e),
        F::Sql(e) => Fault::Sql(e),
        F::Request(e) => match e {
            E::Conflict => S::Conflict.into(),
            E::Malformed => S::Malformed.into(),
            E::Forbidden | E::Unauthorized => S::Forbidden.into(),
            E::NotFound | E::ResourceMissing => S::NotFound.into(),
            E::CommitUnknown => S::CommitUnknown.into(),
            E::RollbackFailed => S::RollbackFailed.into(),
            _ => S::Unavailable(Failure::Storage).into(),
        },
    }
}
impl rss_mdm_scope_service::sources::ScopeDependents for ScopeDependents {
    fn used_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        scope: uuid::Uuid,
    ) -> rss_mdm_scope_service::sources::Pending<'a, bool, rss_mdm_scope_service::transaction::Fault>
    {
        Box::pin(async move { self.0.used_in(tx, scope).await.map_err(scope_error) })
    }
    fn publication_recorded_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        scope: uuid::Uuid,
        run: uuid::Uuid,
    ) -> rss_mdm_scope_service::sources::Pending<'a, (), rss_mdm_scope_service::transaction::Fault>
    {
        Box::pin(async move {
            self.0
                .publication_recorded_in(tx, scope, run)
                .await
                .map_err(scope_error)
        })
    }
}
