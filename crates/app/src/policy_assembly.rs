//! Explicit Policy transaction bindings and foreign-owner adapters.
use rss_mdm_policy_service::{application::Application, events::Events};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;
pub(crate) async fn events(
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    key: &[u8],
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
) -> Result<Arc<Events>, crate::Error> {
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(5));
    let audit = Arc::new(
        audit
            .on_runtime(runtime.clone(), tenant, &budget.control())
            .await?,
    );
    let objects = Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(
        audit.clone(),
    ));
    let application = Arc::new(
        Application::new(
            audit,
            runtime,
            tenant,
            Arc::new(crate::clock::SystemClock),
            key,
            objects,
        )
        .await?,
    );
    Ok(Arc::new(Events {
        application,
        execution,
    }))
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

pub(crate) fn source(
    application: &Application,
) -> Arc<rss_mdm_flow_service::source_work::SourceChanges> {
    Arc::new(rss_mdm_flow_service::source_work::SourceChanges::new(
        application.runtime.clone(),
        application.tenant,
        application.audit_store.clone(),
        application.reconcile_messaging.clone(),
        Arc::new(rss_mdm_policy_service::management::source::execution(
            application.objects.clone(),
        )),
        Arc::new(SourceClock(application.clock.clone())),
    ))
}
struct SourceClock(Arc<dyn rss_mdm_policy_service::clock::Clock>);
impl rss_mdm_flow_service::clock::Clock for SourceClock {
    fn unix_seconds(&self) -> Result<i64, rss_mdm_flow_service::Error> {
        self.0.unix_seconds().map_err(|_| {
            rss_mdm_flow_service::Error::Unavailable(rss_mdm_flow_service::Failure::Clock)
        })
    }
}
