//! Prepare the real independent workers over one host-owned scheduling resource.
use rss_mdm_policy_service::{
    application::Application,
    events::Events,
    worker::{Automation, PolicyWork},
};
use std::sync::Arc;
#[derive(Clone)]
pub(crate) struct Workers {
    pub(crate) policy: Arc<PolicyWork>,
    pub(crate) runner: Arc<Automation>,
    pub(crate) source: Arc<rss_mdm_flow_service::source_work::SourceChangesWork>,
    pub(crate) scheduler: crate::scheduler::SchedulerStorage,
}
impl Workers {
    pub(crate) async fn open(
        application: Arc<Application>,
        events: Option<Arc<Events>>,
        options: sqlx::postgres::PgConnectOptions,
    ) -> Result<Self, crate::Error> {
        let scheduler = crate::scheduler::SchedulerStorage::open(options).await?;
        let source = rss_mdm_flow_service::source_work::SourceChangesWork::new(
            crate::policy_assembly::source(&application),
            scheduler.store.clone(),
        );
        let policy = match events {
            Some(events) => PolicyWork::new(application, events, scheduler.store.clone()),
            None => PolicyWork::management_only(application, scheduler.store.clone()),
        };
        let runner = Automation::new(policy.clone());
        Ok(Self {
            policy,
            runner,
            source,
            scheduler,
        })
    }
    pub(crate) fn register(
        &self,
        signals: &crate::worker_wake::Signals,
        mut stage: impl FnMut(rss_runtime::ManagedTaskRegistration),
    ) {
        stage(self.runner.clone().registration(signals.policy()));
        stage(self.source.clone().registration(signals.flow()));
    }
}
