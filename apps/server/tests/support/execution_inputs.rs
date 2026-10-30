//! Real Execution construction for independent input-consumption regressions.
use rss_reconcile::{Control, DurableStore};
use std::{sync::Arc, time::Duration};
pub(crate) struct InputOwner {
    pub execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    resources: tokio::sync::Mutex<super::runtime::Resources>,
}
impl InputOwner {
    pub async fn open(
        application: &crate::planning::test_support::OwnerFixture,
        concurrency: usize,
    ) -> anyhow::Result<Arc<Self>> {
        let tenant = application.tenant;
        let mut config = super::identity::config(&tenant.to_string())?;
        config.background.device_concurrency = concurrency;
        let (identity, mut resources) = super::identity::identity(&tenant.to_string()).await?;
        let key = application.cursor_key.clone();
        let assembly = crate::assembly::execution::open(
            &config,
            config.native_protector()?,
            application.policy.audit_store.clone(),
            None,
            Default::default(),
            rss_device_command_postgres::CommandClock::Postgres,
            Arc::new(
                rss_mdm_authorization_service::session::SessionAuthority::new(
                    identity.authority.clone(),
                    tenant,
                ),
            ),
            key,
        )
        .await?;
        resources.resource(rss_mdm_execution_service::Resource(
            assembly.service.clone(),
        ));
        let owner = Arc::new(Self {
            execution: assembly.service,
            runtime: assembly.runtime,
            resources: tokio::sync::Mutex::new(resources),
        });
        let timer = rss_mdm_execution_service::recovery::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = Control::new(&timer, Duration::from_secs(6), &cancel);
        owner
            .execution
            .recovery_store()
            .wake(
                &rss_mdm_execution_service::source_changes::target(tenant),
                &rss_reconcile::ResourceSet::empty(tenant),
                &control,
            )
            .await?;
        Ok(owner)
    }
    pub async fn close(&self) {
        std::mem::take(&mut *self.resources.lock().await)
            .finish(async { Ok(()) })
            .await
            .unwrap();
    }
}
