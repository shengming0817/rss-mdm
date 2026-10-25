//! Test application startup and resource shutdown.
use super::*;

pub(crate) fn case_tenant() -> &'static str {
    crate::test_support::case::tenant()
}
pub(crate) fn case_device() -> &'static str {
    static VALUE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VALUE.get_or_init(|| format!("/api/v1/devices/{}", case::name("device-1")))
}

pub(crate) async fn database(value: &Value) -> Result<Arc<crate::Database>> {
    let config: Config = serde_json::from_value(value.clone())?;
    Ok(Arc::new(
        crate::Database::connect(config.access_options()?)
            .await
            .map_err(|error| anyhow::anyhow!("access database rejected: {error:?}"))?,
    ))
}

pub(crate) async fn app(value: &Value) -> Result<(Router, Resources)> {
    let (router, _, resources) = app_with_access(value, database(value).await?).await?;
    Ok((router, resources))
}

pub(crate) async fn app_with_access(
    value: &Value,
    access: Arc<crate::Database>,
) -> Result<(
    Router,
    Arc<rss_mdm_audit_integration::AuditStore>,
    Resources,
)> {
    let c: Config = serde_json::from_value(value.clone())?;
    let audit_store = access.audit_store_fixture(&c.audit).await?;
    let (router, _, _, _, resources) = crate::api::application_fixture(
        c,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        access,
        None,
        audit_store.clone(),
    )
    .await
    .map_err(|error| anyhow::anyhow!("fixture application admission: {error:?}"))?;
    Ok((
        router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse()?,
        ))),
        audit_store,
        resources,
    ))
}

pub(crate) fn monotonic() -> Arc<dyn rss_observation::Clock> {
    Arc::new(crate::Monotonic(|| {
        rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
    }))
}

pub(crate) async fn start_automation(value: &Value) -> Result<Option<rss_runtime::ShutdownStack>> {
    if !crate::test_support::case::owns_worker() {
        return Ok(None);
    }
    let config: Config = serde_json::from_value(value.clone())?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = stack.startup()?;
    let access = Arc::new(crate::Database::connect(config.access_options()?).await?);
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::lifecycle::AccessResource(access.clone()),
    ));
    let audit_store = access.audit_store_fixture(&config.audit).await?;
    let inventory = crate::inventory_runtime::InventoryRuntime::fixture(
        config.runtime_database.options()?,
        access.inventory(),
        rss_request_context::TenantId::parse(case_tenant())?,
        monotonic(),
        audit_store.clone(),
    )
    .await?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        InventoryFixtureResource(inventory.clone()),
    ));
    let content =
        crate::execution_assembly::open_content(&config, config.native_protector()?).await?;
    if let Some(content) = &content {
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(
            crate::execution_assembly::ContentResource(content.clone()),
        ));
    }
    let service = config
        .flow
        .open(
            inventory,
            audit_store,
            rss_request_context::TenantId::parse(case_tenant())?,
            Arc::new(crate::clock::SystemClock),
            content,
            |resource| startup.stage_resource(rss_runtime::DynManagedResource::new_box(resource)),
        )
        .await?;
    let automation = crate::automation::Automation::connect(
        crate::automation::PlanningWork::connect(
            service.planning.clone(),
            config.flow.storage.database.options()?,
        )
        .await?,
        service.assets.clone(),
        service.compliance.clone(),
    )
    .await?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::automation::Resource(automation.work.clone()),
    ));
    let notifications = crate::worker_wake::Listener::new(
        config.access_options()?,
        rss_request_context::TenantId::parse(case_tenant())?,
    );
    let signals = notifications.signals.clone();
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        notifications.clone(),
    ));
    let mut launch = startup.commit();
    launch.stage_task_with_token(notifications.registration().critical());
    launch.stage_deferred_task_with_token(automation.registration(signals.flow()).critical());
    launch.finish();
    Ok(Some(stack))
}

pub(crate) fn credential(label: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret(label))
}

pub(crate) async fn stop_worker(owner: Option<rss_runtime::ShutdownStack>) -> Result<()> {
    if let Some(owner) = owner {
        ensure!(owner.shutdown().join().await?.is_clean());
    }
    Ok(())
}

pub(crate) fn secret(label: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(case::name(label).as_bytes()).into()
}

#[derive(Default)]
#[must_use = "fixture resources must be explicitly shut down"]
pub(crate) struct Resources(pub(super) Vec<Box<rss_runtime::DynManagedResource<'static>>>);
impl Resources {
    pub(crate) fn extend(&mut self, mut other: Self) {
        self.0.append(&mut other.0);
    }
    pub(crate) fn acquire(&mut self, resource: Box<rss_runtime::DynManagedResource<'static>>) {
        self.0.push(resource);
    }
    pub(crate) fn resource(&mut self, resource: impl rss_runtime::ManagedResource + 'static) {
        self.acquire(rss_runtime::DynManagedResource::new_box(resource));
    }
    pub(crate) async fn build<T>(
        initialize: impl for<'a> FnOnce(&'a mut Self) -> futures::future::BoxFuture<'a, Result<T>>,
    ) -> Result<(Self, T)> {
        use futures::FutureExt;
        let mut resources = Self::default();
        let result = std::panic::AssertUnwindSafe(async { initialize(&mut resources).await })
            .catch_unwind()
            .await;
        match result {
            Ok(Ok(value)) => Ok((resources, value)),
            failure => resources
                .settle(failure)
                .await
                .map(|value| (Self::default(), value)),
        }
    }

    fn take_owner(&mut self) -> Result<rss_runtime::ShutdownStack> {
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(40))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut startup = owner.startup()?;
        for resource in std::mem::take(&mut self.0) {
            startup.stage_resource(resource);
        }
        startup.commit().finish();
        Ok(owner)
    }

    pub(crate) async fn finish<T>(
        self,
        operation: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        use futures::FutureExt;
        self.settle(std::panic::AssertUnwindSafe(operation).catch_unwind().await)
            .await
    }

    async fn settle<T>(mut self, result: std::thread::Result<Result<T>>) -> Result<T> {
        let cleanup = async {
            let receipt = self.take_owner()?.shutdown().join().await?;
            ensure!(
                receipt.is_clean(),
                "fixture resource shutdown incomplete: {receipt:?}"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        match result {
            Ok(Ok(value)) => {
                cleanup?;
                Ok(value)
            }
            Ok(Err(error)) => match cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => {
                    Err(error.context(format!("fixture cleanup also failed: {cleanup:#}")))
                }
            },
            Err(panic) => {
                if let Err(error) = cleanup {
                    eprintln!("fixture cleanup failed after panic: {error:#}");
                }
                std::panic::resume_unwind(panic)
            }
        }
    }
}

impl Drop for Resources {
    fn drop(&mut self) {
        if self.0.is_empty() {
            return;
        }
        // Cancellation cannot await: hand the same resources to RSS's existing drop drain.
        if let Err(error) = self.take_owner() {
            eprintln!("fixture resource drop cleanup unavailable: {error:#}");
        }
    }
}

pub(crate) struct InventoryFixtureResource(pub Arc<crate::inventory_runtime::InventoryRuntime>);
impl rss_runtime::ManagedResource for InventoryFixtureResource {
    fn name(&self) -> &str {
        "fixture-inventory"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        self.0.close_fixture().await
    }
}

#[tokio::test]
async fn fixture_resources_preserve_failures_and_close_during_initialization() {
    use futures::FutureExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Resource(Arc<AtomicUsize>, bool);
    impl rss_runtime::ManagedResource for Resource {
        fn name(&self) -> &str {
            "fixture-cleanup-probe"
        }
        async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            if self.1 {
                return Err(rss_runtime::ShutdownError::new(std::io::Error::other(
                    "injected cleanup failure",
                )));
            }
            Ok(())
        }
    }
    let closed = Arc::new(AtomicUsize::new(0));
    for cleanup_failure in [false, true] {
        for panic in [false, true] {
            let mut resources = Resources::default();
            resources.resource(Resource(closed.clone(), cleanup_failure));
            let outcome = std::panic::AssertUnwindSafe(resources.finish::<()>(async {
                assert!(!panic, "test fixture assertion failure");
                anyhow::bail!("test fixture operation failure")
            }))
            .catch_unwind()
            .await;
            if panic {
                let payload = outcome.expect_err("original panic must survive cleanup");
                assert_eq!(
                    payload.downcast_ref::<&str>(),
                    Some(&"test fixture assertion failure")
                );
            } else {
                let error = outcome
                    .expect("operation returns an error")
                    .expect_err("operation failed");
                assert!(format!("{error:#}").contains("test fixture operation failure"));
                if cleanup_failure {
                    assert!(format!("{error:#}").contains("fixture-cleanup-probe"));
                }
            }
        }
    }
    assert_eq!(closed.load(Ordering::SeqCst), 4);
    for panic in [false, true] {
        let count = closed.clone();
        let outcome = std::panic::AssertUnwindSafe(Resources::build::<()>(move |resources| {
            Box::pin(async move {
                resources.resource(Resource(count, false));
                assert!(!panic, "injected initialization panic");
                anyhow::bail!("injected initialization failure")
            })
        }))
        .catch_unwind()
        .await;
        assert!(if panic {
            outcome.is_err()
        } else {
            outcome.unwrap().is_err()
        });
    }
    assert_eq!(closed.load(Ordering::SeqCst), 6);
    let mut resources = Resources::default();
    resources.resource(Resource(closed.clone(), false));
    drop(resources);
    tokio::time::timeout(Duration::from_secs(2), async {
        while closed.load(Ordering::SeqCst) != 7 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("RSS drop drain closes the abandoned fixture");
}

pub(crate) struct PoolResource(pub sqlx::PgPool);
impl rss_runtime::ManagedResource for PoolResource {
    fn name(&self) -> &str {
        "capability-pool"
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        self.0.close().await;
        Ok(())
    }
}
pub(crate) struct SourceResource(pub Arc<rss_transactional_messaging_postgres::PgRuntime>);
impl rss_runtime::ManagedResource for SourceResource {
    fn name(&self) -> &str {
        "capability-source"
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        self.0.close().await;
        Ok(())
    }
}

/// Fixtures use the same RSS admission/drain owner as the product process.
pub(crate) struct NativeRequests {
    control: rss_runtime::AdmissionControl,
    pub(crate) gate: rss_runtime::AdmissionGate,
    owner: tokio::sync::Mutex<Option<rss_runtime::ShutdownStack>>,
}
impl NativeRequests {
    pub(crate) fn new() -> Arc<Self> {
        let mut owner = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(40)).unwrap(),
            Arc::new(crate::lifecycle::RuntimeTimer),
        )
        .unwrap();
        let (control, gate) = owner
            .startup()
            .unwrap()
            .commit()
            .finish_with_admission("native-fixture", Duration::from_secs(35));
        control.open().unwrap();
        Arc::new(Self {
            control,
            gate,
            owner: tokio::sync::Mutex::new(Some(owner)),
        })
    }
    pub(crate) fn wrap(self: &Arc<Self>, router: axum::Router) -> axum::Router {
        router
            .layer(axum::Extension(self.gate.clone()))
            .layer(axum::Extension(self.clone()))
    }
    pub(crate) async fn drain(&self) -> Result<()> {
        self.control.close();
        if let Some(owner) = self.owner.lock().await.take() {
            ensure!(owner.shutdown().join().await?.is_clean());
        }
        Ok(())
    }
}
impl rss_runtime::ManagedResource for Arc<NativeRequests> {
    fn name(&self) -> &str {
        "native-fixture"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(40)
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.drain()
            .await
            .map_err(|e| rss_runtime::ShutdownError::new(std::io::Error::other(e.to_string())))
    }
}
pub(crate) fn native_router(router: axum::Router) -> axum::Router {
    NativeRequests::new().wrap(router)
}
