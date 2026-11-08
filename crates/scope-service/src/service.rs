use crate::transaction::*;
use crate::*;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgRuntime;
use std::sync::Arc;

pub struct Scopes {
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub(crate) read_pool: sqlx::PgPool,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub(crate) store: rss_mdm_scope_postgres::ScopeBinding,
    pub(crate) clock: Arc<dyn clock::Clock>,
    pub(crate) cursor_key: ring::hmac::Key,
    pub(crate) objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    pub(crate) groups: Arc<rss_mdm_group_postgres::GroupSources>,
    pub(crate) projection: crate::projection::ScopeProjection,
    pub(crate) dependents: Arc<dyn sources::ScopeDependents>,
    pub(crate) input_state: std::sync::atomic::AtomicU8,
    pub(crate) runner_health: std::sync::Mutex<crate::health::RunnerObservation>,
    pub(crate) task: std::sync::OnceLock<rss_runtime::TaskStatus>,
}
pub struct Dependencies {
    pub read_pool: sqlx::PgPool,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    pub groups: Arc<rss_mdm_group_postgres::GroupSources>,
    pub dependents: Arc<dyn sources::ScopeDependents>,
    pub cursor_key: Vec<u8>,
}
impl Scopes {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.store.profile()
    }
    pub async fn new(
        profile: rss_mdm_install_support::StorageProfile,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn clock::Clock>,
        dependencies: Dependencies,
    ) -> std::result::Result<Self, Error> {
        Self::bind(profile, runtime, tenant, clock, dependencies, false).await
    }
    /// Bind a configuration participant to the caller's existing Policy runtime.
    pub async fn bind_policy(
        profile: rss_mdm_install_support::StorageProfile,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn clock::Clock>,
        dependencies: Dependencies,
    ) -> std::result::Result<Self, Error> {
        Self::bind(profile, runtime, tenant, clock, dependencies, true).await
    }
    async fn bind(
        profile: rss_mdm_install_support::StorageProfile,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        clock: Arc<dyn clock::Clock>,
        dependencies: Dependencies,
        editing: bool,
    ) -> std::result::Result<Self, Error> {
        let store = rss_mdm_scope_postgres::ScopeBinding::new(profile, runtime.clone(), tenant);
        let s = Self {
            projection: crate::projection::ScopeProjection::new(profile, runtime.clone(), tenant),
            runtime,
            tenant,
            clock,
            store,
            read_pool: dependencies.read_pool,
            audit_store: dependencies.audit_store,
            reconcile_messaging: dependencies.reconcile_messaging,
            objects: dependencies.objects,
            groups: dependencies.groups,
            dependents: dependencies.dependents,
            cursor_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &dependencies.cursor_key),
            task: Default::default(),
            input_state: Default::default(),
            runner_health: Default::default(),
        };
        s.runtime
            .local_tx_with_context(tenant, deadline(), (&s, editing), |(s, editing), tx| {
                Box::pin(async move {
                    s.audit_store.bind_in(tx).await.map_err(PgError::from)?;
                    (if *editing {
                        s.store.admit_configuration_in(tx).await
                    } else {
                        s.store.admit_in(tx).await
                    })
                    .map_err(|e| match e {
                        rss_mdm_scope_postgres::BindingError::Storage(e) => e,
                        _ => sqlx::Error::Protocol("Scope admission".into()).into(),
                    })
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::Admission)),
                |_| Err(Error::Unavailable(Failure::Admission)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable(Failure::Admission)),
            )?;
        Ok(s)
    }
    pub fn task_state(&self) -> Option<rss_runtime::TaskState> {
        self.task.get().map(rss_runtime::TaskStatus::current)
    }
}
