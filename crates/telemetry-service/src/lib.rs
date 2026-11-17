//! Product telemetry: trusted device admission and delivery over existing RSS mechanisms.
#![forbid(unsafe_code)]
pub mod backend;
mod contract_schema;
mod current;
pub mod diagnostics;
pub mod gap_query;
pub mod maintenance;
pub mod selection;
/// Exact shared access privileges; retained maintenance reads never enable telemetry writes.
pub const DIAGNOSTIC_ACCESS_CONTRACT: &str = include_str!("diagnostic-access.json");
pub mod query;
mod samples;
/// Closed failures never retain sampled values, credentials or provider diagnostics.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum Error {
    /// No diagnostic report belongs to this current registration.
    #[error("telemetry not found")]
    NotFound,
    /// The bound Agent does not implement this configuration.
    #[error("telemetry unsupported")]
    Unsupported,
    /// Invalid profile or batch.
    #[error("invalid telemetry input")]
    Invalid,
    /// Identity/content or version conflict.
    #[error("telemetry conflict")]
    Conflict,
    /// Current authority does not permit the operation.
    #[error("telemetry denied")]
    Denied,
    /// Explicit resource capacity was exceeded.
    #[error("telemetry capacity exceeded")]
    Capacity,
    /// A provider could not confirm the effect.
    #[error("telemetry outcome unknown")]
    Unknown,
    /// Required durable state is unavailable or invalid.
    #[error("telemetry unavailable")]
    Storage,
}
impl From<rss_timeseries::Error> for Error {
    fn from(e: rss_timeseries::Error) -> Self {
        match e {
            rss_timeseries::Error::Conflict
            | rss_timeseries::Error::IncompatibleDefinition
            | rss_timeseries::Error::Retired
            | rss_timeseries::Error::HistoryExpired => Self::Conflict,
            rss_timeseries::Error::BudgetExceeded => Self::Capacity,
            rss_timeseries::Error::InvalidInput
            | rss_timeseries::Error::NumericRange
            | rss_timeseries::Error::InvalidCursor => Self::Invalid,
            rss_timeseries::Error::Unsupported => Self::Unsupported,
            rss_timeseries::Error::Unauthorized => Self::Denied,
            rss_timeseries::Error::Deadline
            | rss_timeseries::Error::Unavailable
            | rss_timeseries::Error::Invariant => Self::Storage,
        }
    }
}
impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::Invalid
    }
}

mod admission;
mod configuration;
pub mod configurations;
mod definitions;
mod delivery;
mod gaps;
pub mod preview;
mod retention;
use rss_mdm_agent_wire::runtime::{TelemetryReceipt, TelemetryUpload};
use rss_mdm_registration_service::device::DevicePrincipal;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime};
use std::sync::{Arc, Mutex};
/// Product-owned schema installed by the privileged App migrator.
pub const SCHEMA_SQL: &str = include_str!("schema.sql");
/// Host ceilings, shared by all Agent ingress replicas through PostgreSQL.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Limits {
    pub request_bytes: u32,
    /// Outstanding batches per registration.
    pub pending_batches: u32,
    /// Tenant-wide new batch rate, shared across all devices and replicas.
    pub batches_per_minute: u32,
    /// Tenant-wide measured transport/decompression bytes, shared across replicas.
    pub bytes_per_minute: u32,
}
impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        if !(1..=4 * 1024 * 1024).contains(&self.request_bytes)
            || !(1..=4096).contains(&self.pending_batches)
            || !(1..=1000000).contains(&self.batches_per_minute)
            || self.bytes_per_minute < self.request_bytes
        {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
}
/// Provider limits already admitted by the host; applied before durable product intake.
#[derive(Clone, Copy)]
pub struct StorageBudget {
    pub points: std::num::NonZeroU32,
    pub series: std::num::NonZeroU32,
    pub bytes: std::num::NonZeroU32,
}
/// Only the Policy capabilities and audit resource actually consumed by telemetry.
pub struct PolicyDependencies {
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub agent_facts: Arc<dyn rss_mdm_script_service::agent_facts::Store>,
    pub read_pool: sqlx::PgPool,
    pub clock: Arc<dyn rss_request_context::Clock>,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub policies: Arc<rss_mdm_policy_service::telemetry::Reader>,
    pub objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
}
/// Shared telemetry application; installation owns physical backends and shutdown.
pub struct Service {
    agent_facts: Arc<dyn rss_mdm_script_service::agent_facts::Store>,
    read_pool: sqlx::PgPool,
    clock: Arc<dyn rss_request_context::Clock>,

    runtime: Arc<PgRuntime>,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    policies: Arc<rss_mdm_policy_service::telemetry::Reader>,
    objects: Arc<dyn rss_mdm_inventory_service::objects::ObjectReader>,
    storage: rss_transactional_messaging::fence::StorageIdentity,
    resources: std::collections::BTreeMap<[u8; 32], backend::Resource>,
    default_resource: [u8; 32],
    protection: Arc<rss_mdm_native_protection::Protector>,
    readers: selection::Readers,
    signing: Arc<rss_mdm_task_trust::Signing>,
    limits: Limits,
    maintenance_policy: maintenance::Policy,
    running: std::sync::atomic::AtomicBool,
}
impl Service {
    /// True when the host actually opened every configured installation.
    pub fn admits_installations(&self, count: usize) -> bool {
        self.resources.len() == count
    }
    pub fn new(
        probe: rss_transactional_messaging::fence::ExecutionBinding,
        runtime: Arc<PgRuntime>,
        dependencies: PolicyDependencies,
        resources: Vec<backend::Resource>,
        signing: Arc<rss_mdm_task_trust::Signing>,
        limits: Limits,
        maintenance_policy: maintenance::Policy,
    ) -> Result<Self, Error> {
        let default_resource = resources
            .first()
            .filter(|r| r.tenant.is_none() && r.backend.is_some())
            .ok_or(Error::Invalid)?
            .binding;
        let count = resources.len();
        let resources = resources
            .into_iter()
            .map(|r| (r.binding, r))
            .collect::<std::collections::BTreeMap<_, _>>();
        if resources.len() != count {
            return Err(Error::Invalid);
        }
        limits.validate()?;
        maintenance_policy.validate()?;
        if !dependencies.policies.is_bound_to(&runtime) {
            return Err(Error::Denied);
        }
        Ok(Self {
            agent_facts: dependencies.agent_facts,
            read_pool: dependencies.read_pool,
            clock: dependencies.clock,

            runtime,
            audit_store: dependencies.audit_store,
            policies: dependencies.policies,
            objects: dependencies.objects,
            storage: probe.storage(),
            resources,
            default_resource,
            protection: dependencies.protection,
            readers: Default::default(),
            signing,
            limits,
            maintenance_policy,
            running: std::sync::atomic::AtomicBool::new(false),
        })
    }
    /// Maximum decompressed complete body before parsing any uploaded JSON.
    pub fn request_bytes(&self) -> usize {
        self.limits.request_bytes as usize
    }
    /// Atomically authenticate current source, fix identity and enqueue the original input.
    /// `wire_bytes` is measured by the trusted ingress as max(encoded bytes, decoded bytes).
    pub async fn receive(
        self: &Arc<Self>,
        principal: &DevicePrincipal,
        input: &TelemetryUpload,
        wire_bytes: usize,
    ) -> Result<TelemetryReceipt, Error> {
        let rejection = Arc::new(Mutex::new(None));
        let failure = rejection.clone();
        let service = self.clone();
        let principal = principal.clone();
        let input = input.clone();
        self.runtime
            .local_tx(principal.binding(), deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            admission::receive_on(&service, c, &principal, &input, wire_bytes)
                                .await
                                .map_err(|error| {
                                    *failure.lock().expect("telemetry rejection") = Some(error);
                                    sqlx::Error::Protocol("telemetry input rejected".into())
                                })
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Storage),
                |_| {
                    Err(rejection
                        .lock()
                        .expect("telemetry rejection")
                        .unwrap_or(Error::Storage))
                },
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
    /// Read the original receipt only after current device credential validation.
    pub async fn status(
        self: &Arc<Self>,
        principal: &DevicePrincipal,
        batch: uuid::Uuid,
    ) -> Result<TelemetryReceipt, Error> {
        let principal = principal.clone();
        self.runtime
            .local_tx(principal.binding(), deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(
                            async move { Ok(admission::status_on(c, &principal, batch).await) },
                        )
                    })
                    .await
                })
            })
            .await
            .fold(
                |value| value,
                |_| Err(Error::Storage),
                |_| Err(Error::Storage),
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
}
fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        std::time::Duration::from_secs(10),
    )
}
fn storage_error(_: impl std::fmt::Debug) -> PgError {
    sqlx::Error::Protocol("telemetry storage unavailable".into()).into()
}

/// Runtime privilege and RLS admission.
pub const ADMISSION_SQL: &str = include_str!("admission.sql");

#[cfg(test)]
mod tests;

/// Current projection evidence is interpreted only by the Inventory runtime.
pub enum CurrentObservation {
    NotRequested,
    Pending,
    Admitted(Box<rss_mdm_inventory_service::collection::store::Run>),
}
impl Service {
    /// Read one observation only after verifying original batch membership and live device credentials.
    pub async fn current_observation(
        self: &Arc<Self>,
        principal: &DevicePrincipal,
        batch: uuid::Uuid,
        observation: uuid::Uuid,
    ) -> Result<CurrentObservation, Error> {
        let principal = principal.clone();

        self.runtime
            .local_tx(principal.binding(), deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(admission::current_on(c, &principal, batch, observation).await)
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                |v| v,
                |_| Err(Error::Storage),
                |_| Err(Error::Storage),
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
}

async fn verify_owner(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    rss_mdm_inventory_service::verify_authority(rss_mdm_install_support::StorageProfile::Mdm, c)
        .await?;
    rss_mdm_inventory_postgres::verify_asset_history(c).await?;
    rss_mdm_inventory_postgres::verify_collections(c)
        .await
        .map_err(|_| sqlx::Error::Protocol("collection producer admission rejected".into()))?;
    if !sqlx::query_scalar::<_, bool>(ADMISSION_SQL)
        .fetch_one(c)
        .await?
    {
        return Err(sqlx::Error::Protocol(
            "owner storage admission rejected".into(),
        ));
    }
    Ok(())
}

pub mod profile_validation;

/// Two relay deliveries and one sequential maintenance loop can use control storage.
pub const RELAY_CONCURRENCY: u32 = 2;
/// Relay consumers plus the sequential maintenance loop.
pub const CONTROL_WORKERS: u32 = RELAY_CONCURRENCY + 1;

mod snapshot;

impl Service {
    /// Initialize only domain selection. Existing explicit selections are retained exactly.
    pub async fn admit_default(
        self: &Arc<Self>,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        budget: rss_transactional_messaging::policy::OperationDeadline,
    ) -> Result<(), Error> {
        let cutoff =
            rss_request_context::Deadline::from_timeout(&backend::SystemClock, budget.timeout())
                .map_err(|_| Error::Storage)?;
        let default = self.default_resource;
        self.runtime.local_tx(execution,budget,move|tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move {
                verify_owner(c).await?;
                sqlx::query("INSERT INTO mdm_telemetry.storage_binding(tenant_id,binding,expected_epoch) VALUES($1::uuid,$2,$3) ON CONFLICT DO NOTHING").bind(&tenant).bind(default.as_slice()).bind(execution.epoch().get()).execute(c).await?;
                Ok(())
            })).await
        })).await.fold(Ok,|_|Err(Error::Storage),|_|Err(Error::Storage),|_|Err(Error::Unknown),|_|Err(Error::Unknown),|_|Err(Error::Storage))?;
        self.backend(execution, cutoff).await.map(|_| ())
    }

    async fn backend_on(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: TenantId,
    ) -> Result<backend::Selected, Error> {
        let cutoff = rss_request_context::Deadline::from_timeout(
            &backend::SystemClock,
            std::time::Duration::from_secs(6),
        )
        .map_err(|_| Error::Storage)?;
        self.backend_until(c, tenant, cutoff, false).await
    }
    async fn work_backend_on(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: TenantId,
    ) -> Result<backend::Selected, Error> {
        let cutoff = rss_request_context::Deadline::from_timeout(
            &backend::SystemClock,
            std::time::Duration::from_secs(6),
        )
        .map_err(|_| Error::Storage)?;
        self.backend_until(c, tenant, cutoff, true).await
    }
    async fn backend_until(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: TenantId,
        cutoff: rss_request_context::Deadline,
        draining_worker: bool,
    ) -> Result<backend::Selected, Error> {
        selection::lock_read(c, tenant).await?;
        let row = selection::load_row(c, tenant, true, draining_worker)
            .await?
            .ok_or(Error::Storage)?;
        let resource = self
            .resources
            .get(row.binding.as_slice())
            .ok_or(Error::Storage)?;
        if row
            .resource_id
            .is_some_and(|id| id != resource.installation)
        {
            return Err(Error::Storage);
        }
        if resource.tenant.is_some_and(|fixed| fixed != tenant) {
            return Err(Error::Denied);
        }
        let backend = match resource.backend.as_deref().ok_or(Error::Storage)? {
            backend::Backend::Postgres(pg) => backend::Access::Postgres(pg.clone()),
            backend::Backend::ClickHouse(owner) => backend::Access::ClickHouse(
                self.readers
                    .access(owner, &self.protection, tenant, &row, cutoff)
                    .await?,
            ),
        };
        Ok(backend::Selected {
            backend,
            budget: resource.budget,
        })
    }

    async fn backend(
        self: &Arc<Self>,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        cutoff: rss_request_context::Deadline,
    ) -> Result<backend::Selected, Error> {
        let service = self.clone();
        self.runtime
            .local_tx(
                execution,
                rss_transactional_messaging::policy::OperationDeadline::from_cutoff(
                    cutoff,
                    &backend::SystemClock,
                ),
                move |tx| {
                    Box::pin(async move {
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                Ok(service
                                    .backend_until(c, execution.tenant(), cutoff, false)
                                    .await)
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                |v| v,
                |_| Err(Error::Storage),
                |_| Err(Error::Storage),
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
}
