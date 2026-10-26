//! Product telemetry: trusted device admission and delivery over existing RSS mechanisms.
#![forbid(unsafe_code)]
pub mod backend;
mod current;
pub mod diagnostics;
pub mod gap_query;
pub mod maintenance;
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
mod preview;
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
/// One tenant's telemetry application; the host owns its worker and adopted backend.
pub struct Service {
    tenant: TenantId,
    runtime: Arc<PgRuntime>,
    planning: Arc<rss_mdm_flow_service::planning::Planning>,
    backend: backend::Backend,
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
    limits: Limits,
    storage_budget: StorageBudget,
    running: std::sync::atomic::AtomicBool,
}
impl Service {
    /// Bind only already-admitted dependencies; never install or repair schemas here.
    pub fn new(
        tenant: TenantId,
        runtime: Arc<PgRuntime>,
        planning: Arc<rss_mdm_flow_service::planning::Planning>,
        backend: backend::Backend,
        execution: Arc<rss_mdm_execution_service::ExecutionService>,
        limits: Limits,
        storage_budget: StorageBudget,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if planning.tenant != tenant || !Arc::ptr_eq(&runtime, &planning.runtime) {
            return Err(Error::Denied);
        }
        Ok(Self {
            tenant,
            runtime,
            planning,
            backend,
            execution,
            limits,
            storage_budget,
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
            .local_tx(self.tenant, deadline(), move |tx| {
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
        let service = self.clone();
        let principal = principal.clone();
        self.runtime
            .local_tx(self.tenant, deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(admission::status_on(&service, c, &principal, batch).await)
                        })
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
    /// Idempotent close; the caller must stop the relay before closing adopted resources.
    pub async fn close(&self, deadline: rss_request_context::Deadline) -> Result<(), Error> {
        self.backend.close(deadline).await.map_err(Into::into)
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
        let service = self.clone();
        self.runtime
            .local_tx(self.tenant, deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(
                                admission::current_on(&service, c, &principal, batch, observation)
                                    .await,
                            )
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

/// The host claims one admitted installation/configuration before starting any tenant replica.
/// A mismatch never rewrites the original binding or redirects existing accepted work.
pub async fn admit_configuration(
    runtime: &Arc<PgRuntime>,
    tenant: TenantId,
    binding: [u8; 32],
) -> Result<(), Error> {
    runtime.local_tx(tenant,deadline(),move|tx|Box::pin(async move {
        tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_telemetry.storage_binding VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(tenant.to_string()).bind(binding.as_slice()).execute(&mut *c).await?;
            let stored:Vec<u8>=sqlx::query_scalar("SELECT binding FROM mdm_telemetry.storage_binding WHERE tenant_id=$1::uuid").bind(tenant.to_string()).fetch_one(c).await?;
            Ok(stored==binding)
        })).await
    })).await.fold(|same|if same {Ok(())}else{Err(Error::Conflict)},|_|Err(Error::Storage),|_|Err(Error::Storage),|_|Err(Error::Unknown),|_|Err(Error::Unknown),|_|Err(Error::Storage))
}
