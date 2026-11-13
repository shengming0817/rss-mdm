//! Registration-owned native bootstrap delivery and cleanup, settled by the initiating transaction.
mod action_admission;
mod apple;
pub mod apple_business;
pub mod apple_facts;
pub mod authority;
pub mod bootstrap;
mod database;
mod diagnostic;
pub mod error;
mod input_storage;
pub mod missing;
pub mod model;
mod protection;
mod protocol;
mod service;
pub mod storage;
pub mod transaction;
pub mod windows_business;
pub mod windows_results;
mod windows_wake;
pub mod worker_wake;
use crate::device;
pub use diagnostic::{ConfigIssue, Failure};
pub use error::Error;
pub use model::{AttemptPhase, Create, DispatchFailure, DispatchV1, NativeTarget, Task};
use rss_device_command as dc;
use rss_device_command::Store as _;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service as authorization;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgOutboxStore, PgRuntime, PgTransaction};
pub use service::{AcceptedReceipt, target};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
pub use transaction::*;
use uuid::Uuid;
pub fn messaging_domain() -> rss_transactional_messaging::message::MessagingDomain {
    rss_transactional_messaging::message::MessagingDomain::parse("mdm.registration.installation.v1")
        .expect("fixed Registration domain")
}
pub fn recovery_scope(tenant: TenantId) -> rss_reconcile::Scope {
    rss_reconcile::Scope::new(tenant, "mdm.registration.installation.v1")
        .expect("fixed Registration scope")
}
/// Frozen installation coordinates supplied by Software after current authorization.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    pub id: Uuid,
    pub policy: Uuid,
    pub version: Uuid,
    pub device: rss_mdm_agent_wire::DeviceId,
    pub platform: rss_mdm_policy::Platform,
    pub source: rss_mdm_inventory::ReportSource,
    pub release: Uuid,
    pub deadline: i64,
    pub input_version: String,
    pub download_origin: String,
    pub origin: rss_mdm_audit_integration::activity::ActivityOrigin,
}
pub trait Installations: Send + Sync {
    fn dispatch_ready_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: TenantId,
        id: Uuid,
    ) -> crate::agent::Pending<'a, bool>;
    /// Only a known rejected/cancelled/expired parent releases the cleanup duty.
    fn delivery_ended_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: TenantId,
        id: Uuid,
    ) -> crate::agent::Pending<'a, bool>;

    fn authorized_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: TenantId,
        id: Uuid,
    ) -> crate::agent::Pending<'a, Installation>;
}
pub struct Materials {
    pub installations: Arc<dyn Installations>,
    pub endpoints: Option<std::collections::BTreeMap<String, String>>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub windows_results: Arc<dyn windows_results::Store>,
    pub apple_profiles: Arc<dyn apple_facts::AppleProfiles>,
    pub apple_results: Arc<dyn apple_facts::AppleResults>,
    pub instance: String,
}
pub struct Transactions {
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) store: rss_device_command_postgres::PgStore<()>,
    pub(crate) reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub(crate) materials: Arc<Materials>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) windows_results: Arc<dyn windows_results::Store>,
    pub(crate) apple_profiles: Arc<dyn apple_facts::AppleProfiles>,
    pub(crate) apple_results: Arc<dyn apple_facts::AppleResults>,
    pub(crate) instance: String,
}
pub struct Service {
    pub(crate) transactions: Transactions,
    pub(crate) outbox: Arc<PgOutboxStore<()>>,
    pub(crate) reconcile: rss_reconcile_postgres::PgStore,
    pub(crate) worker_budget: Arc<tokio::sync::Semaphore>,
    pub(crate) worker_concurrency: usize,
    pub(crate) readiness: rss_mdm_recovery_observation::Readiness,
}
impl Service {
    pub fn new(
        transactions: Transactions,
        outbox: Arc<PgOutboxStore<()>>,
        reconcile: rss_reconcile_postgres::PgStore,
        worker_budget: Arc<tokio::sync::Semaphore>,
        worker_concurrency: usize,
    ) -> Self {
        let readiness = rss_mdm_recovery_observation::Readiness::new(
            recovery_scope(transactions.tenant),
            true,
            false,
        );
        Self {
            transactions,
            outbox,
            reconcile,
            worker_budget,
            worker_concurrency,
            readiness,
        }
    }
    pub fn recovery_store(
        &self,
    ) -> impl rss_reconcile::DurableStore<Claim = rss_reconcile_postgres::PgClaim> + '_ {
        health::ObservedStore(self)
    }
    pub fn health(&self) -> rss_mdm_recovery_observation::Health {
        self.readiness.health()
    }
}
impl Transactions {
    pub async fn bind(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        materials: Arc<Materials>,
    ) -> std::result::Result<Self, Error> {
        let caller = runtime.clone();
        let audit = audit_store.clone();
        let store = runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    audit.bind_in(tx).await.map_err(PgError::from)?;
                    tx.with_connection(|c| {
                        Box::pin(async move {
                            let valid: bool =
                                sqlx::query_scalar(include_str!("bootstrap-admission.sql"))
                                    .fetch_one(c)
                                    .await?;
                            if !valid {
                                return Err(sqlx::Error::Protocol(
                                    "Registration bootstrap participant admission".into(),
                                ));
                            }
                            Ok(())
                        })
                    })
                    .await?;
                    storage::bind_command_in(
                        caller,
                        tx,
                        rss_device_command_postgres::CommandClock::Postgres,
                    )
                    .await
                    .map(|(_, store)| store)
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::CommandInvariant)),
                |_| Err(Error::Unavailable(Failure::CommandInvariant)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable(Failure::CommandInvariant)),
            )?;
        let reconcile_messaging =
            rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), tenant, deadline())
                .await
                .map_err(|_| Error::Unavailable(Failure::CommandInvariant))?;
        Ok(Self {
            runtime,
            tenant,
            audit_store,
            store,
            reconcile_messaging,
            protection: materials.protection.clone(),
            windows_results: materials.windows_results.clone(),
            apple_profiles: materials.apple_profiles.clone(),
            apple_results: materials.apple_results.clone(),
            instance: materials.instance.clone(),
            materials,
        })
    }
    pub fn validate_in(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }
    pub(crate) async fn required_command(
        &self,
        tx: &mut PgTransaction<'_>,
        op: &storage::Operation,
    ) -> Result<dc::Command> {
        self.store
            .load(tx, op.scope, &op.command_id()?)
            .await?
            .ok_or_else(|| Error::Unavailable(Failure::CommandInvariant).into())
    }
}

pub mod timeline;
mod wake;

pub mod health;
pub mod recovery;

pub use protocol::settle_one as settle_windows_receipt_in;

pub mod retirement;

pub mod queries;
