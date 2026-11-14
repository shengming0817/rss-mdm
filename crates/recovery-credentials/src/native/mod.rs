//! Recovery-owned native credential delivery and cleanup, settled by the initiating transaction.
mod action_admission;
mod apple;
pub mod apple_business;
pub mod apple_facts;
pub mod authority;
mod database;
mod diagnostic;
pub mod error;
mod input_storage;
pub mod model;
mod protection;
mod protocol;
mod service;
pub mod storage;
pub mod transaction;
pub mod worker_wake;
pub use diagnostic::{ConfigIssue, Failure};
pub use error::Error;
pub use model::{AttemptPhase, Create, DispatchFailure, DispatchV1, NativeTarget, Task};
use rss_device_command as dc;
use rss_device_command::Store as _;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service as authorization;
use rss_mdm_registration_service::device;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgOutboxStore, PgRuntime, PgTransaction};
pub use service::{AcceptedReceipt, target};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
pub use transaction::*;
use uuid::Uuid;
const DOMAIN: &str = "mdm.recovery.native.v1";
pub fn messaging_domain() -> rss_transactional_messaging::message::MessagingDomain {
    rss_transactional_messaging::message::MessagingDomain::parse("mdm.recovery.native.v1")
        .expect("fixed Recovery domain")
}
pub fn recovery_scope(tenant: TenantId) -> rss_reconcile::Scope {
    rss_reconcile::Scope::new(tenant, "mdm.recovery.native.v1").expect("fixed Recovery scope")
}
pub struct Materials {
    pub supersede_batch: rss_device_command::BatchLimit,
    pub credentials: Arc<crate::Protection>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub apple_profiles: Arc<dyn apple_facts::AppleProfiles>,
    pub apple_results: Arc<dyn apple_facts::AppleResults>,
}
pub struct Transactions {
    pub(crate) runtime: Arc<PgRuntime>,

    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) store: rss_device_command_postgres::PgStore<()>,
    pub(crate) reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub(crate) materials: Arc<Materials>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) apple_profiles: Arc<dyn apple_facts::AppleProfiles>,
    pub(crate) apple_results: Arc<dyn apple_facts::AppleResults>,
}
pub struct Service {
    pub(crate) read_pool: sqlx::PgPool,
    pub(crate) storage: rss_transactional_messaging::fence::StorageIdentity,
    pub(crate) relay_after: Mutex<Option<(Uuid, i64)>>,
    pub(crate) transactions: Transactions,
    pub(crate) outbox: Arc<PgOutboxStore<()>>,
    pub(crate) reconcile: rss_reconcile_postgres::PgStore,
    pub(crate) worker_budget: Arc<tokio::sync::Semaphore>,
    pub(crate) recovery_batch: rss_device_command::BatchLimit,
    pub(crate) readiness: rss_mdm_recovery_observation::Readiness,
}
impl Service {
    pub fn new(
        read_pool: sqlx::PgPool,
        storage: rss_transactional_messaging::fence::StorageIdentity,
        transactions: Transactions,
        outbox: Arc<PgOutboxStore<()>>,
        reconcile: rss_reconcile_postgres::PgStore,
        worker_budget: Arc<tokio::sync::Semaphore>,
        recovery_batch: rss_device_command::BatchLimit,
    ) -> Self {
        let readiness = rss_mdm_recovery_observation::Readiness::new(DOMAIN, true, false);
        Self {
            read_pool,
            storage,
            relay_after: Mutex::new(None),
            transactions,
            outbox,
            reconcile,
            worker_budget,
            recovery_batch,
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
        probe: rss_transactional_messaging::fence::ExecutionBinding,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
        materials: Arc<Materials>,
    ) -> std::result::Result<Self, Error> {
        let supersede_batch = materials.supersede_batch;
        let caller = runtime.clone();
        let audit = audit_store.clone();
        let store = runtime
            .local_tx(probe, deadline(), move |tx| {
                Box::pin(async move {
                    audit.bind_in(tx).await.map_err(PgError::from)?;
                    tx.with_connection(|c| {
                        Box::pin(async move {
                            let valid: bool = sqlx::query_scalar(include_str!("admission.sql"))
                                .fetch_one(c)
                                .await?;
                            if !valid {
                                return Err(sqlx::Error::Protocol(
                                    "Recovery native participant admission".into(),
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
                        supersede_batch,
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
        let reconcile_messaging = Box::pin(rss_reconcile_postgres::PgMessagingStore::new(
            runtime.clone(),
            probe,
            deadline(),
        ))
        .await
        .map_err(|_| Error::Unavailable(Failure::CommandInvariant))?;
        Ok(Self {
            runtime,

            audit_store,
            store,
            reconcile_messaging,
            protection: materials.protection.clone(),
            apple_profiles: materials.apple_profiles.clone(),
            apple_results: materials.apple_results.clone(),
            materials,
        })
    }
    pub fn validate_in(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;

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

pub mod retirement;

pub mod inputs;
pub mod operations;
pub mod queries;

/// Narrow access-role work discovery exported by this owner.
pub const WORK_ACCESS_CONTRACT: &str = r#"{"tables":[],"functions":[{"name":"mdm_recovery_tasks.native_work_scopes","search_path":"search_path=pg_catalog, pg_temp"},{"name":"mdm_recovery_tasks.native_work_epoch","search_path":"search_path=pg_catalog, pg_temp"},{"name":"mdm_recovery_tasks.native_work_relay_scopes","search_path":"search_path=pg_catalog, pg_temp"}],"external_relations":[],"verified_schemas":[]}"#;
