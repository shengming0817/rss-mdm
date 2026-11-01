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
pub mod missing;
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
pub fn messaging_domain() -> rss_transactional_messaging::message::MessagingDomain {
    rss_transactional_messaging::message::MessagingDomain::parse("mdm.recovery.native.v1")
        .expect("fixed Recovery domain")
}
pub fn recovery_scope(tenant: TenantId) -> rss_reconcile::Scope {
    rss_reconcile::Scope::new(tenant, "mdm.recovery.native.v1").expect("fixed Recovery scope")
}
pub struct Materials {
    pub credentials: Arc<crate::Protection>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub apple_profiles: Arc<dyn apple_facts::AppleProfiles>,
    pub apple_results: Arc<dyn apple_facts::AppleResults>,
}
pub struct Transactions {
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) store: rss_device_command_postgres::PgStore<()>,
    pub(crate) reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub(crate) materials: Arc<Materials>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) apple_profiles: Arc<dyn apple_facts::AppleProfiles>,
    pub(crate) apple_results: Arc<dyn apple_facts::AppleResults>,
}
pub struct Service {
    pub(crate) transactions: Transactions,
    pub(crate) outbox: Arc<PgOutboxStore<()>>,
    pub(crate) reconcile: rss_reconcile_postgres::PgStore,
    pub(crate) worker_budget: Arc<tokio::sync::Semaphore>,
    pub(crate) worker_concurrency: usize,
    pub(crate) readiness: health::Readiness,
}
impl Service {
    pub fn new(
        transactions: Transactions,
        outbox: Arc<PgOutboxStore<()>>,
        reconcile: rss_reconcile_postgres::PgStore,
        worker_budget: Arc<tokio::sync::Semaphore>,
        worker_concurrency: usize,
    ) -> Self {
        let readiness = health::Readiness::default();
        readiness.inputs(Ok(()));
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
    pub fn health(&self) -> health::Health {
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
            apple_profiles: materials.apple_profiles.clone(),
            apple_results: materials.apple_results.clone(),
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

pub mod retirement;

pub mod inputs;
pub mod operations;
pub mod queries;
