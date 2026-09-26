//! Product operation composition; RSS remains the command, messaging and recovery owner.
//! Producers keep phase-specific event identities beside the actual mutation/replay decision.
//! `transact` owns settlement; shared `Fact`/`AuditStore` own encoding and persistence.
//! Planning's optional-operation adapter additionally chooses request versus business events;
//! command producers already have explicit phase identities and retain that choice here.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
pub(crate) mod actions;
mod apple;
mod apple_push;
pub(crate) mod http;
mod lifecycle;
mod model;
pub(crate) mod native;
mod plans;
mod protocol;
pub(crate) mod recovery;
mod service;
pub(crate) mod storage;
use crate::{Error, Failure};
pub(crate) use http::routes;
pub(crate) use lifecycle::Resource;
use model::*;
use rss_device_command as dc;
use rss_device_command::Store;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgOutboxStore, PgRuntime, PgTransaction};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

const DOMAIN: &str = "mdm.commands.v2";
pub(crate) fn messaging_domain() -> rss_transactional_messaging::message::MessagingDomain {
    rss_transactional_messaging::message::MessagingDomain::parse(DOMAIN).expect("fixed domain")
}
fn recovery_scope(tenant: TenantId) -> rss_reconcile::Scope {
    rss_reconcile::Scope::new(tenant, DOMAIN).expect("fixed scope")
}

pub(crate) struct ExecutionService {
    pub(crate) signer: Option<Arc<crate::task_signing::Signer>>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) outbox: Arc<PgOutboxStore<()>>,
    pub(crate) store: rss_device_command_postgres::PgStore<()>,
    pub(crate) reconcile: rss_reconcile_postgres::PgStore,
    pub(crate) tenant: TenantId,
    pub(crate) instance: String,
    pub(crate) content: Option<Arc<crate::content::Store>>,
}
pub(crate) use crate::transaction::*;
impl ExecutionService {
    async fn required_command(
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

#[cfg(all(test, feature = "integration"))]
impl ExecutionService {
    pub(crate) fn inject_fault(
        &self,
        fault: rss_transactional_messaging_postgres::PgTransactionFault,
    ) {
        self.runtime.inject_next_transaction_fault(fault);
    }
}

#[cfg(test)]
pub(crate) mod tests;

use rss_mdm_audit_integration::RequestAudit;

pub mod error;
