//! Product operation composition; RSS remains the command, messaging and recovery owner.
//! Producers keep phase-specific event identities beside the actual mutation/replay decision.
//! `transact` owns settlement; shared `Fact`/`AuditStore` own encoding and persistence.
//! Planning's optional-operation adapter additionally chooses request versus business events;
//! command producers already have explicit phase identities and retain that choice here.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
pub mod actions;
mod agent_install;
mod apple;
mod apple_push;
mod configuration;
mod input_storage;
mod managed_registration;
pub use configuration::Diagnosis as ConfigurationDiagnosis;
pub mod health;
mod lifecycle;
pub mod model;
pub mod native;
mod permissions;
mod protocol;
pub mod recovery;
mod remote;
mod service;
pub mod storage;
use crate::{Error, Failure};
pub use lifecycle::Resource;
pub use model::*;
use rss_device_command as dc;
use rss_device_command::Store;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgOutboxStore, PgRuntime, PgTransaction};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

const DOMAIN: &str = "mdm.commands.v3";
pub fn messaging_domain() -> rss_transactional_messaging::message::MessagingDomain {
    rss_transactional_messaging::message::MessagingDomain::parse(DOMAIN).expect("fixed domain")
}
pub fn recovery_scope(tenant: TenantId) -> rss_reconcile::Scope {
    rss_reconcile::Scope::new(tenant, DOMAIN).expect("fixed scope")
}

pub struct ExecutionService {
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub readiness: health::Readiness,
    pub exports: std::collections::BTreeMap<
        String,
        Arc<rss_mdm_software_service::publication::PublicationService>,
    >,
    pub agent_installation: crate::planning::policies::agent_install::Config,
    pub enrollment_entries: crate::planning::policies::enrollment::Entries,
    pub agent_store: Arc<dyn channels::Agent>,
    pub apple_store: Arc<dyn channels::AppleStore>,
    pub policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub signer: Option<Arc<crate::task_signing::Signer>>,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub runtime: Arc<PgRuntime>,
    pub outbox: Arc<PgOutboxStore<()>>,
    pub store: rss_device_command_postgres::PgStore<()>,
    pub reconcile: rss_reconcile_postgres::PgStore,
    pub tenant: TenantId,
    pub instance: String,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
}
pub use crate::transaction::*;
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

#[cfg(feature = "integration")]
impl ExecutionService {
    pub fn inject_fault(&self, fault: rss_transactional_messaging_postgres::PgTransactionFault) {
        self.runtime.inject_next_transaction_fault(fault);
    }
}

use rss_mdm_audit_integration::RequestAudit;

pub mod error;

pub mod authority;

pub mod channels;

pub use service::target;

pub mod directory;
pub mod timeline;
