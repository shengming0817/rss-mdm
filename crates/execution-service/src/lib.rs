//! Product execution contracts, lifecycle, storage and read service.
pub mod action_admission;
pub mod action_contract;
pub mod agent_install;
pub mod configuration;
mod database;
pub mod enrollment;
mod error;
pub mod frozen;
pub mod model;
mod permissions;
pub mod protection;
pub mod remote_operations;
pub mod sources;
pub mod task_signing;
pub mod transaction;
pub mod worker_wake;
pub use error::Error;
mod diagnostic;
pub use diagnostic::{ConfigIssue, Failure};
pub use model::{AttemptPhase, Change, Create, DispatchV3, NativeTarget, Task};
use rss_mdm_authorization_service as authorization;

mod payload;
mod target;
pub use target::Target;

pub mod source_authority;

use rss_mdm_inventory_service::{assets, collection};
use rss_mdm_registration_service::device;
pub mod actions;
mod apple;
mod apple_push;
mod input_storage;
mod managed_registration;
mod native_configuration;
mod native_installation;
pub use native_configuration::Diagnosis as ConfigurationDiagnosis;
pub mod health;
mod lifecycle;
pub mod native;

mod protocol;
pub mod recovery;
mod remote_execution;
mod service;
pub mod storage;
pub use lifecycle::Resource;

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
    pub source: Arc<dyn source_authority::SourceAuthority>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub readiness: health::Readiness,
    pub software: Arc<rss_mdm_software_service::preparation::Preparation>,
    pub agent_installation: crate::agent_install::Config,
    pub enrollment_entries: crate::enrollment::Entries,
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
pub use transaction::*;
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

pub mod missing;

pub mod authority;

pub mod channels;

pub use service::target;

pub mod directory;
pub mod timeline;

mod error_projection;

pub mod wake;

pub mod freeze_inputs;
pub mod input_preparation;
pub use input_preparation::authorize_policy_snapshot;

/// Exact execution storage contracts consumed by application admission.
pub const CATALOG_SQL: &str = include_str!("catalog.sql");
pub const CATALOG_JSON: &str = include_str!("catalog.json");
pub const DEPENDENCIES_SQL: &str = include_str!("dependencies.sql");
pub const DEPENDENCIES_JSON: &str = include_str!("dependencies.json");

pub mod queries;

/// Policy publication receives immutable input preparation, never execution readers or workers.
pub struct Inputs {
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub software: Arc<rss_mdm_software_service::preparation::Preparation>,
    pub agent_installation: crate::agent_install::Config,
    pub enrollment_entries: crate::enrollment::Entries,
    pub(crate) runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
    pub signing_enabled: bool,
}
impl ExecutionService {
    pub fn inputs(&self) -> Arc<Inputs> {
        Arc::new(Inputs {
            protection: self.protection.clone(),
            software: self.software.clone(),
            agent_installation: self.agent_installation.clone(),
            enrollment_entries: self.enrollment_entries.clone(),
            runtime: self.runtime.clone(),
            tenant: self.tenant,
            content: self.content.clone(),
            signing_enabled: self.signer.is_some(),
        })
    }
}

mod agent_preparation;
pub mod enrollment_preparation;

pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");
