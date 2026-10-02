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
mod native_rules;
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
    pub(crate) inputs: Arc<Inputs>,
    pub(crate) source: Arc<dyn source_authority::SourceAuthority>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) agent_store: Arc<dyn channels::Agent>,
    pub(crate) apple_store: Arc<dyn channels::AppleStore>,
    pub(crate) policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub(crate) signer: Option<Arc<crate::task_signing::Signer>>,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) outbox: Arc<PgOutboxStore<()>>,
    pub(crate) store: rss_device_command_postgres::PgStore<()>,
    pub(crate) reconcile: rss_reconcile_postgres::PgStore,
    pub(crate) tenant: TenantId,
    pub(crate) instance: String,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) readiness: health::Readiness,
}
pub struct Dependencies {
    pub inputs: Arc<Inputs>,
    pub source: Arc<dyn source_authority::SourceAuthority>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
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
impl ExecutionService {
    pub fn new(dependencies: Dependencies) -> Self {
        Self {
            readiness: Default::default(),
            inputs: dependencies.inputs,
            source: dependencies.source,
            protection: dependencies.protection,
            agent_store: dependencies.agent_store,
            apple_store: dependencies.apple_store,
            policy_reader: dependencies.policy_reader,
            signer: dependencies.signer,
            audit_store: dependencies.audit_store,
            runtime: dependencies.runtime,
            outbox: dependencies.outbox,
            store: dependencies.store,
            reconcile: dependencies.reconcile,
            tenant: dependencies.tenant,
            instance: dependencies.instance,
            content: dependencies.content,
        }
    }
    pub fn health(&self) -> health::Health {
        self.readiness.health()
    }
    pub(crate) fn admission(&self) -> queries::Admission {
        queries::Admission {
            source: self.source.clone(),
            software: self.inputs.software.clone(),
            agent_store: self.agent_store.clone(),
            agent_installation: self.inputs.agent_installation.clone(),
        }
    }
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
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) software: Arc<rss_mdm_software_service::preparation::Preparation>,
    pub(crate) agent_installation: crate::agent_install::Config,
    pub(crate) enrollment_entries: crate::enrollment::Entries,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) signing_enabled: bool,
}
pub struct InputDependencies {
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub software: Arc<rss_mdm_software_service::preparation::Preparation>,
    pub agent_installation: crate::agent_install::Config,
    pub enrollment_entries: crate::enrollment::Entries,
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
    pub signing_enabled: bool,
}
impl Inputs {
    pub fn new(dependencies: InputDependencies) -> Self {
        Self {
            protection: dependencies.protection,
            software: dependencies.software,
            agent_installation: dependencies.agent_installation,
            enrollment_entries: dependencies.enrollment_entries,
            runtime: dependencies.runtime,
            tenant: dependencies.tenant,
            content: dependencies.content,
            signing_enabled: dependencies.signing_enabled,
        }
    }
    pub fn freeze_enrollment(
        &self,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        snapshot: &rss_mdm_authorization_service::Snapshot,
        action: &rss_mdm_policy::Action,
    ) -> std::result::Result<enrollment::FrozenEnrollment, Error> {
        if !self.signing_enabled {
            return Err(Error::Unsupported);
        }
        enrollment_preparation::freeze(proof, snapshot, action, &self.enrollment_entries)
    }
    pub fn authorize_native(
        &self,
        frozen: &mut frozen::Frozen,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        snapshot: &rss_mdm_authorization_service::Snapshot,
        device: Option<&std::collections::BTreeSet<String>>,
        owner: Option<configuration::Owner>,
    ) -> std::result::Result<(), Error> {
        frozen.authorize_native(
            proof,
            snapshot,
            device,
            &self.protection,
            self.tenant,
            owner,
        )
    }
    pub async fn verify_artifact(
        &self,
        artifact: &rss_mdm_resource::Artifact,
        class: rss_mdm_content_service::StorageClass,
    ) -> std::result::Result<rss_mdm_content_service::Verified, Error> {
        Ok(self
            .content
            .as_ref()
            .ok_or(Error::Unsupported)?
            .verify_class(artifact, class)
            .await?)
    }
}

mod agent_preparation;
pub mod enrollment_preparation;

pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");
