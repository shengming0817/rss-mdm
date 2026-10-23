//! Product execution contracts, lifecycle, storage and read service.
pub mod action_admission;
pub mod action_contract;
pub mod agent_install;
pub mod configuration;
mod database;
pub mod device_control;
pub mod enrollment;
mod error;
pub mod frozen;
pub mod model;
mod permissions;
pub mod protection;
pub mod sources;
pub mod task_signing;
pub mod transaction;
pub mod unmanage;
pub mod worker_wake;
pub use error::Error;
mod diagnostic;
pub use diagnostic::{ConfigIssue, Failure};
pub use model::{AttemptPhase, Change, Create, DispatchV1, NativeTarget, Task};
use rss_mdm_authorization_service as authorization;

mod agent_collection_eligibility;
pub use agent_collection_eligibility::matches as native_collection_supported;
mod payload;
pub mod script_eligibility;
pub mod self_service;
mod target;
pub use target::Target;

pub mod source_authority;

use rss_mdm_inventory_service::{assets, collection};
use rss_mdm_registration_service::device;
pub mod actions;
mod apple;
mod apple_assets;
mod apple_push;
mod bootstrap_delivery;
mod input_storage;
mod managed_registration;
mod native_configuration;
mod native_installation;
mod native_rules;
pub use native_configuration::Diagnosis as ConfigurationDiagnosis;
pub mod health;
mod lifecycle;
pub mod native;
mod retirement;
mod windows_wake;
pub use retirement::retire_in;
/// Privileges for participation in the registration owner’s original transaction.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

mod protocol;
pub mod recovery;
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

const DOMAIN: &str = "mdm.commands.v1";
pub fn messaging_domain() -> rss_transactional_messaging::message::MessagingDomain {
    rss_transactional_messaging::message::MessagingDomain::parse(DOMAIN).expect("fixed domain")
}
pub fn recovery_scope(tenant: TenantId) -> rss_reconcile::Scope {
    rss_reconcile::Scope::new(tenant, DOMAIN).expect("fixed scope")
}

#[cfg(feature = "integration")]
type DiagnosticAssociationGate = (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>);
pub struct ExecutionService {
    pub(crate) recovery_credentials: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
    pub(crate) inputs: Arc<Inputs>,
    pub(crate) source: Arc<dyn source_authority::SourceAuthority>,
    pub(crate) sessions: Arc<authorization::session::SessionAuthority>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) agent_store: Arc<dyn channels::Agent>,
    pub(crate) apple_profiles: Arc<dyn channels::AppleProfiles>,
    pub(crate) apple_push: Arc<dyn channels::ApplePush>,
    pub(crate) apple_collections: Arc<dyn channels::AppleCollections>,
    pub(crate) apple_results: Arc<dyn channels::AppleResults>,
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
    #[cfg(feature = "integration")]
    pub(crate) installation_authorization_floor: std::sync::atomic::AtomicI64,
    #[cfg(feature = "integration")]
    pub(crate) diagnostic_commit_fault:
        Mutex<Option<rss_transactional_messaging_postgres::PgTransactionFault>>,
    #[cfg(feature = "integration")]
    pub(crate) diagnostic_association_gate: Mutex<Option<DiagnosticAssociationGate>>,
}
pub struct Dependencies {
    pub recovery_credentials: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
    pub sessions: Arc<authorization::session::SessionAuthority>,
    pub inputs: Arc<Inputs>,
    pub source: Arc<dyn source_authority::SourceAuthority>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub agent_store: Arc<dyn channels::Agent>,
    pub apple_profiles: Arc<dyn channels::AppleProfiles>,
    pub apple_push: Arc<dyn channels::ApplePush>,
    pub apple_collections: Arc<dyn channels::AppleCollections>,
    pub apple_results: Arc<dyn channels::AppleResults>,
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
            recovery_credentials: dependencies.recovery_credentials,
            #[cfg(feature = "integration")]
            installation_authorization_floor: Default::default(),
            #[cfg(feature = "integration")]
            diagnostic_commit_fault: Mutex::new(None),
            #[cfg(feature = "integration")]
            diagnostic_association_gate: Mutex::new(None),
            sessions: dependencies.sessions,
            inputs: dependencies.inputs,
            source: dependencies.source,
            protection: dependencies.protection,
            agent_store: dependencies.agent_store,
            apple_profiles: dependencies.apple_profiles,
            apple_push: dependencies.apple_push,
            apple_collections: dependencies.apple_collections,
            apple_results: dependencies.apple_results,
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
    pub fn recovery_credentials(&self) -> Option<Arc<rss_mdm_recovery_credentials::Protection>> {
        self.recovery_credentials.clone()
    }
    pub fn health(&self) -> health::Health {
        self.readiness.health()
    }
    pub(crate) fn admission(&self) -> queries::Admission {
        queries::Admission {
            software_distribution: self.inputs.software_distribution,
            source: self.source.clone(),
            software: self.inputs.software.clone(),
            agent_store: self.agent_store.clone(),
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
    /// Advance this service's installation authorization reads without editing frozen inputs.
    pub fn advance_installation_authorization_to(
        &self,
        seconds: i64,
    ) -> std::result::Result<(), Error> {
        if seconds <= 0 {
            return Err(Error::Malformed);
        }
        self.installation_authorization_floor
            .fetch_max(seconds, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    /// Pause after real file work and before the fenced association transaction.
    pub fn pause_diagnostic_association_after_file_work(
        &self,
        ready: Arc<tokio::sync::Notify>,
        resume: Arc<tokio::sync::Notify>,
    ) {
        *self
            .diagnostic_association_gate
            .lock()
            .expect("diagnostic association gate") = Some((ready, resume));
    }
    /// Inject only the association transaction after real diagnostic content publication.
    pub fn inject_diagnostic_association_fault(
        &self,
        fault: rss_transactional_messaging_postgres::PgTransactionFault,
    ) {
        *self
            .diagnostic_commit_fault
            .lock()
            .expect("diagnostic fault") = Some(fault);
    }
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

mod freeze_inputs;
pub mod input_preparation;
pub use input_preparation::authorize_policy_snapshot;

/// Exact execution storage contracts consumed by application admission.
pub const CATALOG_SQL: &str = include_str!("catalog.sql");
pub const CATALOG_JSON: &str = include_str!("catalog.json");
pub const DEPENDENCIES_SQL: &str = include_str!("dependencies.sql");
pub const DEPENDENCIES_JSON: &str = include_str!("dependencies.json");

pub mod queries;

/// Host-owned admission for operations that require a working Agent bootstrap listener.
/// Material and transaction authorities are still checked by each operation.
pub trait AgentInstallationAdmission: Send + Sync {
    fn ready_signing_revision(&self, now: i64) -> Option<u64>;
}

/// Policy publication receives immutable input preparation, never execution readers or workers.
pub struct Inputs {
    pub(crate) software_distribution: SoftwareDistribution,
    pub(crate) product_origin: String,
    pub(crate) recovery_enabled: bool,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) software: Arc<rss_mdm_software_service::preparation::Preparation>,
    pub(crate) agent_origin: String,
    pub(crate) bootstrap: Option<std::collections::BTreeMap<String, String>>,
    pub(crate) enrollment_entries: crate::enrollment::Entries,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) signing_enabled: bool,
    pub(crate) agent_installation: Arc<dyn AgentInstallationAdmission>,
}
pub struct InputDependencies {
    pub software_distribution: SoftwareDistribution,
    pub product_origin: String,
    pub recovery_enabled: bool,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub software: Arc<rss_mdm_software_service::preparation::Preparation>,
    pub agent_origin: String,
    pub bootstrap: Option<std::collections::BTreeMap<String, String>>,
    pub enrollment_entries: crate::enrollment::Entries,
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
    pub signing_enabled: bool,
    pub agent_installation: Arc<dyn AgentInstallationAdmission>,
}
impl Inputs {
    pub fn new(dependencies: InputDependencies) -> Self {
        Self {
            software_distribution: dependencies.software_distribution,
            product_origin: dependencies.product_origin,
            recovery_enabled: dependencies.recovery_enabled,
            protection: dependencies.protection,
            software: dependencies.software,
            agent_origin: dependencies.agent_origin,
            bootstrap: dependencies.bootstrap,
            enrollment_entries: dependencies.enrollment_entries,
            runtime: dependencies.runtime,
            tenant: dependencies.tenant,
            content: dependencies.content,
            signing_enabled: dependencies.signing_enabled,
            agent_installation: dependencies.agent_installation,
        }
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
            .verify_class(
                artifact,
                class,
                self.content
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .upload_budget()?
                    .operation_deadline(),
            )
            .await?)
    }
}

mod agent_preparation;
pub mod enrollment_preparation;

pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

mod collection_eligibility;

#[cfg(test)]
#[path = "../tests/native_collection_unit.rs"]
mod native_collection_unit;

impl ExecutionService {
    fn installation_authorization_time(&self, database_now: i64) -> i64 {
        #[cfg(feature = "integration")]
        {
            database_now.max(
                self.installation_authorization_floor
                    .load(std::sync::atomic::Ordering::SeqCst),
            )
        }
        #[cfg(not(feature = "integration"))]
        database_now
    }
}

pub mod recovery_credentials;

pub(crate) mod credential_tasks;

mod credential_maintenance;

/// Host-owned software admission, read once with the rest of product configuration.
#[derive(Clone, Copy, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareDistribution {
    #[serde(default)]
    pub mdm_enabled: bool,
}
impl Inputs {
    pub fn software_distribution(&self) -> SoftwareDistribution {
        self.software_distribution
    }
    pub fn admit_software_channel(
        &self,
        action: &rss_mdm_policy::Action,
    ) -> std::result::Result<(), Error> {
        if matches!(
            action,
            rss_mdm_policy::Action::Software {
                channel: rss_mdm_policy::SoftwareChannel::Mdm,
                ..
            }
        ) && !self.software_distribution.mdm_enabled
        {
            return Err(Error::MdmSoftwareDisabled);
        }
        Ok(())
    }
}

mod native_software;

pub mod device_access;
