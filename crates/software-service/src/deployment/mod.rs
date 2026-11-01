//! Software deployment identity, authority and device effects.
pub mod frozen;
pub mod identity;
pub mod native;

/// Host-owned software admission, read once with the rest of product configuration.
#[derive(Clone, Copy, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareDistribution {
    #[serde(default)]
    pub mdm_enabled: bool,
}

pub mod action_admission;
pub mod action_contract;
pub mod actions;
pub mod agent_facts;
pub mod agent_install;
pub mod apple;
pub mod apple_assets;
pub mod apple_business;
pub mod apple_facts;
pub mod authority;
pub mod authorization_decision;
pub mod capacity;
pub mod database;
pub mod diagnostic;
pub mod directory;
pub mod error;
pub mod error_projection;
pub mod health;
pub mod input_storage;
pub mod inventory;
pub mod managed_registration;
pub mod missing;
pub mod model;
pub mod native_installation;
pub mod native_software;
pub mod policy_events;
pub mod protection;
pub mod protocol;
pub mod queries;
pub mod recovery;
pub mod scope;
pub mod self_service;
pub mod service;
pub mod source_changes;
pub mod sources;
pub mod storage;
pub mod storage_authority;
pub mod target;
pub mod timeline;
pub mod transaction;
pub mod transactions;
pub mod wake;
pub mod windows_business;
pub mod windows_results;
pub mod windows_wake;
pub mod worker_wake;

pub use diagnostic::{ConfigIssue, Failure};
pub use error::Error;
pub use model::{
    AttemptPhase, Change, Create, DispatchFailure, DispatchV1, NativeTarget, Task, TaskSummary,
};
pub use protocol::settle_one as settle_windows_receipt_in;
use rss_device_command as dc;
use rss_device_command::Store;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service as authorization;
use rss_mdm_registration_service::device;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgOutboxStore, PgRuntime, PgTransaction};
pub use service::{AcceptedReceipt, ChangedReceipt, target};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
pub use storage_authority::verify_authority;
pub use target::Target;
pub use transaction::*;
pub use transactions::{Materials, Transactions};
use uuid::Uuid;
const DOMAIN: &str = "mdm.software.deployment.v1";
pub fn messaging_domain() -> rss_transactional_messaging::message::MessagingDomain {
    rss_transactional_messaging::message::MessagingDomain::parse(DOMAIN)
        .expect("fixed Software domain")
}
pub fn recovery_scope(tenant: TenantId) -> rss_reconcile::Scope {
    rss_reconcile::Scope::new(tenant, DOMAIN).expect("fixed Software scope")
}
pub struct SoftwareService {
    pub(crate) worker_budget: Arc<tokio::sync::Semaphore>,
    pub(crate) worker_concurrency: usize,
    pub(crate) sessions: Arc<authorization::session::SessionAuthority>,
    pub(crate) outbox: Arc<PgOutboxStore<()>>,
    pub(crate) reconcile: rss_reconcile_postgres::PgStore,
    pub(crate) readiness: health::Readiness,
    pub(crate) transactions: Arc<Transactions>,
}
impl SoftwareService {
    pub fn new(
        transactions: Arc<Transactions>,
        sessions: Arc<authorization::session::SessionAuthority>,
        outbox: Arc<PgOutboxStore<()>>,
        reconcile: rss_reconcile_postgres::PgStore,
        worker_budget: Arc<tokio::sync::Semaphore>,
        worker_concurrency: usize,
    ) -> Self {
        Self {
            transactions,
            sessions,
            outbox,
            reconcile,
            worker_budget,
            worker_concurrency,
            readiness: Default::default(),
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
pub struct Inputs {
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) tenant: TenantId,
    pub(crate) materials: Arc<InputMaterials>,
}
pub struct InputMaterials {
    pub software_distribution: SoftwareDistribution,
    pub product_origin: String,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub software: Arc<crate::preparation::Preparation>,
    pub bootstrap_configured: bool,
    pub signing_enabled: bool,
    pub agent_installation: Arc<dyn crate::installation::inputs::Admission>,
}
impl Inputs {
    pub fn bind(runtime: Arc<PgRuntime>, tenant: TenantId, materials: Arc<InputMaterials>) -> Self {
        Self {
            runtime,
            tenant,
            materials,
        }
    }
    fn validate_in(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }
    pub fn software_distribution(&self) -> SoftwareDistribution {
        self.materials.software_distribution
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
        ) && !self.materials.software_distribution.mdm_enabled
        {
            return Err(Error::MdmSoftwareDisabled);
        }
        Ok(())
    }
}
impl Transactions {
    pub(crate) fn admission(&self) -> queries::Admission {
        queries::Admission {
            software_distribution: self.inputs.materials.software_distribution,
            source: self.source.clone(),
            inventory: self.inventory.clone(),
            lifecycle: self.lifecycle.clone(),
            software: self.inputs.materials.software.clone(),
            agent_store: self.agent_store.clone(),
        }
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
    pub(crate) fn installation_authorization_time(&self, database_now: i64) -> i64 {
        database_now
    }
}
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
pub const NATIVE_SOURCE_ACCESS_CONTRACT: &str = include_str!("native-source-access-contract.json");
pub const NATIVE_SOURCE_ADMISSION_SQL: &str = include_str!("native-source-admission.sql");

pub mod retirement;

mod agent_preparation;
pub mod input_preparation;
pub use input_preparation::{action_permission, authorize_action};

pub const INSTALL_SQL: &str = include_str!("../../schema/deployment/install.sql");
pub const RELATIONS_SQL: &str = include_str!("../../schema/deployment/relations.sql");
pub const SOURCE_CHANGES_SQL: &str = include_str!("../../schema/deployment/source-changes.sql");
