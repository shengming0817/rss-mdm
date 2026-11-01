//! Fixed Device controls and accepted unmanage work: authority, delivery, evidence and recovery.
pub mod action_admission;
pub mod action_contract;
mod database;
pub mod device_control;
mod error;
pub mod frozen;
pub mod model;
mod permissions;
pub mod protection;
pub mod sources;
pub mod transaction;
pub mod unmanage;
pub mod worker_wake;
pub use error::Error;
mod diagnostic;
pub use diagnostic::{ConfigIssue, Failure};
pub use model::{
    AttemptPhase, Change, Create, DispatchFailure, DispatchV1, NativeTarget, Task, TaskSummary,
};
use rss_mdm_authorization_service as authorization;

mod target;
pub use target::Target;

use rss_mdm_inventory_service::collection;
use rss_mdm_registration_service::device;
pub mod actions;
mod apple;
pub mod health;
mod input_storage;
mod lifecycle;
mod retirement;
mod windows_wake;
pub use retirement::retire_in;
/// Privileges for participation in the registration owner’s original transaction.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

pub mod authorization_decision;
mod protocol;
pub use protocol::settle_one as settle_windows_receipt_in;
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

pub struct Service {
    pub(crate) worker_budget: Arc<tokio::sync::Semaphore>,
    pub(crate) worker_concurrency: usize,
    pub(crate) outbox: Arc<PgOutboxStore<()>>,
    pub(crate) reconcile: rss_reconcile_postgres::PgStore,
    pub(crate) readiness: health::Readiness,

    pub(crate) transactions: transactions::Transactions,
}
pub mod capacity;
pub struct Dependencies {
    pub retirement: Arc<dyn rss_mdm_registration_service::Retirement>,
    pub worker_budget: Arc<tokio::sync::Semaphore>,
    pub capacity: Arc<dyn capacity::DeviceCapacity>,
    pub task_cleanup: Arc<dyn crate::control::task_cleanup::TaskCleanup>,
    pub configuration_cleanup: Arc<dyn crate::control::configuration_cleanup::ConfigurationCleanup>,
    pub worker_concurrency: usize,
    pub lock_pins: Option<Arc<dyn crate::control::lock_pin::LockPins>>,
    pub source: Arc<crate::planning::PlanningObjects>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub agent_store: Arc<dyn agent_facts::Store>,
    pub apple_profiles: Arc<dyn apple_facts::AppleProfiles>,
    pub windows_results: Arc<dyn crate::control::windows_results::Store>,
    pub apple_results: Arc<dyn apple_facts::AppleResults>,
    pub policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub runtime: Arc<PgRuntime>,
    pub outbox: Arc<PgOutboxStore<()>>,
    pub store: rss_device_command_postgres::PgStore<()>,
    pub reconcile: rss_reconcile_postgres::PgStore,
    pub reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub tenant: TenantId,
    pub instance: String,
}
impl Service {
    /// The production durable store, including owner health and settlement semantics.
    pub fn recovery_store(
        &self,
    ) -> impl rss_reconcile::DurableStore<Claim = rss_reconcile_postgres::PgClaim> + '_ {
        health::ObservedStore(self)
    }

    pub fn new(dependencies: Dependencies) -> Self {
        Self {
            transactions: transactions::Transactions {
                retirement: dependencies.retirement,
                capacity: dependencies.capacity,
                lock_pins: dependencies.lock_pins,

                source: dependencies.source,
                protection: dependencies.protection,
                agent_store: dependencies.agent_store,
                apple_profiles: dependencies.apple_profiles,
                task_cleanup: dependencies.task_cleanup,
                configuration_cleanup: dependencies.configuration_cleanup,
                windows_results: dependencies.windows_results,
                apple_results: dependencies.apple_results,
                policy_reader: dependencies.policy_reader,
                audit_store: dependencies.audit_store,
                runtime: dependencies.runtime,
                store: dependencies.store,
                reconcile_messaging: dependencies.reconcile_messaging,
                tenant: dependencies.tenant,
                instance: dependencies.instance,
            },
            worker_concurrency: dependencies.worker_concurrency,
            worker_budget: dependencies.worker_budget,
            readiness: Default::default(),

            outbox: dependencies.outbox,
            reconcile: dependencies.reconcile,
        }
    }

    pub fn health(&self) -> health::Health {
        self.readiness.health()
    }
}

pub use transaction::*;

use rss_mdm_audit_integration::RequestAudit;

pub mod missing;

pub mod authority;

pub mod agent_facts;
pub mod apple_business;
pub mod apple_facts;
pub mod windows_business;
pub mod windows_results;

pub use service::{AcceptedReceipt, ChangedReceipt, target};

pub mod directory;
pub mod timeline;

mod error_projection;

pub mod wake;

pub mod input_preparation;
pub use input_preparation::{action_permission, authorize_action};
mod transactions;

pub mod queries;

pub const INSTALL_SQL: &str = include_str!("../../schema/control-install.sql");
pub const RELATIONS_SQL: &str = concat!(
    include_str!("../../schema/control-relations.sql"),
    "\n",
    include_str!("../../schema/control-command-runtime.sql")
);

pub mod credential_inputs;

mod storage_authority;
pub use storage_authority::verify_authority;

pub mod source_changes;
/// Execution-owned input checkpoint and privileges.
pub const SOURCE_CHANGES_SQL: &str = include_str!("../../schema/control-source-changes.sql");

impl crate::control::transactions::Transactions {
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

/// Native registration reads frozen Execution authority through this narrow profile.
pub mod configuration_cleanup;

pub mod task_cleanup;

pub mod lock_pin;
