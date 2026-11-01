//! Transaction resources bind to the initiating runtime; workers stay with Service.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs (one connection, one settlement owner).
use crate::control::*;

pub(crate) struct Transactions {
    pub(crate) retirement: Arc<dyn rss_mdm_registration_service::Retirement>,
    pub(crate) capacity: Arc<dyn crate::control::capacity::DeviceCapacity>,
    pub(crate) task_cleanup: Arc<dyn crate::control::task_cleanup::TaskCleanup>,
    pub(crate) configuration_cleanup:
        Arc<dyn crate::control::configuration_cleanup::ConfigurationCleanup>,
    pub(crate) lock_pins: Option<Arc<dyn crate::control::lock_pin::LockPins>>,
    pub(crate) source: Arc<crate::planning::PlanningObjects>,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) agent_store: Arc<dyn agent_facts::Store>,
    pub(crate) apple_profiles: Arc<dyn apple_facts::AppleProfiles>,
    pub(crate) windows_results: Arc<dyn crate::control::windows_results::Store>,
    pub(crate) apple_results: Arc<dyn apple_facts::AppleResults>,
    pub(crate) policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) store: rss_device_command_postgres::PgStore<()>,
    pub(crate) reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub(crate) tenant: TenantId,
    pub(crate) instance: String,
}
