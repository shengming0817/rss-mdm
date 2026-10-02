//! Configuration and runtime failures owned by this protocol boundary.
use serde::Serialize;
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigIssue {
    ProtocolKey,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    ContentCleanup,
    ContentDeadline,
    ContentMetadata,
    ContentInvariant,
    ContentStorage,
    ContentConfiguration,
    Execution(rss_mdm_execution_service::Failure),
    ExecutionConfiguration(rss_mdm_execution_service::ConfigIssue),
    Inventory(rss_mdm_inventory_service::Failure),
    Runtime,
    Audit,
    AuditAdmission,
    AuditContract,
    AuditIntegrity,
    AuditIsolation,
    Capacity,
    Certificate,
    Clock,
    Database,
    Protocol,
    RequestDeadline,
}
