//! Configuration and runtime failures owned by this protocol boundary.
use serde::Serialize;
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigIssue {
    AppleApns,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Execution(rss_mdm_execution_service::Failure),
    ExecutionConfiguration(rss_mdm_execution_service::ConfigIssue),
    Inventory(rss_mdm_inventory_service::Failure),
    Clock,
    Runtime,
    Capacity,
    AppleInvariant,
    ApplePush,
    AppleAde,
    AppleStorage,
    Audit,
    AuditAdmission,
    AuditContract,
    AuditBackpressure,
    AuditReserveExhausted,
    AuditIntegrity,
    AuditIsolation,
    Certificate,
    Database,
    Protocol,
    RequestDeadline,
}
