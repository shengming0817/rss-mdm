//! Configuration and runtime failures owned by this protocol boundary.
use serde::Serialize;
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigIssue {
    ProtocolKey,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
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
