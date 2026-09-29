//! Configuration and runtime failures owned by this protocol boundary.
use serde::Serialize;
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigIssue {
    AppleApns,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    AppleInvariant,
    ApplePush,
    AppleStorage,
    Audit,
    AuditAdmission,
    AuditContract,
    AuditIntegrity,
    AuditIsolation,
    Certificate,
    Database,
    Protocol,
    RequestDeadline,
}
