use serde::Serialize;
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigIssue {
    IdentityConfiguration,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    NativeProtection,
    NativeInputIntegrity,
    CommandStorage,
    CommandInvariant,
    RequestDeadline,
    Database,
    Audit,
    AuditIntegrity,
    AuditIsolation,
    AuditContract,
    AuditAdmission,
    Capacity,
    Protocol,
}
