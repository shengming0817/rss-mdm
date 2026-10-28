#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Storage,
    Admission,
    Capacity,
    Clock,
    Runtime,
    RequestDeadline,
    Database,
    Audit,
    AuditIntegrity,
    AuditIsolation,
    AuditContract,
    AuditAdmission,
    Inventory(rss_mdm_inventory_service::Failure),
}
