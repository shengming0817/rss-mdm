use serde::Serialize;
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Preparation(rss_mdm_execution_service::Failure),
    PreparationConfiguration(rss_mdm_execution_service::ConfigIssue),
    PreparationContract,
    Inventory(rss_mdm_inventory_service::Failure),
    SoftwareIntegrity,
    PolicyAdmission,

    AutomationConnection,
    AutomationAdmission,
    PolicyStorage,
    AutomationStorage,

    RequestDeadline,
    #[serde(rename = "access_store")]
    Database,
    Audit,
    AuditIntegrity,
    AuditIsolation,
    AuditContract,

    AuditAdmission,
    AssetObjectLimit,
    AssetSourceLimit,
    AssetBytesLimit,
    Clock,
    Runtime,
}
