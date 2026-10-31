use serde::Serialize;
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Preparation,
    PreparationConfiguration,
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
    NativeProtection,
    ContentStorage,
    ContentInvariant,
    ContentMetadata,
    ContentDeadline,
    ContentCleanup,
    NativeInputIntegrity,
    CommandInvariant,
    Capacity,
    Runtime,
}
