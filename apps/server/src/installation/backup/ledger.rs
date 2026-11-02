use crate::installation::{Error, Result};
pub use rss_mdm_audit_integration::backup::Head;
pub async fn verify_operator(
    runtime: &serde_json::Value,
    tenants: &[String],
    database: &crate::config::Database,
) -> Result<Vec<Head>> {
    let audit: crate::config::AuditConfig =
        serde_json::from_value(runtime["audit"].clone()).map_err(|_| Error::Input)?;
    let key = match &audit {
        crate::config::AuditConfig::Plain => None,
        crate::config::AuditConfig::Ledger { key_id, .. } => Some(key_id.as_str()),
    };
    rss_mdm_audit_integration::backup::verify_operator(
        rss_mdm_install_support::StorageProfile::Mdm,
        audit.integrity().map_err(|_| Error::Input)?,
        key,
        tenants,
        &database.options().map_err(|_| Error::Input)?,
    )
    .await
}
