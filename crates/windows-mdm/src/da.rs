//! Application-owned ADMX policy ingestion for the opaque DA envelope.
//! ref: Microsoft win32-and-centennial-app-policy-configuration.
use crate::{CodecError, Result};
/// Fixed Policy CSP installation URI.
pub const INSTALL_URI: &str =
    "./Device/Vendor/MSFT/Policy/ConfigOperations/ADMXInstall/RSSDeviceAccess/Policy/Configuration";
/// Fixed machine policy URI. Deletion removes delivery, never releases a managed lock by itself.
pub const POLICY_URI: &str =
    "./Device/Vendor/MSFT/Policy/Config/RSSDeviceAccess~Policy~DeviceAccess/Configuration";
/// Single registry carrier consumed by DA.
pub const REGISTRY_KEY: &str = "Software\\Policies\\RSS\\DeviceAccess";
/// Fixed registry value name.
pub const VALUE: &str = "SignedConfiguration";
/// ADMX definition; no Windows system policy is replaced.
pub const ADMX: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions revision="1.0" schemaVersion="1.0"><policyNamespaces><target prefix="rssda" namespace="RSS.DeviceAccess"/><using prefix="windows" namespace="Microsoft.Policies.Windows"/></policyNamespaces><resources minRequiredRevision="1.0"/><categories><category name="DeviceAccess" displayName="$(string.Category)"/></categories><policies><policy name="Configuration" class="Machine" displayName="$(string.Configuration)" explainText="$(string.Explanation)" presentation="$(presentation.Configuration)" key="Software\Policies\RSS\DeviceAccess"><parentCategory ref="DeviceAccess"/><supportedOn ref="windows:SUPPORTED_Windows10"/><elements><text id="SignedConfiguration" valueName="SignedConfiguration" required="true" maxLength="131072"/></elements></policy></policies></policyDefinitions>"#;
/// Language resources for the same fixed definition.
pub const ADML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<policyDefinitionResources revision="1.0" schemaVersion="1.0"><displayName>RSS Device Access</displayName><description>Managed signed configuration</description><resources><stringTable><string id="Category">RSS Device Access</string><string id="Configuration">Signed configuration</string><string id="Explanation">Preserve the signed envelope unchanged. Delivery does not establish verified management or device application.</string></stringTable><presentationTable><presentation id="Configuration"><textBox refId="SignedConfiguration"><label>Signed configuration</label></textBox></presentation></presentationTable></resources></policyDefinitionResources>"#;
/// Template values are transport material, never proof of installation.
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Templates {
    /// ADMX installation URI.
    pub install_uri: &'static str,
    /// Original ADMX XML, supplied as a string through Policy CSP.
    pub admx: &'static str,
    /// ADML language resource.
    pub adml: &'static str,
    /// Policy configuration URI.
    pub policy_uri: &'static str,
    /// Escaped native policy value for Add/Replace with format chr.
    pub policy_value: String,
    /// Exact opaque registry string for comparison or GPO application.
    pub registry_value: String,
}
/// Produce a single native string value without decoding/reencoding the inner payload.
pub fn templates(signed: &rss_mdm_agent_wire::da::SignedConfiguration) -> Result<Templates> {
    signed.decode().map_err(|_| CodecError::InvalidValue)?;
    let value = serde_json::to_string(signed).map_err(|_| CodecError::InvalidValue)?;
    let escaped = quick_xml::escape::escape(&value);
    Ok(Templates {
        install_uri: INSTALL_URI,
        admx: ADMX,
        adml: ADML,
        policy_uri: POLICY_URI,
        policy_value: format!("<enabled/><data id=\"{VALUE}\" value=\"{escaped}\"/>"),
        registry_value: value,
    })
}
/// Extract the one registry carrier. The consumer subsequently verifies installed DA trust.
pub fn extract(value: &str) -> Result<rss_mdm_agent_wire::da::SignedConfiguration> {
    if value.len() > 131072 {
        return Err(CodecError::LimitExceeded);
    }
    let signed: rss_mdm_agent_wire::da::SignedConfiguration =
        serde_json::from_str(value).map_err(|_| CodecError::InvalidValue)?;
    signed.decode().map_err(|_| CodecError::InvalidValue)?;
    Ok(signed)
}
