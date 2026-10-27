use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const MAX_MATERIAL_BYTES: usize = 1024 * 1024;
pub const UNLOCK_SECONDS: u64 = 900;

/// Closed diagnoses contain no uploaded bytes, provider errors or passwords.
#[derive(Clone, Debug, thiserror::Error, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    #[error("invalid archive input")]
    Malformed,
    #[error("archive permission denied")]
    Forbidden,
    #[error("authentication expired")]
    Unauthorized,
    #[error("archive is locked")]
    Locked,
    #[error("archive password rejected")]
    Password,
    #[error("material cannot be parsed")]
    Material,
    #[error("certificate, request or key does not match")]
    KeyMismatch,
    #[error("archive object not found")]
    NotFound,
    #[error("archive operation conflicts")]
    Conflict,
    #[error("archive integrity check failed")]
    Integrity,
    #[error("archive dependency unavailable")]
    Storage,
    #[error("archive work limit reached")]
    Limited,
    #[error("archive commit outcome unknown")]
    CommitUnknown,
    #[error("archive rollback unconfirmed")]
    RollbackFailed,
    #[error("audit operation failed")]
    Audit,
}
impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(_: rss_mdm_audit_integration::Error) -> Self {
        Self::Audit
    }
}
impl From<rss_audit_postgres::Error> for Error {
    fn from(_: rss_audit_postgres::Error) -> Self {
        Self::Audit
    }
}
impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        match e {
            rss_mdm_authorization_service::Error::Unauthorized => Self::Unauthorized,
            rss_mdm_authorization_service::Error::Forbidden => Self::Forbidden,
            _ => Self::Storage,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Metadata(pub serde_json::Map<String, serde_json::Value>);
impl Metadata {
    pub fn validate(&self) -> Result<(), Error> {
        if !crate::presentation::valid(&self.0, 16384) {
            return Err(Error::Malformed);
        }
        for (key, limit, required) in [
            ("name", 256, true),
            ("category", 128, true),
            ("owner", 256, false),
            ("notes", 4096, false),
        ] {
            let text = self
                .0
                .get(key)
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::Malformed)?;
            if text.len() > limit || (required && text.trim().is_empty()) {
                return Err(Error::Malformed);
            }
        }
        for (key, limit) in [("labels", 128), ("usages", 512)] {
            let values = self
                .0
                .get(key)
                .and_then(serde_json::Value::as_array)
                .ok_or(Error::Malformed)?;
            if values.len() > 32
                || values
                    .iter()
                    .any(|v| v.as_str().is_none_or(|s| s.is_empty() || s.len() > limit))
            {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
}
#[derive(schemars::JsonSchema, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Certificate,
    Chain,
    Csr,
    Pkcs12,
    PrivateKey,
    Opaque,
}
/// Password fields are deliberately neither Debug nor persisted with materials.
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportFile {
    pub name: String,
    pub format: Format,
    #[schemars(with = "String")]
    pub data: Zeroizing<String>,
    #[schemars(with = "Option<String>")]
    pub password: Option<Zeroizing<String>>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Import {
    pub entry_id: Uuid,
    pub expected_revision: i64,
    pub metadata: Metadata,
    pub files: Vec<ImportFile>,
    /// Attach to an existing request version only after checking its public key.
    pub request_version: Option<VersionRef>,
}
#[derive(schemars::JsonSchema, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionRef {
    pub entry_id: Uuid,
    pub version: i64,
}
#[derive(schemars::JsonSchema, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    Rsa2048,
    Rsa3072,
    P256,
}
#[derive(schemars::JsonSchema, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Ca,
    Https,
    Csr,
    ApnsCsr,
    ScepTemplate,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Generate {
    pub entry_id: Uuid,
    pub expected_revision: i64,
    pub metadata: Metadata,
    pub profile: Profile,
    pub algorithm: Algorithm,
    pub common_name: String,
    pub organization: String,
    pub sans: Vec<String>,
    pub days: u32,
    pub issuer: Option<VersionRef>,
    pub scep_url: Option<String>,
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordInput {
    #[schemars(with = "String")]
    pub password: Zeroizing<String>,
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangePassword {
    #[schemars(with = "String")]
    pub old_password: Zeroizing<String>,
    #[schemars(with = "String")]
    pub new_password: Zeroizing<String>,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub reminder_days: u32,
    pub categories: Vec<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            reminder_days: 30,
            categories: vec![
                "https".into(),
                "mdm-ca".into(),
                "agent-ca".into(),
                "apns".into(),
                "profile-signing".into(),
                "code-signing".into(),
                "trust".into(),
                "custom".into(),
            ],
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<(), Error> {
        if self.reminder_days > 3650
            || self.categories.len() > 128
            || self
                .categories
                .iter()
                .any(|v| v.is_empty() || v.len() > 128)
        {
            Err(Error::Malformed)
        } else {
            Ok(())
        }
    }
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    pub revision: i64,
    pub value: Settings,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManageEntry {
    pub expected_revision: i64,
    pub retired: bool,
    pub recommended_version: Option<i64>,
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeSettings {
    pub expected_revision: i64,
    pub value: Settings,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateFacts {
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    pub serial: String,
    pub fingerprint: String,
    pub algorithm: String,
    pub not_before: i64,
    pub not_after: i64,
    pub public_key: String,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterialFacts {
    pub name: String,
    pub format: Format,
    pub certificates: Vec<CertificateFacts>,
    pub public_keys: Vec<String>,
    pub contains_private_key: bool,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    pub entry_id: Uuid,
    pub version: i64,
    pub actor: String,
    pub instance: String,
    pub operation_id: Uuid,
    pub created_at: i64,
    pub metadata: Metadata,
    pub facts: Vec<MaterialFacts>,
    pub request_version: Option<VersionRef>,
    pub source: String,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: Uuid,
    pub revision: i64,
    pub retired: bool,
    pub recommended_version: Option<i64>,
    pub latest: Version,
}
#[derive(schemars::JsonSchema, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub tenant_id: String,
    pub items: Vec<rss_mdm_query::directory::Projection<Entry>>,
    pub next_cursor: Option<String>,
    pub as_of: i64,
    pub reminder_days: u32,
    pub alerts: Alerts,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alerts {
    pub expired: i64,
    pub expiring: i64,
    pub not_yet_valid: i64,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeMetadata {
    pub expected_revision: i64,
    pub metadata: Metadata,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultState {
    pub initialized: bool,
    pub generation: i64,
    pub unlocked_until: Option<i64>,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub operation_id: Uuid,
    pub action: String,
    pub entry_id: Option<Uuid>,
    pub version: Option<i64>,
    pub revision: i64,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportFile {
    pub name: String,
    #[schemars(with = "String")]
    pub data: Zeroizing<String>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Export {
    pub entry_id: Uuid,
    pub version: i64,
    pub files: Vec<ExportFile>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Bundle {
    pub files: Vec<ExportFile>,
}

impl schemars::JsonSchema for Metadata {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "CertificateMetadata".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type":"object","required":["name","category","owner","notes","labels","usages"],
            "properties":{
                "name":{"type":"string","maxLength":256},"category":{"type":"string","maxLength":128},
                "owner":{"type":"string","maxLength":256},"notes":{"type":"string","maxLength":4096},
                "labels":{"type":"array","maxItems":32,"items":{"type":"string","minLength":1,"maxLength":128}},
                "usages":{"type":"array","maxItems":32,"items":{"type":"string","minLength":1,"maxLength":512}}
            },
            "additionalProperties":{"x-rss-extension":"Ordinary certificate metadata retained by Metadata::validate and its 16384-byte budget"}
        })
    }
}
