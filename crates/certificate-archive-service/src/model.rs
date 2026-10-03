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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
    pub category: String,
    pub labels: Vec<String>,
    pub usages: Vec<String>,
    pub owner: String,
    pub notes: String,
}
impl Metadata {
    pub fn validate(&self) -> Result<(), Error> {
        if self.name.trim().is_empty()
            || self.name.len() > 256
            || self.category.is_empty()
            || self.category.len() > 128
            || self.owner.len() > 256
            || self.notes.len() > 4096
            || self.labels.len() > 32
            || self.usages.len() > 32
            || self.labels.iter().any(|s| s.is_empty() || s.len() > 128)
            || self.usages.iter().any(|s| s.is_empty() || s.len() > 512)
            || serde_json::to_vec(self)
                .map_err(|_| Error::Malformed)?
                .len()
                > 16384
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportFile {
    pub name: String,
    pub format: Format,
    pub data: Zeroizing<String>,
    pub password: Option<Zeroizing<String>>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Import {
    pub entry_id: Uuid,
    pub expected_revision: i64,
    pub metadata: Metadata,
    pub files: Vec<ImportFile>,
    /// Attach to an existing request version only after checking its public key.
    pub request_version: Option<VersionRef>,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionRef {
    pub entry_id: Uuid,
    pub version: i64,
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    Rsa2048,
    Rsa3072,
    P256,
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Ca,
    Https,
    Csr,
    ApnsCsr,
    ScepTemplate,
}
#[derive(Serialize, Deserialize)]
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
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordInput {
    pub password: Zeroizing<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangePassword {
    pub old_password: Zeroizing<String>,
    pub new_password: Zeroizing<String>,
}
#[derive(Clone, Serialize, Deserialize)]
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    pub revision: i64,
    pub value: Settings,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManageEntry {
    pub expected_revision: i64,
    pub retired: bool,
    pub recommended_version: Option<i64>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeSettings {
    pub expected_revision: i64,
    pub value: Settings,
}
#[derive(Clone, Serialize, Deserialize)]
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterialFacts {
    pub name: String,
    pub format: Format,
    pub certificates: Vec<CertificateFacts>,
    pub public_keys: Vec<String>,
    pub contains_private_key: bool,
}
#[derive(Clone, Serialize, Deserialize)]
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
    pub source: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: Uuid,
    pub revision: i64,
    pub retired: bool,
    pub recommended_version: Option<i64>,
    pub latest: Version,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub tenant_id: String,
    pub items: Vec<Entry>,
    pub next_after: Option<Uuid>,
    pub as_of: i64,
    pub reminder_days: u32,
    pub alerts: Alerts,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alerts {
    pub expired: i64,
    pub expiring: i64,
    pub not_yet_valid: i64,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeMetadata {
    pub expected_revision: i64,
    pub metadata: Metadata,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultState {
    pub initialized: bool,
    pub generation: i64,
    pub unlocked_until: Option<i64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub operation_id: Uuid,
    pub action: String,
    pub entry_id: Option<Uuid>,
    pub version: Option<i64>,
    pub revision: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportFile {
    pub name: String,
    pub data: Zeroizing<String>,
}
#[derive(Serialize, Deserialize)]
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
