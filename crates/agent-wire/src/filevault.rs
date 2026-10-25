//! Device-authenticated read-only CMS escrow, independent from execution tasks and PSSO.
//! ref: Apple DeviceManagement/FDERecoveryKeyEscrow (FileVaultPRK.dat CMS carrier).
use crate::runtime::WireError;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
/// Decoded native CMS budget; the JSON envelope has a separate transport budget.
pub const CMS_BYTES: usize = 65_536;
/// Accommodates base64 plus bounded coordinates.
pub const REQUEST_BYTES: usize = 98_304;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Current device-scoped collection authorization and public recipient metadata.
pub struct Configuration {
    /// Whether the server explicitly authorizes collection.
    pub enabled: bool,
    /// Current authorization revision; zero means no configured custody.
    pub revision: i64,
    /// Recovery-owner identity, independent from transport registration.
    pub custody_id: Option<Uuid>,
    /// Recovery-owner generation, fenced independently from device enrollment.
    pub custody_epoch: i64,
    /// Exact configured escrow certificate fingerprint.
    pub recipient_id: Option<String>,
    /// Public certificate for the independently deployed escrow profile; never a private key.
    pub recipient_certificate: Option<String>,
    /// Current material revision for optimistic concurrency.
    pub material_revision: i64,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// One frozen native CMS submission; it carries no plaintext recovery key.
pub struct Upload {
    /// Stable idempotency identity retained before sending.
    pub operation_id: Uuid,
    /// Recovery-owner identity, independent from transport registration.
    pub custody_id: Uuid,
    /// Recovery-owner generation, fenced independently from device enrollment.
    pub custody_epoch: i64,
    /// Exact authorization revision selected before reading the file.
    pub configuration_revision: i64,
    /// Material revision observed before this submission.
    pub expected_revision: i64,
    /// Exact configured escrow certificate fingerprint.
    pub recipient_id: String,
    /// Lowercase SHA-256 of the decoded original CMS bytes.
    pub cms_digest: String,
    /// Original Apple CMS bytes, base64 encoded; never log the carrier.
    pub cms: String,
}
impl Upload {
    /// Validate bounded coordinates and the exact CMS content digest before use.
    pub fn decode(&self) -> Result<Vec<u8>, WireError> {
        if self.operation_id.is_nil()
            || self.custody_id.is_nil()
            || self.custody_epoch < 1
            || self.configuration_revision < 1
            || self.expected_revision < 0
            || self.recipient_id.len() != 64
            || !self.recipient_id.bytes().all(|b| b.is_ascii_hexdigit())
            || self.cms.len() > CMS_BYTES.div_ceil(3) * 4
        {
            return Err(WireError::InvalidValue);
        }
        let bytes = STANDARD
            .decode(&self.cms)
            .map_err(|_| WireError::InvalidValue)?;
        if bytes.is_empty()
            || bytes.len() > CMS_BYTES
            || self.cms_digest != format!("{:x}", Sha256::digest(&bytes))
        {
            return Err(WireError::InvalidValue);
        }
        Ok(bytes)
    }
}
impl std::fmt::Debug for Upload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileVaultUpload([REDACTED])")
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Durable acceptance of one exact submission, independent of endpoint validity.
pub struct Receipt {
    /// Stable idempotency identity retained before sending.
    pub operation_id: Uuid,
    /// Recovery-owner identity, independent from transport registration.
    pub custody_id: Uuid,
    /// Recovery-owner generation, fenced independently from device enrollment.
    pub custody_epoch: i64,
    /// Exact authorization revision selected before reading the file.
    pub configuration_revision: i64,
    /// Exact configured escrow certificate fingerprint.
    pub recipient_id: String,
    /// Lowercase SHA-256 of the decoded original CMS bytes.
    pub cms_digest: String,
    /// Durably stored recovery material identity.
    pub material: Uuid,
    /// Immutable stored material version.
    pub version: i64,
    /// Durable custody is not proof of a successful recovery unlock.
    pub escrowed: bool,
}
impl Receipt {
    /// Reject an acknowledgement for any different identity, configuration or content.
    pub fn matches(&self, upload: &Upload) -> bool {
        self.escrowed
            && !self.material.is_nil()
            && self.version > 0
            && self.operation_id == upload.operation_id
            && self.custody_id == upload.custody_id
            && self.custody_epoch == upload.custody_epoch
            && self.configuration_revision == upload.configuration_revision
            && self.recipient_id == upload.recipient_id
            && self.cms_digest == upload.cms_digest
    }
}
