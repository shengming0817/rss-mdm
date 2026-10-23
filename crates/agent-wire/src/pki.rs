//! Authenticated device trust distribution; HTTPS authority replaces a separate signing key.
use crate::runtime::WireError;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use uuid::Uuid;

/// Exact supported PKI format, independent of enrollment and runtime versions.
pub const API_VERSION: u8 = 1;
/// Canonical manifest of PKI HTTP payload schemas.
pub const SCHEMA_MANIFEST: &str = include_str!("../schema/pki/manifest.json");
/// SHA-256 of the ordered schema file bytes named by [`SCHEMA_MANIFEST`].
pub const SCHEMA_FINGERPRINT: &str =
    "4cdfbaa90da88f79d70ed5dcedce67839e686374f975372e0ec2de0287d1f7d8";

const MAX_REVISION: u64 = i64::MAX as u64;
const MAX_ISSUERS: usize = 16;
const ACTIVE_ISSUERS: usize = 1;
const DIGEST_HEX_LENGTH: usize = 64;
/// Independent device-certificate purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// Windows native device identity.
    Windows,
    /// Apple native device identity.
    Apple,
    /// Agent runtime identity.
    Agent,
    /// Short-lived native installation bootstrap, excluded from runtime identity.
    AgentBootstrap,
}
/// Approved issuer lifecycle. Retired issuers are excluded from distributed trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Trust is distributed before signing switches.
    Prepared,
    /// Sole issuer for newly authorized signing operations.
    Active,
    /// Existing identities remain trusted while migration finishes.
    VerifyOnly,
}
/// Public issuer and its independently signed revocation material. All DER values use base64.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    /// SHA256 of exact issuer certificate DER.
    #[serde(deserialize_with = "digest")]
    #[schemars(schema_with = "digest_schema")]
    pub digest: String,
    /// Approved lifecycle state.
    pub mode: Mode,
    /// DER issuer certificate.
    pub certificate: String,
    /// DER offline root certificate.
    pub root: String,
    /// DER CRL signed by this issuer.
    pub crl: String,
    /// DER CRL signed by the offline root, including intermediate revocations.
    pub root_crl: String,
    /// Authorized CA provisioner marker.
    pub provisioner: String,
    /// JWK public key identity; empty for native SCEP and historical local issuers.
    pub kid: String,
}
/// One complete approved trust revision, bound to the existing authenticated HTTPS authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    /// Trust format, currently exactly one.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "version_schema")]
    pub version: u8,
    /// Immutable product installation instance; never inferred from a URL.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub service_id: Uuid,
    /// Configured native-protocol locator; Agent identity is bound by service_id.
    pub origin: String,
    /// Tenant owning these device identities.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub tenant: Uuid,
    /// Device certificate purpose, independent of HTTPS/APNs/profile signing.
    pub purpose: Purpose,
    /// Monotonic approved trust revision.
    #[serde(deserialize_with = "revision")]
    #[schemars(schema_with = "revision_schema")]
    pub revision: u64,
    /// Complete overlap set, bounded to sixteen issuer generations.
    #[serde(deserialize_with = "issuers")]
    #[schemars(schema_with = "issuers_schema")]
    pub issuers: Vec<Issuer>,
}
/// Device acknowledges the exact installed trust revision over its current authenticated channel.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    /// Idempotent device operation.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation: Uuid,
    /// Trust wire format.
    #[serde(deserialize_with = "version")]
    #[schemars(schema_with = "version_schema")]
    pub version: u8,
    /// Installed monotonic revision.
    #[serde(deserialize_with = "revision")]
    #[schemars(schema_with = "revision_schema")]
    pub revision: u64,
    /// SHA256 of approved generations and revision; CRL refreshes do not change this binding.
    #[serde(deserialize_with = "digest")]
    #[schemars(schema_with = "digest_schema")]
    pub digest: String,
}

impl Trust {
    /// Check static PKI constraints, including values constructed directly in Rust.
    /// This does not verify certificates, revocation, purpose binding or installation authority.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.version != API_VERSION
            || self.tenant.is_nil()
            || self.service_id.is_nil()
            || !valid_revision(self.revision)
            || !valid_issuers(&self.issuers)
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }

    /// Stable installation binding. Revocation bytes have their own signed monotonic numbers.
    pub fn installation_digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let generations = self
            .issuers
            .iter()
            .map(|g| {
                (
                    &g.digest,
                    g.mode,
                    &g.certificate,
                    &g.root,
                    &g.provisioner,
                    &g.kid,
                )
            })
            .collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&(
            "device-trust-install/v1",
            self.version,
            self.service_id,
            self.tenant,
            self.purpose,
            self.revision,
            generations,
        ))
        .expect("public scalar trust");
        format!("{:x}", Sha256::digest(bytes))
    }
}

impl Acknowledgement {
    /// Check static PKI constraints before checking the authenticated installation binding.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.version != API_VERSION
            || self.operation.is_nil()
            || !valid_revision(self.revision)
            || !valid_digest(&self.digest)
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}

fn valid_revision(value: u64) -> bool {
    (1..=MAX_REVISION).contains(&value)
}
fn valid_digest(value: &str) -> bool {
    value.len() == DIGEST_HEX_LENGTH
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_issuers(values: &[Issuer]) -> bool {
    (1..=MAX_ISSUERS).contains(&values.len())
        && values.iter().filter(|g| g.mode == Mode::Active).count() == ACTIVE_ISSUERS
        && values.iter().all(|g| valid_digest(&g.digest))
}
fn version<'de, D: Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
    let value = u8::deserialize(d)?;
    if value != API_VERSION {
        return Err(D::Error::custom(WireError::InvalidValue));
    }
    Ok(value)
}
fn revision<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let value = u64::deserialize(d)?;
    if !valid_revision(value) {
        return Err(D::Error::custom(WireError::InvalidValue));
    }
    Ok(value)
}
fn digest<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let value = String::deserialize(d)?;
    if !valid_digest(&value) {
        return Err(D::Error::custom(WireError::InvalidValue));
    }
    Ok(value)
}
fn issuers<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Issuer>, D::Error> {
    let value = Vec::<Issuer>::deserialize(d)?;
    if !valid_issuers(&value) {
        return Err(D::Error::custom(WireError::InvalidValue));
    }
    Ok(value)
}
fn version_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"const": API_VERSION})
}
fn revision_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type": "integer", "minimum": 1, "maximum": MAX_REVISION})
}
fn digest_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type": "string", "minLength": DIGEST_HEX_LENGTH,
        "maxLength": DIGEST_HEX_LENGTH, "pattern": format!("^[0-9a-f]{{{DIGEST_HEX_LENGTH}}}$")})
}
fn issuers_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let mut schema = generator.subschema_for::<Vec<Issuer>>();
    schema.insert("minItems".into(), serde_json::json!(1));
    schema.insert("maxItems".into(), serde_json::json!(MAX_ISSUERS));
    schema.insert(
        "contains".into(),
        serde_json::json!({
            "properties": {"mode": {"const": Mode::Active}}, "required": ["mode"]
        }),
    );
    schema.insert("minContains".into(), serde_json::json!(ACTIVE_ISSUERS));
    schema.insert("maxContains".into(), serde_json::json!(ACTIVE_ISSUERS));
    schema
}

/// Device-reported installation observation; never a rotation acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Stable report operation, retained across response loss.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation: Uuid,
    /// Exact observation format.
    #[schemars(extend("const" = 1))]
    pub version: u8,
    /// Authenticated registration identity.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub registration: Uuid,
    /// Authenticated registration generation.
    #[schemars(extend("minimum" = 1, "maximum" = i64::MAX))]
    pub generation: u64,
    /// Monotonic sequence within this registration generation and domain.
    #[schemars(extend("minimum" = 1, "maximum" = i64::MAX))]
    pub sequence: u64,
    /// Target revision, absent when fetching the target failed.
    #[schemars(extend("minimum" = 1, "maximum" = i64::MAX))]
    pub target_revision: Option<u64>,
    /// Target installation digest, paired with target_revision.
    #[schemars(extend("pattern" = "^[0-9a-f]{64}$", "minLength" = 64, "maxLength" = 64))]
    pub target_digest: Option<String>,
    /// Last durably installed revision, absent when no state can be read.
    #[schemars(extend("minimum" = 1, "maximum" = i64::MAX))]
    pub actual_revision: Option<u64>,
    /// Read-back installation digest, paired with actual_revision.
    #[schemars(extend("pattern" = "^[0-9a-f]{64}$", "minLength" = 64, "maxLength" = 64))]
    pub actual_digest: Option<String>,
    /// Local result; applied does not imply ACK confirmation or current connectivity.
    pub state: ObservationState,
    /// Closed, non-secret failure category.
    pub reason: Option<ObservationReason>,
    /// Device observation time in Unix seconds; not ordering authority.
    #[schemars(extend("minimum" = 0))]
    pub observed_at: i64,
}
/// Installation result independently reported by the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    /// Target received but not durably installed.
    Received,
    /// The purpose owner committed and independently read back its applied trust material.
    /// Agent applies private trust; this is not a claim about global OS root settings.
    Applied,
    /// Attempt failed; prior installed state may remain usable.
    Failed,
    /// Local installed state cannot be determined.
    Unknown,
}
/// Closed failure reasons; raw errors and material bytes are excluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservationReason {
    /// Authenticated transport unavailable.
    Transport,
    /// Material or successor validation failed.
    Validation,
    /// Durable write or readback failed.
    Storage,
    /// Device credential unavailable or rejected.
    Credential,
    /// The purpose owner could not apply its local trust material.
    Installation,
    /// Restart requires a fresh observation.
    Restart,
}
impl Observation {
    /// Validate shape, state consistency and bounded coordinates. The service authenticates identity.
    /// Consumers must call this method: JSON Schema alone cannot compare installation digests.
    pub fn validate(&self) -> Result<(), WireError> {
        let number = |v: u64| (1..=i64::MAX as u64).contains(&v);
        let material = |revision: Option<u64>, digest: &Option<String>| match (revision, digest) {
            (None, None) => true,
            (Some(r), Some(d)) => {
                number(r)
                    && d.len() == 64
                    && d.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }
            _ => false,
        };
        if self.version != API_VERSION
            || self.operation.is_nil()
            || self.registration.is_nil()
            || !number(self.generation)
            || !number(self.sequence)
            || self.observed_at < 0
            || !material(self.target_revision, &self.target_digest)
            || !material(self.actual_revision, &self.actual_digest)
            || match self.state {
                ObservationState::Applied => {
                    self.reason.is_some()
                        || self.target_revision.is_none()
                        || self.target_revision != self.actual_revision
                        || self.target_digest != self.actual_digest
                }
                ObservationState::Received => {
                    self.reason.is_some() || self.target_revision.is_none()
                }
                ObservationState::Failed | ObservationState::Unknown => self.reason.is_none(),
            }
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}
/// Last report with server reception time. Absence means unknown, never successful installation.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedInstallation {
    /// Device statement, not a server assertion of disk contents or CRL freshness.
    pub observation: Observation,
    /// Server receipt time in Unix seconds.
    pub received_at: i64,
}
