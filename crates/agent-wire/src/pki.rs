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
    "be5074ea67a0d0541dd1d2f2a129a15ed2229b5ded29a581bcc4d40819ec8cbd";

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
    /// Exact configured service origin, without a path or trailing slash.
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
            &self.origin,
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
