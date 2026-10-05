//! Authenticated device trust distribution; HTTPS authority replaces a separate signing key.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
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
    pub version: u8,
    /// Exact configured service origin, without a path or trailing slash.
    pub origin: String,
    /// Tenant owning these device identities.
    pub tenant: Uuid,
    /// Device certificate purpose, independent of HTTPS/APNs/profile signing.
    pub purpose: Purpose,
    /// Monotonic approved trust revision.
    pub revision: u64,
    /// Complete overlap set, bounded to sixteen issuer generations.
    pub issuers: Vec<Issuer>,
}
/// Device acknowledges the exact installed trust revision over its current authenticated channel.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    /// Idempotent device operation.
    pub operation: Uuid,
    /// Trust wire format.
    pub version: u8,
    /// Installed monotonic revision.
    pub revision: u64,
    /// SHA256 of approved generations and revision; CRL refreshes do not change this binding.
    pub digest: String,
}

impl Trust {
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
