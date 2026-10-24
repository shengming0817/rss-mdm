//! RSS Platform SSO wire values. Apple protocols and server authority remain separate.
//! ref: Apple AuthenticationServices/ASAuthorizationProviderExtensionRegistrationHandler.h (SDK 26.4)
use crate::runtime::WireError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Current RSS-owned API format; independent of Apple's PSSO version.
pub const API_VERSION: u8 = 1;
/// Manifest generated from these Rust wire declarations.
pub const SCHEMA_MANIFEST: &str = include_str!("../schema/platform_sso/manifest.json");
/// SHA-256 of the ordered generated schema bytes.
pub const SCHEMA_FINGERPRINT: &str =
    "40f09ace0b645d989fd3ef56d17d8fde27e5500eb3b843547453eeba6422454e";

/// One-use nonce lifetime in seconds.
pub const NONCE_SECONDS: i64 = 120;
/// Native access-token lifetime in seconds.
pub const TOKEN_SECONDS: i64 = 300;
/// Native SSO refresh-material lifetime in seconds.
pub const SSO_SECONDS: i64 = 14400;
/// Apple outer login-request JWT purpose.
pub const LOGIN_TYPE: &str = "platformsso-login-request+jwt";
/// Apple inner login-assertion JWT purpose.
pub const ASSERTION_TYPE: &str = "platformsso-login-assertion+jwt";
/// RSS browser proof purpose.
pub const BRIDGE_TYPE: &str = "rss-mdm-platform-sso-browser+jwt";
/// Exact supported native login scope.
pub const SCOPE: &str = "openid offline_access urn:apple:platformsso";

#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Deployment-selected identities; no private signing material.
pub struct Configuration {
    /// Apple signing team identifier.
    pub team_id: String,
    /// Signed extension bundle identifier.
    pub extension_id: String,
    /// Signed containing application bundle identifier.
    pub application_id: String,
    /// Exact application inventory version required before registration.
    pub application_version: String,
    /// Apple login client UUID.
    pub client_id: Uuid,
}
impl Configuration {
    /// Validate deployment identities without granting registration authority.
    pub fn validate(&self) -> Result<(), WireError> {
        let identifier = |s: &str| {
            s.len() <= 255
                && s.contains('.')
                && s.split('.').all(|p| {
                    !p.is_empty() && p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                })
        };
        if self.team_id.len() != 10
            || !self
                .team_id
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            || !identifier(&self.extension_id)
            || !identifier(&self.application_id)
            || self.application_id == self.extension_id
            || self.client_id.is_nil()
            || self.application_version.is_empty()
            || self.application_version.len() > 64
            || !self
                .application_version
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()))
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Exact tenant-scoped HTTPS endpoints.
pub struct Endpoints {
    /// Tenant protocol base URL.
    pub base: String,
    /// Expected native token issuer.
    pub issuer: String,
    /// One-use server nonce endpoint.
    pub nonce: String,
    /// Native login endpoint.
    pub token: String,
    /// Server verification-key endpoint.
    pub jwks: String,
}
impl Endpoints {
    /// Derive endpoints from a canonical HTTPS origin and nonzero tenant.
    pub fn new(origin: &str, tenant: Uuid) -> Result<Self, WireError> {
        let url = url::Url::parse(origin).map_err(|_| WireError::InvalidValue)?;
        if tenant.is_nil()
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.origin().ascii_serialization() != origin
        {
            return Err(WireError::InvalidValue);
        }
        let base = format!("{origin}/api/v1/apple/platform-sso/{tenant}");
        Ok(Self {
            issuer: base.clone(),
            nonce: format!("{base}/nonce"),
            token: format!("{base}/token"),
            jwks: format!("{base}/jwks"),
            base,
        })
    }
}

/// Public key only. The verifier validates the curve, point and Apple's derived key id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    /// JWK key type, EC.
    pub kty: String,
    /// JWK curve, P-256.
    pub crv: String,
    /// Canonical unpadded Base64URL x coordinate.
    pub x: String,
    /// Canonical unpadded Base64URL y coordinate.
    pub y: String,
}

/// No caller-controlled principal/assurance: the binding is always resolved by its owner.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Registration {
    /// Audit/idempotency operation.
    pub operation_id: Uuid,
    /// One-use bootstrap challenge.
    pub challenge_id: Uuid,
    /// Public key whose possession is proved.
    pub signing_key: PublicKey,
    /// Encryption public key bound into the proof.
    pub encryption_key: PublicKey,
    /// Signed registration JWT; never log.
    pub proof: String,
}

/// Registration proof purpose, distinct from login and browser proof.
pub const REGISTRATION_TYPE: &str = "rss-mdm-platform-sso-registration+jwt";
/// Native Apple grant; no password or ordinary refresh grant is supported.
pub const GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Which system-owned keys are being registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Shared device keys; no user binding.
    Device,
    /// Secure Enclave signing key and user encryption key.
    User,
}
impl Kind {
    /// Stable persisted and wire representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::User => "user",
        }
    }
}
/// Start one registration through the authenticated Agent channel.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bootstrap {
    /// Audit/idempotency operation.
    pub operation_id: Uuid,
    /// Device or user scope.
    pub kind: Kind,
    /// Required only for user registration.
    pub binding_id: Option<Uuid>,
    /// Required only for user registration.
    pub binding_generation: Option<i64>,
}
/// Short-lived registration challenge. Never log or expose it to the renderer.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapResponse {
    /// One-use challenge identity.
    pub id: Uuid,
    /// One-use server nonce.
    pub nonce: String,
    /// Absolute expiry in UTC seconds.
    pub expires_at: i64,
    /// Stable registered-source identity.
    pub source_id: Uuid,
    /// Version being registered.
    pub source_version: i64,
    /// Exact HTTPS tenant endpoints.
    pub endpoints: Endpoints,
    /// Apple login client identifier.
    pub client_id: Uuid,
    /// Server-selected login subject, never the local account name.
    pub login_user_name: String,
}
/// Signed registration claims. Signature verification and authority belong to consumers.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationClaims {
    /// Current Agent registration UUID.
    pub iss: Uuid,
    /// Tenant registration audience.
    pub aud: String,
    /// Exact bootstrap challenge.
    pub challenge_id: Uuid,
    /// Exact source identity.
    pub source_id: Uuid,
    /// Exact source version.
    pub source_version: i64,
    /// Bootstrap nonce.
    pub nonce: String,
    /// SHA-256 of the X9.63 encryption key, standard Base64.
    pub encryption_key_id: String,
    /// Issued UTC seconds.
    pub iat: i64,
    /// Expiry UTC seconds.
    pub exp: i64,
}
/// Server proof class; registration alone does not attest hardware or MFA.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationTrust {
    /// Device-authenticated bootstrap and key possession.
    MdmBootstrapPop,
}
/// Successful registration receipt, not native system registration evidence.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    /// Source registered by this operation.
    pub source_id: Uuid,
    /// Accepted source version.
    pub source_version: i64,
    /// Device or user registration.
    pub kind: Kind,
    /// Registration was durably accepted.
    pub registered: bool,
    /// Independent hardware attestation fact.
    pub hardware_attested: bool,
    /// Actual registration proof class.
    pub registration_trust: RegistrationTrust,
}
/// Revocation outcome; local system cleanup is a separate operation.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    /// Revoked source.
    pub source_id: Uuid,
    /// Current source version.
    pub source_version: i64,
    /// Server revocation completed.
    pub revoked: bool,
}
/// Public recovery coordinates, never private key material.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceStatus {
    /// Stable source identity.
    pub id: Uuid,
    /// Accepted registration version.
    pub version: i64,
    /// Whether the source was revoked.
    pub revoked: bool,
    /// Accepted signing public key.
    pub signing_key: PublicKey,
    /// Accepted encryption public key.
    pub encryption_key: PublicKey,
}
/// Read-only server observations. These never authorize a login.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    /// Current MDM application inventory matches.
    pub application_observed: bool,
    /// Current MDM profile inventory matches.
    pub profile_observed: bool,
    /// Shared device registration is current.
    pub device_registered: bool,
    /// User registration is current.
    pub user_registered: bool,
    /// Server admission currently permits native login.
    pub login_ready: bool,
    /// Device key recovery coordinates.
    pub device_source: Option<SourceStatus>,
    /// User key recovery coordinates.
    pub user_source: Option<SourceStatus>,
    /// Actual registration proof class.
    pub registration_trust: RegistrationTrust,
    /// Independent hardware attestation fact.
    pub hardware_attested: bool,
}
/// Browser login initiation; Identity remains the session owner.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserBegin {
    /// User-selected business binding; the server reauthorizes it.
    pub binding_id: Uuid,
}
/// Identity challenge exposed to the native extension by the configured browser flow.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserChallenge {
    /// Identity challenge ID.
    pub id: Uuid,
    /// One-use nonce.
    pub nonce: String,
    /// UTC expiry.
    pub expires_at: i64,
    /// Exact proof audience.
    pub audience: String,
}
/// Browser completion. The browser-bound cookie is transported separately.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserComplete {
    /// Identity challenge ID.
    pub challenge_id: Uuid,
    /// One-use nonce.
    pub nonce: String,
    /// Native key proof, never an arbitrary identity token.
    pub proof: String,
}
/// Native proof for the one supported RSS browser-session bridge.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserClaims {
    /// Current user source UUID.
    pub iss: Uuid,
    /// Identity challenge audience.
    pub aud: String,
    /// Identity challenge nonce.
    pub nonce: String,
    /// Current source version.
    pub source_version: i64,
    /// Unexpired native access token; never persisted by the browser.
    pub access_token: String,
    /// Issued UTC seconds.
    pub iat: i64,
    /// Expiry UTC seconds.
    pub exp: i64,
}
impl PublicKey {
    /// X9.63 bytes; checks wire encoding, not elliptic-curve membership.
    pub fn x963(&self) -> Result<Vec<u8>, WireError> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as URL};
        if self.kty != "EC" || self.crv != "P-256" {
            return Err(WireError::InvalidValue);
        }
        let mut point = vec![4];
        for coordinate in [&self.x, &self.y] {
            if coordinate.len() != 43 {
                return Err(WireError::InvalidValue);
            }
            let bytes = URL
                .decode(coordinate)
                .map_err(|_| WireError::InvalidValue)?;
            if bytes.len() != 32 || URL.encode(&bytes) != *coordinate {
                return Err(WireError::InvalidValue);
            }
            point.extend(bytes);
        }
        Ok(point)
    }
    /// Apple key ID: standard Base64 SHA-256 of the uncompressed public point.
    pub fn key_id(&self) -> Result<String, WireError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use sha2::{Digest, Sha256};
        Ok(STANDARD.encode(Sha256::digest(self.x963()?)))
    }
}
/// Canonical signing input for RSS-owned proofs; signing stays in the native key owner.
fn proof_input<T: Serialize>(typ: &str, key: &PublicKey, claims: &T) -> Result<String, WireError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as URL};
    if ![REGISTRATION_TYPE, BRIDGE_TYPE].contains(&typ) {
        return Err(WireError::InvalidValue);
    }
    let header = serde_json::json!({"alg":"ES256", "typ":typ, "kid":key.key_id()?});
    Ok(format!(
        "{}.{}",
        URL.encode(serde_json::to_vec(&header).map_err(|_| WireError::InvalidValue)?),
        URL.encode(serde_json::to_vec(claims).map_err(|_| WireError::InvalidValue)?)
    ))
}

impl RegistrationClaims {
    /// Bytes signed by the native registration key; never log this value.
    pub fn signing_input(&self, key: &PublicKey) -> Result<String, WireError> {
        proof_input(REGISTRATION_TYPE, key, self)
    }
}
impl BrowserClaims {
    /// Bytes signed by the registered user key for one browser challenge.
    pub fn signing_input(&self, key: &PublicKey) -> Result<String, WireError> {
        proof_input(BRIDGE_TYPE, key, self)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_identity_and_registration_input_are_shared_with_native_consumer() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as URL};
        let key = PublicKey {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "BkFHRYQoleq39LplGqlcmsEdnw64w0wbcbHAEjrM4pw".into(),
            y: "jbOoWZbgDFTEfLa1O_7ZuJy3R8d2XAw0CHWUKmJLsbU".into(),
        };
        assert_eq!(key.x963().unwrap().len(), 65);
        assert_eq!(key.key_id().unwrap().len(), 44);
        let mut invalid = key.clone();
        invalid.x.push('=');
        assert!(invalid.key_id().is_err());
        let claims = RegistrationClaims {
            iss: Uuid::new_v4(),
            aud: "https://mdm.example/register".into(),
            challenge_id: Uuid::new_v4(),
            source_id: Uuid::new_v4(),
            source_version: 2,
            nonce: "nonce".into(),
            encryption_key_id: key.key_id().unwrap(),
            iat: 10,
            exp: 20,
        };
        let input = claims.signing_input(&key).unwrap();
        let (header, body) = input.split_once('.').unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL.decode(header).unwrap()).unwrap();
        assert_eq!(header["typ"], REGISTRATION_TYPE);
        assert_eq!(header["kid"], key.key_id().unwrap());
        let decoded: RegistrationClaims =
            serde_json::from_slice(&URL.decode(body).unwrap()).unwrap();
        assert_eq!(decoded.challenge_id, claims.challenge_id);
        assert_eq!(decoded.source_version, 2);
        let mut invalid = serde_json::to_value(&claims).unwrap();
        invalid["principal"] = serde_json::json!("not-authority");
        assert!(serde_json::from_value::<RegistrationClaims>(invalid).is_err());
    }
    #[test]
    fn endpoints_are_exact_https_tenant_authorities() {
        let t = Uuid::new_v4();
        assert!(
            Endpoints::new("https://mdm.example", t)
                .unwrap()
                .token
                .ends_with(&format!("/{t}/token"))
        );
        for origin in [
            "http://mdm.example",
            "https://user@mdm.example",
            "https://mdm.example/prefix",
            "https://mdm.example?x=1",
            "https://mdm.example/",
        ] {
            assert!(Endpoints::new(origin, t).is_err());
        }
        assert!(Endpoints::new("https://mdm.example", Uuid::nil()).is_err());
    }
}

/// Status selector over the authenticated Agent channel.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusQuery {
    /// Optional binding for this device's user status.
    pub binding_id: Option<Uuid>,
}
