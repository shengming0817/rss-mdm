//! The single RSS Platform SSO V1 contract. Apple protocol versions are independent.
//! ref: apple/device-management mdm/profiles/com.apple.extensiblesso.yaml
use crate::{
    Error,
    native::{
        input::Fields,
        profiles::{PayloadInput, ProfileInput},
    },
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const NONCE_SECONDS: i64 = 120;
pub const TOKEN_SECONDS: i64 = 300;
pub const SSO_SECONDS: i64 = 14400;
pub const LOGIN_TYPE: &str = "platformsso-login-request+jwt";
pub const ASSERTION_TYPE: &str = "platformsso-login-assertion+jwt";
pub const BRIDGE_TYPE: &str = "rss-mdm-platform-sso-browser+jwt";
pub const SCOPE: &str = "openid offline_access urn:apple:platformsso";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub team_id: String,
    pub extension_id: String,
    pub application_id: String,
    pub application_version: String,
    pub client_id: Uuid,
}
impl Configuration {
    pub fn validate(&self) -> Result<(), Error> {
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
                .bytes()
                .all(|c| c.is_ascii_digit() || c == b'.')
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    /// Uses the existing native schema/compiler; this is not evidence of installation.
    pub fn profile(
        &self,
        origin: &str,
        tenant: Uuid,
        id: Uuid,
        payload_id: Uuid,
    ) -> Result<ProfileInput, Error> {
        self.validate()?;
        let endpoints = Endpoints::new(origin, tenant)?;
        if id.is_nil() || payload_id.is_nil() || payload_id == id {
            return Err(Error::Malformed);
        }
        let mut fields = plist::Dictionary::new();
        fields.insert("Type".into(), "Redirect".into());
        fields.insert(
            "ExtensionIdentifier".into(),
            self.extension_id.clone().into(),
        );
        fields.insert("TeamIdentifier".into(), self.team_id.clone().into());
        fields.insert(
            "URLs".into(),
            plist::Value::Array(vec![format!("{}/browser/", endpoints.base).into()]),
        );
        let mut platform = plist::Dictionary::new();
        platform.insert("AuthenticationMethod".into(), "UserSecureEnclaveKey".into());
        platform.insert("UseSharedDeviceKeys".into(), true.into());
        fields.insert("PlatformSSO".into(), platform.into());
        Ok(ProfileInput {
            identifier: format!("rss.platform-sso.{id}"),
            uuid: id,
            metadata: Fields::default(),
            payloads: vec![PayloadInput {
                schema: "mdm/profiles/com.apple.extensiblesso.yaml".into(),
                identifier: format!("rss.platform-sso.{id}.extension"),
                uuid: payload_id,
                metadata: Fields::default(),
                fields: Fields::from_plist(&fields).map_err(|_| Error::Malformed)?,
            }],
        })
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoints {
    pub base: String,
    pub issuer: String,
    pub nonce: String,
    pub token: String,
    pub jwks: String,
}
impl Endpoints {
    pub fn new(origin: &str, tenant: Uuid) -> Result<Self, Error> {
        let url = url::Url::parse(origin).map_err(|_| Error::Malformed)?;
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
            return Err(Error::Malformed);
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

/// No caller-controlled principal/assurance: the binding is always resolved by its owner.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Registration {
    pub operation_id: Uuid,
    pub challenge_id: Uuid,
    pub signing_key: PublicKey,
    pub encryption_key: PublicKey,
    pub proof: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_uses_the_native_schema_and_preserves_local_login() {
        use crate::{
            applicability::{Channel, Context, Enrollment, Version},
            native::Target,
        };
        let config = Configuration {
            team_id: "ABCDEFGHIJ".into(),
            extension_id: "com.example.rss.psso".into(),
            application_id: "com.example.rss".into(),
            application_version: "1.0".into(),
            client_id: Uuid::new_v4(),
        };
        let profile = config
            .profile(
                "https://mdm.example",
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
            )
            .unwrap();
        let context = Context {
            version: Some(Version::parse("26.4").unwrap()),
            channel: Channel::Device,
            enrollment: Enrollment::Device,
            supervised: Some(true),
            automated_enrollment: Some(false),
            user_approved: Some(true),
            apple_silicon: Some(true),
        };
        let compiled = profile
            .compile(&Target {
                context: &context,
                access_rights: &[],
            })
            .unwrap();
        let value = plist::Value::from_reader(std::io::Cursor::new(compiled.bytes)).unwrap();
        let fields = &value.as_dictionary().unwrap()["PayloadContent"]
            .as_array()
            .unwrap()[0];
        let psso = fields.as_dictionary().unwrap()["PlatformSSO"]
            .as_dictionary()
            .unwrap();
        assert_eq!(
            psso["AuthenticationMethod"].as_string(),
            Some("UserSecureEnclaveKey")
        );
        assert_eq!(psso["UseSharedDeviceKeys"].as_boolean(), Some(true));
        assert!(!psso.contains_key("EnableCreateUserAtLogin"));
        assert!(!psso.contains_key("LoginPolicy"));
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
