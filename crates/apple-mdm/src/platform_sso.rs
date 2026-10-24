//! Native configuration compilation for the public Platform SSO contract.
//! ref: apple/device-management mdm/profiles/com.apple.extensiblesso.yaml
use crate::{
    Error,
    native::{
        input::Fields,
        profiles::{PayloadInput, ProfileInput},
    },
};
use rss_mdm_agent_wire::platform_sso::{Configuration, Endpoints};
use uuid::Uuid;

/// Uses the existing native schema/compiler; this is not evidence of installation.
pub fn profile(
    configuration: &Configuration,
    origin: &str,
    tenant: Uuid,
    id: Uuid,
    payload_id: Uuid,
) -> Result<ProfileInput, Error> {
    configuration.validate().map_err(|_| Error::Malformed)?;
    let endpoints = Endpoints::new(origin, tenant).map_err(|_| Error::Malformed)?;
    if id.is_nil() || payload_id.is_nil() || payload_id == id {
        return Err(Error::Malformed);
    }
    let mut fields = plist::Dictionary::new();
    fields.insert("Type".into(), "Redirect".into());
    fields.insert(
        "ExtensionIdentifier".into(),
        configuration.extension_id.clone().into(),
    );
    fields.insert(
        "TeamIdentifier".into(),
        configuration.team_id.clone().into(),
    );
    fields.insert(
        "URLs".into(),
        plist::Value::Array(vec![format!("{}/browser/", endpoints.base).into()]),
    );
    let mut platform = plist::Dictionary::new();
    platform.insert("AuthenticationMethod".into(), "UserSecureEnclaveKey".into());
    platform.insert("UseSharedDeviceKeys".into(), true.into());
    fields.insert("PlatformSSO".into(), platform.into());
    let host = url::Url::parse(origin).map_err(|_| Error::Malformed)?;
    let domain = host.domain().ok_or(Error::Malformed)?;
    let mut associated = plist::Dictionary::new();
    let mut item = plist::Dictionary::new();
    item.insert(
        "ApplicationIdentifier".into(),
        format!("{}.{}", configuration.team_id, configuration.application_id).into(),
    );
    item.insert(
        "AssociatedDomains".into(),
        plist::Value::Array(vec![format!("authsrv:{domain}?mode=managed").into()]),
    );
    item.insert("EnableDirectDownloads".into(), true.into());
    associated.insert(
        "Configuration".into(),
        plist::Value::Array(vec![item.into()]),
    );
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("rss.platform-sso.associated-domains:{id}"));
    let associated_id = Uuid::from_slice(&digest[..16]).map_err(|_| Error::Malformed)?;
    if associated_id == id || associated_id == payload_id {
        return Err(Error::Malformed);
    }
    Ok(ProfileInput {
        identifier: format!("rss.platform-sso.{id}"),
        uuid: id,
        metadata: Fields::default(),
        payloads: vec![
            PayloadInput {
                schema: "mdm/profiles/com.apple.extensiblesso.yaml".into(),
                identifier: format!("rss.platform-sso.{id}.extension"),
                uuid: payload_id,
                metadata: Fields::default(),
                fields: Fields::from_plist(&fields).map_err(|_| Error::Malformed)?,
            },
            PayloadInput {
                schema: "mdm/profiles/com.apple.associated-domains.yaml".into(),
                identifier: format!("rss.platform-sso.{id}.associated-domains"),
                uuid: associated_id,
                metadata: Fields::default(),
                fields: Fields::from_plist(&associated).map_err(|_| Error::Malformed)?,
            },
        ],
    })
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
        let profile = profile(
            &config,
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
        let payloads = value.as_dictionary().unwrap()["PayloadContent"]
            .as_array()
            .unwrap();
        assert_eq!(payloads.len(), 2);
        let association = &payloads[1].as_dictionary().unwrap()["Configuration"]
            .as_array()
            .unwrap()[0];
        assert_eq!(
            association.as_dictionary().unwrap()["ApplicationIdentifier"].as_string(),
            Some("ABCDEFGHIJ.com.example.rss")
        );
        assert_eq!(
            association.as_dictionary().unwrap()["AssociatedDomains"]
                .as_array()
                .unwrap()[0]
                .as_string(),
            Some("authsrv:mdm.example?mode=managed")
        );
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
        for version in [".", "1..0", ".1", "1."] {
            let mut bad = config.clone();
            bad.application_version = version.into();
            assert!(bad.validate().is_err());
        }
    }
}
