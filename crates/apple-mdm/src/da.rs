//! Managed DA carrier. Native wrapping preserves the independently signed inner envelope.
//! ref: apple/device-management mdm/profiles/com.apple.ManagedClient.preferences.yaml.
use crate::{
    Error,
    native::{
        Target,
        input::Fields,
        profiles::{PayloadInput, ProfileInput},
    },
};
use plist::{Dictionary, Value};
use rss_mdm_agent_wire::da::SignedConfiguration;
use sha2::{Digest, Sha256};
/// Fixed application preference domain consumed by DA clients.
pub const DOMAIN: &str = "com.rss.device-access";
/// The only managed preference value; no unsigned parallel settings are accepted.
pub const VALUE: &str = "SignedConfiguration";
/// Append the carrier identity before the native expectation is signed.
pub fn bind(profile: &mut ProfileInput) -> Result<(), Error> {
    let digest = Sha256::digest(format!("rss.da.managed-preferences:{}", profile.uuid));
    profile.payloads.push(PayloadInput {
        schema: "mdm/profiles/com.apple.ManagedClient.preferences.yaml".into(),
        identifier: format!("rss.platform-sso.{}.device-access", profile.uuid),
        uuid: uuid::Uuid::from_slice(&digest[..16]).map_err(|_| Error::Malformed)?,
        metadata: Fields::default(),
        fields: carrier("")?,
    });
    Ok(())
}
fn carrier(value: &str) -> Result<Fields, Error> {
    let mut settings = Dictionary::new();
    settings.insert(VALUE.into(), Value::String(value.into()));
    let mut forced = Dictionary::new();
    forced.insert("mcx_preference_settings".into(), settings.into());
    let mut domain = Dictionary::new();
    domain.insert("Forced".into(), Value::Array(vec![forced.into()]));
    let mut content = Dictionary::new();
    content.insert(DOMAIN.into(), domain.into());
    let mut fields = Dictionary::new();
    fields.insert("PayloadContent".into(), content.into());
    Fields::from_plist(&fields).map_err(|_| Error::Malformed)
}
/// Derive a native profile from an already authorized immutable signing receipt.
/// This function checks structural integrity; consumers must verify DA trust separately.
pub fn profile(signed: &SignedConfiguration) -> Result<ProfileInput, Error> {
    let configuration = signed.decode().map_err(|_| Error::Malformed)?;
    let mut profile = crate::platform_sso::from_da_configuration(&configuration)?;
    profile.payloads.last_mut().ok_or(Error::Malformed)?.fields =
        carrier(&serde_json::to_string(signed).map_err(|_| Error::Malformed)?)?;
    Ok(profile)
}
/// Extract opaque inner bytes and reject changes to every bound native field.
/// The three display metadata keys may be changed by a deployment owner before re-signing CMS.
/// Callers unwrap CMS with their existing certificate owner and verify DA trust independently.
pub fn extract(bytes: &[u8], target: &Target<'_>) -> Result<SignedConfiguration, Error> {
    if bytes.len() > 262144 {
        return Err(Error::Malformed);
    }
    let value = Value::from_reader(std::io::Cursor::new(bytes)).map_err(|_| Error::Malformed)?;
    let payloads = value
        .as_dictionary()
        .and_then(|d| d.get("PayloadContent"))
        .and_then(Value::as_array)
        .ok_or(Error::Malformed)?;
    let mut carriers = payloads
        .iter()
        .filter_map(|p| p.as_dictionary())
        .filter(|p| {
            p.get("PayloadType").and_then(Value::as_string)
                == Some("com.apple.ManagedClient.preferences")
        });
    let carrier = carriers.next().ok_or(Error::Malformed)?;
    if carriers.next().is_some() {
        return Err(Error::Malformed);
    }
    let content = carrier
        .get("PayloadContent")
        .and_then(Value::as_dictionary)
        .and_then(|d| d.get(DOMAIN))
        .and_then(Value::as_dictionary)
        .and_then(|d| d.get("Forced"))
        .and_then(Value::as_array)
        .filter(|a| a.len() == 1)
        .and_then(|a| a[0].as_dictionary())
        .and_then(|d| d.get("mcx_preference_settings"))
        .and_then(Value::as_dictionary)
        .filter(|d| d.len() == 1)
        .and_then(|d| d.get(VALUE))
        .and_then(Value::as_string)
        .ok_or(Error::Malformed)?;
    let signed: SignedConfiguration =
        serde_json::from_str(content).map_err(|_| Error::Malformed)?;
    let expected = profile(&signed)?
        .compile(target)
        .map_err(|_| Error::Malformed)?;
    let expected =
        Value::from_reader(std::io::Cursor::new(expected.bytes)).map_err(|_| Error::Malformed)?;
    if canonical(value)? != canonical(expected)? {
        return Err(Error::Malformed);
    }
    Ok(signed)
}
fn canonical(mut value: Value) -> Result<Value, Error> {
    fn clean(d: &mut Dictionary) {
        for key in [
            "PayloadDisplayName",
            "PayloadDescription",
            "PayloadOrganization",
        ] {
            d.remove(key);
        }
    }
    let root = value.as_dictionary_mut().ok_or(Error::Malformed)?;
    clean(root);
    for p in root
        .get_mut("PayloadContent")
        .and_then(Value::as_array_mut)
        .ok_or(Error::Malformed)?
    {
        clean(p.as_dictionary_mut().ok_or(Error::Malformed)?);
    }
    Ok(value)
}
/// Bind a real MDM content transport URL to the exact same profile identities and bytes.
/// An HTTPS URL alone is not proof that its transport serves the artifact or supports MDM auth.
pub fn legacy(
    profile: &ProfileInput,
    url: &str,
) -> Result<crate::native::ddm::DeclarationInput, Error> {
    let url = url::Url::parse(url).map_err(|_| Error::Malformed)?;
    if url.scheme() != "https"
        || url.domain().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Malformed);
    }
    let mut fields = Dictionary::new();
    fields.insert("ProfileURL".into(), url.to_string().into());
    Ok(crate::native::ddm::DeclarationInput {
        identifier: format!("{}.legacy", profile.identifier),
        declaration_type: "com.apple.configuration.legacy".into(),
        payload: Fields::from_plist(&fields).map_err(|_| Error::Malformed)?,
    })
}
