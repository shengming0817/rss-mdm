//! Fixed Agent package commands; installation acknowledgement is not presence evidence.
//! ref: apple/device-management mdm/commands/application.{install.enterprise,installed.list}.yaml
use crate::{
    Error,
    protocol::{dictionary, text},
};
use plist::{Dictionary, Value};
use uuid::Uuid;
fn bounded(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}
pub fn install(
    bundle: &str,
    version: &str,
    url: &str,
    hash: [u8; 32],
    operation: Uuid,
) -> Result<Dictionary, Error> {
    let location = url::Url::parse(url).map_err(|_| Error::Malformed)?;
    if !bounded(bundle)
        || !bounded(version)
        || hash == [0; 32]
        || operation.is_nil()
        || url.len() > 2048
        || location.scheme() != "https"
        || location.host_str().is_none()
        || !location.username().is_empty()
        || location.password().is_some()
        || location.fragment().is_some()
    {
        return Err(Error::Malformed);
    }
    let hash = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let asset = dictionary([
        ("kind", "software-package".into()),
        ("url", url.into()),
        ("sha256", hash.into()),
    ]);
    let metadata = dictionary([
        ("bundle-identifier", bundle.into()),
        ("bundle-version", version.into()),
        ("kind", "software".into()),
        ("title", "RSS Agent".into()),
    ]);
    let item = dictionary([
        ("assets", Value::Array(vec![asset.into()])),
        ("metadata", metadata.into()),
    ]);
    Ok(dictionary([
        ("RequestType", "InstallEnterpriseApplication".into()),
        (
            "Manifest",
            dictionary([("items", Value::Array(vec![item.into()]))]).into(),
        ),
        (
            "Configuration",
            dictionary([("RSSInstallationOperation", operation.to_string().into())]).into(),
        ),
    ]))
}
pub fn query(bundle: &str) -> Result<Dictionary, Error> {
    if !bounded(bundle) {
        return Err(Error::Malformed);
    }
    Ok(dictionary([
        ("RequestType", "InstalledApplicationList".into()),
        ("Identifiers", Value::Array(vec![bundle.into()])),
        ("ManagedAppsOnly", false.into()),
    ]))
}
pub fn platform() -> Dictionary {
    dictionary([
        ("RequestType", "DeviceInformation".into()),
        (
            "Queries",
            Value::Array(vec!["IsAppleSilicon".into(), "OSVersion".into()]),
        ),
    ])
}
pub fn architecture(d: &Dictionary) -> Result<&'static str, Error> {
    let d = d
        .get("QueryResponses")
        .and_then(Value::as_dictionary)
        .ok_or(Error::Malformed)?;
    let major = text(d, "OSVersion")?
        .split('.')
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .ok_or(Error::Malformed)?;
    if major < 12 {
        return Err(Error::Unsupported);
    }
    match d.get("IsAppleSilicon").and_then(Value::as_boolean) {
        Some(true) => Ok("aarch64"),
        Some(false) => Ok("x86_64"),
        None => Err(Error::Malformed),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Presence {
    Absent,
    Installing,
    /// Bundle/version presence cannot verify the signing team or package receipt.
    PresentUnverified {
        version: String,
    },
}
pub fn presence(d: &Dictionary, bundle: &str) -> Result<Presence, Error> {
    let list = d
        .get("InstalledApplicationList")
        .and_then(Value::as_array)
        .ok_or(Error::Malformed)?;
    if list.len() > 1 {
        return Err(Error::Malformed);
    }
    let Some(value) = list.first() else {
        return Ok(Presence::Absent);
    };
    let item = value.as_dictionary().ok_or(Error::Malformed)?;
    if text(item, "Identifier")? != bundle {
        return Err(Error::Conflict);
    }
    if let Some(installing) = item.get("Installing") {
        match installing.as_boolean() {
            Some(true) => return Ok(Presence::Installing),
            Some(false) => (),
            None => return Err(Error::Malformed),
        }
    }
    let version = text(item, "Version")?;
    if !bounded(version) {
        return Err(Error::Malformed);
    }
    Ok(Presence::PresentUnverified {
        version: version.into(),
    })
}
