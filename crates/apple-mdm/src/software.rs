//! Native application queries and presence evidence, independent of product admission.
//! ref: apple/device-management mdm/commands/application.{install.enterprise,installed.list}.yaml
use crate::{
    Error,
    protocol::{dictionary, text},
};
use plist::{Dictionary, Value};
fn bounded(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
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

/// Read-only native follow-up derived from the command's own application identities.
/// ManifestURL alone carries no trusted bundle identity; it cannot justify a guessed target.
pub fn observation(
    command: &crate::native::input::CommandInput,
) -> Result<Option<crate::native::input::CommandInput>, Error> {
    if !matches!(
        command.request_type.as_str(),
        "InstallEnterpriseApplication" | "InstallApplication" | "RemoveApplication"
    ) {
        return Ok(None);
    }
    let fields = command.fields.to_plist().map_err(|_| Error::Malformed)?;
    let mut identifiers = std::collections::BTreeSet::new();
    if let Some(id) = fields.get("Identifier").and_then(Value::as_string) {
        if !bounded(id) {
            return Err(Error::Malformed);
        }
        identifiers.insert(id.to_owned());
    }
    if let Some(manifest) = fields.get("Manifest").and_then(Value::as_dictionary)
        && let Some(items) = manifest.get("items").and_then(Value::as_array)
    {
        for item in items {
            let Some(id) = item
                .as_dictionary()
                .and_then(|v| v.get("metadata"))
                .and_then(Value::as_dictionary)
                .and_then(|v| v.get("bundle-identifier"))
                .and_then(Value::as_string)
            else {
                continue;
            };
            if !bounded(id) || identifiers.len() >= 4096 {
                return Err(Error::Malformed);
            }
            identifiers.insert(id.to_owned());
        }
    }
    if identifiers.is_empty() {
        return Ok(None);
    }
    let fields = dictionary([
        (
            "Identifiers",
            Value::Array(identifiers.into_iter().map(Value::String).collect()),
        ),
        ("ManagedAppsOnly", false.into()),
    ]);
    Ok(Some(crate::native::input::CommandInput {
        request_type: "InstalledApplicationList".into(),
        fields: crate::native::input::Fields::from_plist(&fields).map_err(|_| Error::Malformed)?,
    }))
}

/// Typed native presence for the exact single bundle selected by a follow-up command.
pub fn receipt_presence(
    command: &crate::native::input::CommandInput,
    report: &Dictionary,
) -> Result<Option<Presence>, Error> {
    let Some(query) = observation(command)? else {
        return Ok(None);
    };
    let fields = query.fields.to_plist().map_err(|_| Error::Malformed)?;
    let ids = fields
        .get("Identifiers")
        .and_then(Value::as_array)
        .ok_or(Error::Malformed)?;
    if ids.len() != 1 {
        return Ok(None);
    }
    let bundle = ids[0].as_string().ok_or(Error::Malformed)?;
    // A native query may omit optional content; it cannot establish presence in that case.
    Ok(presence(report, bundle).ok())
}
