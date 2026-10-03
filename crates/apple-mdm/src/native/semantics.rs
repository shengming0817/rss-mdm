//! Native constraints expressed in official prose rather than presence/type schema fields.
//! ref: pinned application.install(.enterprise).yaml and configuration/app.managed.yaml.
use super::{Dictionary, Error, Kind, Value};

pub(super) fn check(kind: Kind, identity: &str, fields: &Dictionary) -> Result<(), Error> {
    match (kind, identity) {
        (Kind::Command, "DeleteUser") => {
            if !fields
                .get("DeleteAllUsers")
                .and_then(Value::as_boolean)
                .unwrap_or(false)
                && fields
                    .get("UserName")
                    .and_then(Value::as_string)
                    .is_none_or(|name| name.trim().is_empty())
            {
                return Err(Error::Constraint);
            }
        }
        (Kind::Command, "InstallApplication") => {
            exactly_one(fields, &["iTunesStoreID", "Identifier", "ManifestURL"])?;
            if let Some(value) = fields.get("iTunesStoreID")
                && value.as_unsigned_integer().is_none_or(|id| id == 0)
            {
                return Err(Error::Constraint);
            }
            https(fields, "ManifestURL")?;
        }
        (Kind::Command, "InstallEnterpriseApplication") => {
            exactly_one(fields, &["Manifest", "ManifestURL"])?;
            https(fields, "ManifestURL")?;
        }
        (Kind::Declaration, "com.apple.configuration.app.managed") => {
            exactly_one(
                fields,
                &[
                    "AppStoreID",
                    "BundleID",
                    "ManifestURL",
                    "AppComposedIdentifier",
                ],
            )?;
            https(fields, "ManifestURL")?;
        }
        (
            Kind::Declaration,
            "com.apple.configuration.legacy" | "com.apple.configuration.legacy.interactive",
        ) => {
            exactly_one(fields, &["ProfileURL", "ProfileAssetReference"])?;
            https(fields, "ProfileURL")?;
        }
        (Kind::Declaration, "com.apple.asset.data") => {
            let reference = fields
                .get("Reference")
                .and_then(Value::as_dictionary)
                .ok_or(Error::Field)?;
            https(reference, "DataURL")?;
            if let Some(size) = reference.get("Size") {
                let size = size.as_unsigned_integer().ok_or(Error::Constraint)?;
                if size == 0 && reference.contains_key("Hash-SHA-256") {
                    return Err(Error::Constraint);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn exactly_one(fields: &Dictionary, keys: &[&str]) -> Result<(), Error> {
    let mut selected = keys.iter().filter_map(|key| fields.get(key));
    let value = selected.next().ok_or(Error::Constraint)?;
    if selected.next().is_some() || matches!(value, Value::String(s) if s.trim().is_empty()) {
        return Err(Error::Constraint);
    }
    Ok(())
}

fn https(fields: &Dictionary, key: &str) -> Result<(), Error> {
    let Some(value) = fields.get(key) else {
        return Ok(());
    };
    let url =
        url::Url::parse(value.as_string().ok_or(Error::Field)?).map_err(|_| Error::Constraint)?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(Error::Constraint);
    }
    Ok(())
}
