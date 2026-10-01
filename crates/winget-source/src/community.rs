//! Community YAML is not REST JSON. Resolve official field inheritance before selection.
//! ref: microsoft/winget-cli schemas/JSON/manifests/v1.10.0/manifest.installer.1.10.0.json@3119f00ff5be7f34f85e16158dae2f70d1a2ee04
use crate::*;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

const COMMON: &[&str] = &[
    "PackageIdentifier",
    "PackageVersion",
    "ManifestVersion",
    "ManifestType",
];
const INSTALLER: &[&str] = &[
    "InstallerType",
    "Scope",
    "InstallerSwitches",
    "InstallerSuccessCodes",
    "ProductCode",
    "Dependencies",
    "UpgradeBehavior",
    "MinimumOSVersion",
];
const LOCALE: &[&str] = &[
    "PackageLocale",
    "Publisher",
    "PublisherUrl",
    "PublisherSupportUrl",
    "PrivacyUrl",
    "Author",
    "PackageName",
    "PackageUrl",
    "License",
    "LicenseUrl",
    "Copyright",
    "CopyrightUrl",
    "ShortDescription",
    "Description",
    "Moniker",
    "Tags",
];

/// Precisely selected normalized installer plus the original complete YAML file set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityManifest {
    manifest: Manifest,
    originals: BTreeMap<String, Vec<u8>>,
}
impl CommunityManifest {
    /// Parse either singleton or complete version/installer/defaultLocale materials.
    /// Input is bounded and every recognized file is retained. Unknown behavior/roles are rejected.
    pub fn parse(query: &Query, files: &[(String, Vec<u8>)]) -> Result<Self, Error> {
        if files.is_empty()
            || files.len() > 16
            || files.iter().map(|(_, b)| b.len()).sum::<usize>() > MAX_RESPONSE
        {
            return Err(Error::BudgetExceeded);
        }
        let mut originals = BTreeMap::new();
        let mut roles = BTreeMap::new();
        for (path, bytes) in files {
            if path.is_empty()
                || path.len() > 1024
                || path.contains(['\\', ':'])
                || path
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == "..")
            {
                return Err(Error::InvalidInput);
            }
            if originals.insert(path.clone(), bytes.clone()).is_some() {
                return Err(Error::Ambiguous);
            }
            let value = read(query, bytes)?;
            let role = value["ManifestType"]
                .as_str()
                .ok_or(Error::InvalidResponse)?
                .to_owned();
            if roles.insert(role, value).is_some() {
                return Err(Error::Ambiguous);
            }
        }
        let (installer, locale) = documents(roles)?;
        let installers = inherited(&installer)?;
        let response = json!({"Data":{"PackageIdentifier":query.package(),"Versions":[{"PackageVersion":query.version(),"Channel":"","DefaultLocale":locale,"Installers":installers}]}});
        let bytes = serde_json::to_vec(&response).map_err(|_| Error::InvalidResponse)?;
        Ok(Self {
            manifest: parse_manifest(query, &bytes)?,
            originals,
        })
    }
    /// Complete selected installer and behavior, not just URL/hash.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    /// Credential-free original bytes retained for product provenance and approval.
    pub fn originals(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.originals
    }
}
fn deny_tags(v: &serde_yaml_ng::Value) -> Result<(), Error> {
    use serde_yaml_ng::Value as Y;
    match v {
        Y::Tagged(_) => Err(Error::Unsupported),
        Y::Sequence(values) => {
            for value in values {
                deny_tags(value)?;
            }
            Ok(())
        }
        Y::Mapping(values) => {
            for (key, value) in values {
                deny_tags(key)?;
                deny_tags(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
fn read(query: &Query, bytes: &[u8]) -> Result<Value, Error> {
    let yaml: serde_yaml_ng::Value =
        serde_yaml_ng::from_slice(bytes).map_err(|_| Error::InvalidResponse)?;
    deny_tags(&yaml)?;
    let value = serde_json::to_value(yaml).map_err(|_| Error::InvalidResponse)?;
    if value["PackageIdentifier"].as_str() != Some(query.package())
        || value["PackageVersion"].as_str() != Some(query.version())
    {
        return Err(Error::IdentityMismatch);
    }
    if value["ManifestVersion"].as_str() != Some("1.10.0") {
        return Err(Error::Unsupported);
    }
    let fields = value.as_object().ok_or(Error::InvalidResponse)?;
    let role = value["ManifestType"]
        .as_str()
        .ok_or(Error::InvalidResponse)?;
    let allowed = match role {
        "singleton" => [COMMON, INSTALLER, LOCALE, &["Installers"]].concat(),
        "version" => [COMMON, &["DefaultLocale"]].concat(),
        "installer" => [COMMON, INSTALLER, &["Installers"]].concat(),
        "defaultLocale" => [COMMON, LOCALE].concat(),
        _ => return Err(Error::Unsupported),
    };
    if fields.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(Error::Unsupported);
    }
    Ok(value)
}
fn locale(value: &Value) -> Result<Value, Error> {
    let object = value.as_object().ok_or(Error::InvalidResponse)?;
    Ok(Value::Object(
        object
            .iter()
            .filter(|(key, _)| LOCALE.contains(&key.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    ))
}
fn documents(mut roles: BTreeMap<String, Value>) -> Result<(Value, Value), Error> {
    if let Some(single) = roles.remove("singleton") {
        if !roles.is_empty() {
            return Err(Error::Ambiguous);
        }
        return Ok((single.clone(), locale(&single)?));
    }
    let version = roles.remove("version").ok_or(Error::InvalidResponse)?;
    let installers = roles.remove("installer").ok_or(Error::InvalidResponse)?;
    let default = roles
        .remove("defaultLocale")
        .ok_or(Error::InvalidResponse)?;
    if !roles.is_empty() || version["DefaultLocale"] != default["PackageLocale"] {
        return Err(Error::Unsupported);
    }
    Ok((installers, locale(&default)?))
}
fn inherited(value: &Value) -> Result<Vec<Value>, Error> {
    let candidates = value["Installers"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 128)
        .ok_or(Error::InvalidResponse)?;
    let mut output = Vec::new();
    for candidate in candidates {
        let fields = candidate.as_object().ok_or(Error::InvalidResponse)?;
        let mut effective: Map<String, Value> = INSTALLER
            .iter()
            .filter_map(|k| value.get(k).map(|v| ((*k).to_owned(), v.clone())))
            .collect();
        for (key, v) in fields {
            effective.insert(key.clone(), v.clone());
        }
        output.push(Value::Object(effective));
    }
    Ok(output)
}
