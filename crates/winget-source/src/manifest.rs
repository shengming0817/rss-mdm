use crate::*;
use serde_json::{Value, json};
/// Validated result; construction is only possible through the bounded parser.
#[derive(Clone, Eq, PartialEq)]
pub struct Manifest {
    query: Query,
    url: String,
    sha256: [u8; 32],
    document: Value,
}
impl fmt::Debug for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manifest")
            .field("query", &self.query)
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}
impl Manifest {
    pub fn package(&self) -> &str {
        self.query.package()
    }
    pub fn version(&self) -> &str {
        self.query.version()
    }
    pub fn query(&self) -> &Query {
        &self.query
    }
    pub fn artifact_url(&self) -> &str {
        &self.url
    }
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub fn verify_expected_digest(&self, expected: [u8; 32]) -> Result<(), Error> {
        if self.sha256 == expected {
            Ok(())
        } else {
            Err(Error::InvalidDigest)
        }
    }
    /// REST-shaped metadata for a future controlled publisher; performs no write.
    pub fn publication_metadata(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&self.document).map_err(|_| Error::InvalidResponse)
    }
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, Error> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 4096)
        .ok_or(Error::InvalidResponse)
}
fn keys(v: &Value, allowed: &[&str]) -> Result<(), Error> {
    let o = v.as_object().ok_or(Error::InvalidResponse)?;
    if o.keys().any(|k| !allowed.contains(&k.as_str())) {
        Err(Error::Unsupported)
    } else {
        Ok(())
    }
}
fn digest(s: &str) -> Result<[u8; 32], Error> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::InvalidDigest);
    }
    let mut d = [0; 32];
    for (i, b) in d.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| Error::InvalidDigest)?;
    }
    Ok(d)
}
/// Supported 1.0 subset. Unknown behavior is rejected instead of silently discarded.
pub fn parse_manifest(query: &Query, bytes: &[u8]) -> Result<Manifest, Error> {
    if bytes.len() > MAX_RESPONSE {
        return Err(Error::BudgetExceeded);
    }
    let root: Value = serde_json::from_slice(bytes).map_err(|_| Error::InvalidResponse)?;
    keys(&root, &["Data"])?;
    let data = &root["Data"];
    keys(data, &["PackageIdentifier", "Versions"])?;
    if text(data, "PackageIdentifier")? != query.package {
        return Err(Error::IdentityMismatch);
    }
    let versions = data["Versions"].as_array().ok_or(Error::InvalidResponse)?;
    if versions.len() > 256 {
        return Err(Error::BudgetExceeded);
    }
    let mut found = None;
    for version in versions {
        keys(
            version,
            &[
                "PackageVersion",
                "Channel",
                "DefaultLocale",
                "Locales",
                "Installers",
            ],
        )?;
        if text(version, "PackageVersion")? != query.version {
            continue;
        }
        if version
            .get("Channel")
            .is_some_and(|v| v.as_str() != Some(""))
        {
            return Err(Error::Unsupported);
        }
        if version
            .get("Locales")
            .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
        {
            return Err(Error::Unsupported);
        }
        let locale = &version["DefaultLocale"];
        keys(
            locale,
            &[
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
            ],
        )?;
        for key in [
            "PackageLocale",
            "Publisher",
            "PackageName",
            "ShortDescription",
        ] {
            text(locale, key)?;
        }
        let installers = version["Installers"]
            .as_array()
            .ok_or(Error::InvalidResponse)?;
        if installers.len() > 128 {
            return Err(Error::BudgetExceeded);
        }
        for installer in installers {
            keys(
                installer,
                &[
                    "Architecture",
                    "InstallerType",
                    "InstallerIdentifier",
                    "Scope",
                    "InstallerUrl",
                    "InstallerSha256",
                ],
            )?;
            let arch = text(installer, "Architecture")?;
            let ty = text(installer, "InstallerType")?;
            let scope = match installer.get("Scope") {
                None => "unspecified",
                Some(_) => text(installer, "Scope")?,
            };
            let installer_id = installer
                .get("InstallerIdentifier")
                .map(|_| text(installer, "InstallerIdentifier"))
                .transpose()?;
            if let Some(id) = installer_id {
                identity(id)?;
            }
            if !["x64", "arm64"].contains(&arch)
                || !["msi", "exe"].contains(&ty)
                || !["user", "machine", "unspecified"].contains(&scope)
                || (scope == "unspecified" && installer.get("Scope").is_some())
            {
                return Err(Error::Unsupported);
            }
            let url = text(installer, "InstallerUrl")?;
            safe_url(url)?;
            let sha = digest(text(installer, "InstallerSha256")?)?;
            if arch != query.architecture.as_str()
                || ty != query.installer.as_str()
                || scope != query.scope.as_str()
                || query
                    .installer_id
                    .as_deref()
                    .is_some_and(|id| Some(id) != installer_id)
            {
                continue;
            }
            if found.is_some() {
                return Err(Error::Ambiguous);
            }
            let document = json!({"Data":{"PackageIdentifier":query.package,"Versions":[{"PackageVersion":query.version,"Channel":"","DefaultLocale":locale,"Installers":[installer]}]}});
            found = Some(Manifest {
                query: query.clone(),
                url: url.into(),
                sha256: sha,
                document,
            });
        }
    }
    found.ok_or(Error::NotFound)
}
