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
    /// Validated package identifier.
    pub fn package(&self) -> &str {
        self.query.package()
    }
    /// Exact version identifier.
    pub fn version(&self) -> &str {
        self.query.version()
    }
    /// Validated selection identity that produced this manifest.
    pub fn query(&self) -> &Query {
        &self.query
    }
    /// Validated HTTPS artifact URL; the caller still owns artifact download authorization.
    pub fn artifact_url(&self) -> &str {
        &self.url
    }
    /// Expected artifact SHA-256 bytes.
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    /// Require an exact artifact digest match, returning InvalidDigest on mismatch.
    pub fn verify_expected_digest(&self, expected: [u8; 32]) -> Result<(), Error> {
        if self.sha256 == expected {
            Ok(())
        } else {
            Err(Error::InvalidDigest)
        }
    }
    /// POST /packageManifests request body (not the GET response envelope). No write.
    pub(crate) fn checked_publication_metadata(&self) -> Result<Vec<u8>, Error> {
        let mut request = self.document["Data"].clone();
        let version = &mut request["Versions"][0];
        // Empty Channel is common in GET responses, but violates POST minLength=1.
        version
            .as_object_mut()
            .ok_or(Error::InvalidResponse)?
            .remove("Channel");
        let license = text(&version["DefaultLocale"], "License")?;
        if !(3..=512).contains(&license.chars().count()) {
            return Err(Error::InvalidResponse);
        }
        serde_json::to_vec(&request).map_err(|_| Error::InvalidResponse)
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
/// Parse bounded REST 1.0 response metadata and select exactly one installer for `query`.
/// Requires the Data envelope and matching package identity; examines at most 256
/// versions and 128 installers per selected version within [`MAX_RESPONSE`] bytes.
/// Selection matches version, architecture, installer technology, declared scope and
/// optional installer ID. No match returns [`Error::NotFound`]; multiple matches
/// return [`Error::Ambiguous`]. Unsupported selected behavior, malformed fields/JSON,
/// invalid digests, identities and exceeded budgets retain their closed error categories.
/// Artifact URLs must be HTTPS without credentials, query, fragment, whitespace or
/// controls and at most 2048 bytes. No artifact is fetched or authenticated; callers
/// must independently authorize downloads and verify bytes against the expected digest.
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
            .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
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
        validate_locale(locale)?;
        let installers = version["Installers"]
            .as_array()
            .ok_or(Error::InvalidResponse)?;
        if installers.len() > 128 {
            return Err(Error::BudgetExceeded);
        }
        for installer in installers {
            let scope = match installer.get("Scope") {
                None | Some(Value::Null) => Some("unspecified"),
                Some(value) => value.as_str(),
            };
            if installer["Architecture"].as_str() != Some(query.architecture.as_str())
                || installer["InstallerType"].as_str() != Some(query.installer.as_str())
                || scope != Some(query.scope.as_str())
                || query
                    .installer_id
                    .as_deref()
                    .is_some_and(|id| installer["InstallerIdentifier"].as_str() != Some(id))
            {
                continue;
            }
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
            if installer.get("InstallerIdentifier").is_some() {
                identity(text(installer, "InstallerIdentifier")?)?;
            }
            if scope == Some("unspecified") && installer.get("Scope").is_some_and(|s| !s.is_null())
            {
                return Err(Error::Unsupported);
            }
            let url = text(installer, "InstallerUrl")?;
            safe_url(url)?;
            let sha = digest(text(installer, "InstallerSha256")?)?;
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

fn validate_locale(locale: &Value) -> Result<(), Error> {
    for (key, value) in locale.as_object().ok_or(Error::InvalidResponse)? {
        if value.is_null()
            && ![
                "Publisher",
                "PackageName",
                "ShortDescription",
                "License",
                "PackageLocale",
            ]
            .contains(&key.as_str())
        {
            continue;
        }
        if key == "Tags" {
            let tags = value.as_array().ok_or(Error::InvalidResponse)?;
            if tags.len() > 16 {
                return Err(Error::BudgetExceeded);
            }
            let mut seen = std::collections::BTreeSet::new();
            for tag in tags {
                let tag = tag.as_str().ok_or(Error::InvalidResponse)?;
                if tag.is_empty()
                    || tag.chars().count() > 40
                    || tag.chars().any(char::is_whitespace)
                    || !seen.insert(tag)
                {
                    return Err(Error::InvalidResponse);
                }
            }
            continue;
        }
        let value = value.as_str().ok_or(Error::InvalidResponse)?;
        let (min, max) = match key.as_str() {
            "Publisher" | "PackageName" | "Author" => (2, 256),
            "ShortDescription" => (3, 256),
            "License" | "Copyright" => (3, 512),
            "Description" => (3, 10000),
            "PackageLocale" => (2, 20),
            "Moniker" => (1, 40),
            _ => (1, 2048),
        };
        if !(min..=max).contains(&value.chars().count()) || value.chars().any(char::is_control) {
            return Err(Error::InvalidResponse);
        }
        if key.ends_with("Url") {
            safe_url(value)?;
        }
        if key == "Moniker" && value.chars().any(char::is_whitespace) {
            return Err(Error::InvalidResponse);
        }
        if key == "PackageLocale" {
            let parts: Vec<_> = value.split('-').collect();
            if parts[0].len() != 2
                || !parts[0].bytes().all(|b| b.is_ascii_alphabetic())
                || parts[1..].iter().any(|p| {
                    p.is_empty() || p.len() > 8 || !p.bytes().all(|b| b.is_ascii_alphabetic())
                })
            {
                return Err(Error::Unsupported);
            }
        }
    }
    Ok(())
}
