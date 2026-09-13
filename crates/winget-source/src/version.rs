//! One complete version is the only publication unit; installer queries remain projections.
use crate::*;
use serde_json::{Value, json};
#[derive(Clone, Eq, PartialEq)]
pub struct VersionManifest {
    tenant: TenantId,
    source: String,
    package: String,
    version: String,
    installers: Vec<Manifest>,
    bytes: Vec<u8>,
}
impl VersionManifest {
    pub fn parse(tenant: TenantId, source: &str, bytes: &[u8]) -> Result<Self, Error> {
        identity(source)?;
        if bytes.len() > MAX_RESPONSE {
            return Err(Error::BudgetExceeded);
        }
        let mut body: Value = serde_json::from_slice(bytes).map_err(|_| Error::InvalidResponse)?;
        let obj = body.as_object().ok_or(Error::InvalidResponse)?;
        if obj.len() != 2 || !obj.contains_key("PackageIdentifier") || !obj.contains_key("Versions")
        {
            return Err(Error::Unsupported);
        }
        let package = body["PackageIdentifier"]
            .as_str()
            .ok_or(Error::InvalidResponse)?
            .to_owned();
        let versions = body["Versions"]
            .as_array()
            .filter(|v| v.len() == 1)
            .ok_or(Error::InvalidResponse)?;
        let version = versions[0]["PackageVersion"]
            .as_str()
            .ok_or(Error::InvalidResponse)?
            .to_owned();
        let raw = versions[0]["Installers"]
            .as_array()
            .filter(|v| !v.is_empty() && v.len() <= 64)
            .ok_or(Error::InvalidResponse)?;
        let envelope =
            serde_json::to_vec(&json!({"Data":body})).map_err(|_| Error::InvalidResponse)?;
        let mut installers = Vec::new();
        for item in raw {
            let architecture = match item["Architecture"].as_str() {
                Some("x64") => Architecture::X64,
                Some("arm64") => Architecture::Arm64,
                _ => return Err(Error::Unsupported),
            };
            let installer = match item["InstallerType"].as_str() {
                Some("msi") => InstallerType::Msi,
                Some("exe") => InstallerType::Exe,
                _ => return Err(Error::Unsupported),
            };
            let scope = match item.get("Scope") {
                None | Some(Value::Null) => Scope::Unspecified,
                Some(Value::String(s)) if s == "user" => Scope::User,
                Some(Value::String(s)) if s == "machine" => Scope::Machine,
                _ => return Err(Error::Unsupported),
            };
            let mut query = Query::new(
                tenant,
                source,
                &package,
                &version,
                architecture,
                installer,
                scope,
            )?;
            if let Some(id) = item.get("InstallerIdentifier") {
                query = query.with_installer_id(id.as_str().ok_or(Error::InvalidInput)?)?;
            }
            let manifest = parse_manifest(&query, &envelope)?;
            manifest.checked_publication_metadata()?;
            installers.push(manifest);
        }
        installers.sort_by(|a, b| selection(a.query()).cmp(&selection(b.query())));
        if installers
            .windows(2)
            .any(|w| selection(w[0].query()) == selection(w[1].query()))
        {
            return Err(Error::Ambiguous);
        }
        // Normalize through the validated publication representation; Channel is omitted.
        let normalized: Vec<Value> = installers
            .iter()
            .map(|m| {
                serde_json::from_slice::<Value>(&m.checked_publication_metadata()?)
                    .map_err(|_| Error::InvalidResponse)
            })
            .collect::<Result<_, _>>()?;
        body = normalized[0].clone();
        body["Versions"][0]["Installers"] = Value::Array(
            normalized
                .into_iter()
                .map(|v| v["Versions"][0]["Installers"][0].clone())
                .collect(),
        );
        let bytes = serde_json::to_vec(&body).map_err(|_| Error::InvalidResponse)?;
        Ok(Self {
            tenant,
            source: source.into(),
            package,
            version,
            installers,
            bytes,
        })
    }
    pub fn from_response(tenant: TenantId, source: &str, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_RESPONSE {
            return Err(Error::BudgetExceeded);
        }
        let v: Value = serde_json::from_slice(bytes).map_err(|_| Error::InvalidResponse)?;
        if v.as_object()
            .is_none_or(|o| o.len() != 1 || !o.contains_key("Data"))
        {
            return Err(Error::InvalidResponse);
        }
        Self::parse(
            tenant,
            source,
            &serde_json::to_vec(&v["Data"]).map_err(|_| Error::InvalidResponse)?,
        )
    }
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn package(&self) -> &str {
        &self.package
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn installers(&self) -> &[Manifest] {
        &self.installers
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
fn selection(q: &Query) -> (&str, &str, &str, Option<&str>) {
    (
        q.architecture().as_str(),
        q.installer_type().as_str(),
        q.scope().as_str(),
        q.installer_id(),
    )
}

impl fmt::Debug for VersionManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VersionManifest")
            .field("package", &self.package)
            .field("version", &self.version)
            .field("installers", &self.installers.len())
            .finish_non_exhaustive()
    }
}
