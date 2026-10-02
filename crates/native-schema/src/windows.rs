//! Resolve fixed DDF references against actual Microsoft ADMX source inputs.
mod ddf;
mod generate;
mod learn;
mod policy;
use super::xml::{self, Element};
pub use generate::generate;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

#[derive(Deserialize)]
struct DdfSources {
    files: BTreeMap<String, String>,
}
#[derive(Deserialize, Default)]
struct ReleaseIdentity {
    version: String,
}

#[derive(Deserialize)]
struct AdmxSource {
    #[serde(default)]
    installer: Option<ReleaseIdentity>,
    files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct XsdSources {
    files: BTreeMap<String, String>,
    license_sha256: String,
}

fn verify_xsd(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let root = root.join("schema/upstream/xsd");
    let index: XsdSources = serde_json::from_slice(&fs::read(root.join("source.json"))?)?;
    if format!("{:x}", Sha256::digest(fs::read(root.join("LICENSE.txt"))?)) != index.license_sha256
    {
        return Err("XSD source license has changed".into());
    }
    for (name, hash) in &index.files {
        if Path::new(name).components().count() != 1 {
            return Err("invalid XSD source path".into());
        }
        let bytes = fs::read(root.join(name))?;
        if format!("{:x}", Sha256::digest(&bytes)) != *hash {
            return Err(format!("XSD source has changed: {name}").into());
        }
        let schema = xml::parse(&bytes)?;
        for import in schema.children("import").chain(schema.children("include")) {
            let name = import
                .attributes
                .get("schemaLocation")
                .ok_or("XSD import location missing")?;
            if !index.files.contains_key(name) {
                return Err("XSD import escapes fixed sources".into());
            }
        }
    }
    Ok(())
}

pub struct Sources {
    pub ddf: Vec<(String, Element)>,
    pub learn: BTreeMap<String, learn::Support>,
    pub admx: BTreeMap<String, BTreeSet<String>>,
    pub templates: Vec<(String, u32, u32, Element)>,
}
impl Sources {
    pub fn read(root: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        verify_xsd(root)?;
        let learn = learn::read(root)?;
        let ddf_root = root.join("ddf/upstream");
        let manifest: DdfSources =
            serde_json::from_slice(&fs::read(ddf_root.join("source.json"))?)?;
        if manifest.files.is_empty() {
            return Err("DDF source directory is empty".into());
        }
        let mut ddf = Vec::new();
        for (name, hash) in manifest.files {
            if Path::new(&name).components().count() != 1 {
                return Err("invalid DDF source path".into());
            }
            let bytes = fs::read(ddf_root.join(&name))?;
            if format!("{:x}", Sha256::digest(&bytes)) != hash {
                return Err(format!("DDF source changed: {name}").into());
            }
            let doc = xml::parse(&bytes)?;
            if xml::local(&doc.name) != "MgmtTree" || doc.value("VerDTD") != Some("1.2") {
                return Err(format!("unexpected DDF root: {name}").into());
            }
            ddf.push((name, doc));
        }
        let admx_root = root.join("schema/upstream/admx");
        let releases: Vec<AdmxSource> =
            serde_json::from_slice(&fs::read(admx_root.join("sources.json"))?)?;
        if releases.is_empty() {
            return Err("ADMX source directory is empty".into());
        }
        let mut admx: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut templates = Vec::new();
        for release in releases {
            let (from, until) = match release.installer.as_ref().map(|i| i.version.as_str()) {
                Some("22H2") => (0, 22631),
                Some("23H2") => (22631, 22632),
                Some("24H2") => (26100, 26101),
                Some("25H2") => (26200, 26201),
                Some("26H2") => (26300, 26301),
                // Standalone official supplements are not an OS release fallback.
                None | Some("EAIME-schema-source") => (0, u32::MAX),
                _ => return Err("unmapped official ADMX release".into()),
            };
            for (name, object) in release.files {
                let digest = object.strip_suffix(".admx").ok_or("invalid ADMX object")?;
                if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("invalid ADMX digest".into());
                }
                let bytes = fs::read(admx_root.join("objects").join(&object))?;
                if format!("{:x}", Sha256::digest(&bytes)) != digest {
                    return Err(format!("ADMX source changed: {name}").into());
                }
                let doc = xml::parse(&bytes)?;
                if xml::local(&doc.name) != "policyDefinitions" {
                    return Err(format!("unexpected ADMX root: {name}").into());
                }
                for policy in doc
                    .child("policies")
                    .into_iter()
                    .flat_map(|p| p.children("policy"))
                {
                    admx.entry(name.to_ascii_lowercase()).or_default().insert(
                        policy
                            .attributes
                            .get("name")
                            .ok_or("ADMX policy name missing")?
                            .clone(),
                    );
                }
                templates.push((name.to_ascii_lowercase(), from, until, doc));
            }
        }
        Ok(Self {
            learn,
            ddf,
            admx,
            templates,
        })
    }

    pub fn unresolved_admx(&self) -> BTreeSet<String> {
        fn visit(
            element: &Element,
            policies: &BTreeMap<String, BTreeSet<String>>,
            missing: &mut BTreeSet<String>,
        ) {
            if xml::local(&element.name) == "AdmxBacked" {
                match (
                    element.attributes.get("File"),
                    element.attributes.get("Name"),
                ) {
                    (Some(file), Some(name))
                        if policies
                            .get(&file.to_ascii_lowercase())
                            .is_some_and(|p| p.contains(name)) => {}
                    (Some(file), Some(name)) => {
                        missing.insert(format!("{file}:{name}"));
                    }
                    _ => {
                        missing.insert("invalid AdmxBacked reference".into());
                    }
                }
            }
            for child in &element.children {
                visit(child, policies, missing);
            }
        }
        let mut missing = BTreeSet::new();
        for (_, source) in &self.ddf {
            visit(source, &self.admx, &mut missing);
        }
        missing
    }
}
