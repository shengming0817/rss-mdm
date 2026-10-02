//! Fixed source provenance is checked before any generated production file is written.
use super::yaml::Document;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

#[derive(Deserialize)]
pub struct AppleSources {
    pub repository: String,
    pub releases: Vec<Release>,
}

#[derive(Deserialize)]
pub struct Release {
    pub commit: String,
    pub release: String,
    pub files: BTreeMap<String, String>,
}

pub struct AppleDocument {
    pub path: String,
    pub digest: String,
    pub source: Document,
}

pub fn read_apple(
    root: &Path,
) -> Result<(AppleSources, Vec<AppleDocument>), Box<dyn std::error::Error>> {
    let index: AppleSources = serde_json::from_slice(&fs::read(root.join("sources.json"))?)?;
    if index.repository != "https://github.com/apple/device-management" || index.releases.is_empty()
    {
        return Err("invalid Apple source repository".into());
    }
    let mut documents = Vec::new();
    let mut parsed = BTreeSet::new();
    for release in &index.releases {
        if release.commit.len() != 40 || !release.commit.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("invalid Apple source commit".into());
        }
        if !release.files.contains_key("LICENSE.txt") {
            return Err("source license missing".into());
        }
        for (path, object) in &release.files {
            let (digest, extension) = object.split_once('.').ok_or("invalid source object")?;
            if digest.len() != 64
                || !digest.bytes().all(|c| c.is_ascii_hexdigit())
                || !["yaml", "md", "txt"].contains(&extension)
            {
                return Err("invalid source object identity".into());
            }
            let bytes = fs::read(root.join("objects").join(object))?;
            if format!("{:x}", Sha256::digest(&bytes)) != digest {
                return Err(format!("source digest mismatch: {path}").into());
            }
            if path.ends_with(".yaml")
                && !path.starts_with("docs/")
                && parsed.insert((path.clone(), digest.to_owned()))
            {
                let source = Document::parse(std::str::from_utf8(&bytes)?)
                    .map_err(|e| format!("{path}: {e}"))?;
                documents.push(AppleDocument {
                    path: path.clone(),
                    digest: digest.to_owned(),
                    source,
                });
            }
        }
    }
    Ok((index, documents))
}
