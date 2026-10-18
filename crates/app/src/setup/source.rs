//! Exact V4 source qualification; candidate integrity does not replace trusted artifact distribution.
use super::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::Path};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Supported {
    source_revision: String,
    candidate_format_version: u8,
    inputs_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    inputs_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    file: String,
    sha256: String,
    manifest_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    format_version: u8,
    source: Source,
    version: String,
    platform: String,
    migrations: serde_json::Value,
    image: String,
    archive: Archive,
    providers: BTreeMap<String, String>,
    deployment: BTreeMap<String, String>,
    ui: Option<serde_json::Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    pub source_revision: String,
    pub inputs_sha256: String,
    pub manifest_sha256: String,
    pub archive_sha256: String,
}
fn supported() -> Supported {
    serde_json::from_str(include_str!(
        "../../../../fixtures/installation-source-v4.json"
    ))
    .expect("fixed source contract")
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate(bytes: &[u8], expected: &str) -> Result<(Candidate, Evidence)> {
    if !digest(expected) || format!("{:x}", Sha256::digest(bytes)) != expected {
        return Err(Error::Conflict);
    }
    let candidate: Candidate = serde_json::from_slice(bytes).map_err(|_| Error::Input)?;
    let source = supported();
    if candidate.format_version != source.candidate_format_version
        || candidate.source.inputs_sha256 != source.inputs_sha256
        || candidate.migrations != crate::migration::source_manifest()
        || candidate.archive.file != "server.oci.tar"
        || !digest(&candidate.archive.sha256)
        || !candidate
            .archive
            .manifest_digest
            .strip_prefix("sha256:")
            .is_some_and(digest)
        || !candidate
            .image
            .ends_with(&format!("@{}", candidate.archive.manifest_digest))
        || !candidate.platform.starts_with("linux/")
        || !candidate.version.starts_with("rss-mdm ")
        || candidate.providers.is_empty()
        || candidate.deployment.is_empty()
    {
        return Err(Error::Conflict);
    }
    let evidence = Evidence {
        source_revision: source.source_revision,
        inputs_sha256: source.inputs_sha256,
        manifest_sha256: expected.into(),
        archive_sha256: candidate.archive.sha256.clone(),
    };
    Ok((candidate, evidence))
}
fn file_hash(path: &Path) -> Result<String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Error::Input)?;
    let metadata = file.metadata().map_err(|_| Error::Input)?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 * 1024 {
        return Err(Error::Input);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|_| Error::Storage)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
/// Expected manifest hash comes from the operator's trusted release record, not the manifest itself.
pub fn qualify(directory: &Path, expected_manifest_sha256: &str) -> Result<Evidence> {
    let directory = directory.canonicalize().map_err(|_| Error::Input)?;
    let bytes = crate::config::read(&directory.join("candidate.json"), 1024 * 1024, false)
        .map_err(|_| Error::Input)?;
    let (candidate, evidence) = validate(&bytes, expected_manifest_sha256)?;
    if file_hash(&directory.join(&candidate.archive.file))? != candidate.archive.sha256 {
        return Err(Error::Conflict);
    }
    for (name, expected) in candidate.deployment {
        let relative = Path::new(&name);
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
            || !digest(&expected)
        {
            return Err(Error::Input);
        }
        let path = directory.join(relative);
        let canonical = path.canonicalize().map_err(|_| Error::Input)?;
        if canonical != path || !canonical.starts_with(&directory) || file_hash(&path)? != expected
        {
            return Err(Error::Conflict);
        }
    }
    // Optional UI is not a migration authority; source qualification concerns the server candidate.
    let _ = candidate.ui;
    Ok(evidence)
}
pub(crate) fn admitted(revision: &str, inputs: &str) -> bool {
    let source = supported();
    revision == source.source_revision && inputs == source.inputs_sha256
}

#[cfg(test)]
#[path = "../../tests/setup/source.rs"]
mod tests;
