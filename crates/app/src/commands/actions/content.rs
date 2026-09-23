//! Local immutable artifacts and signing authority, with no URL or ambient download grant.
use crate::{ConfigIssue, Error};
use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rss_mdm_agent_wire::{SignedTask, TaskPayload};
use rss_mdm_resource::Artifact;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub directory: PathBuf,
    pub private_key_file: PathBuf,
    pub key_id: String,
    pub trusted_keys: BTreeMap<String, String>,
}
pub(in crate::commands) struct Content {
    directory: PathBuf,
    key_id: String,
    key: Ed25519KeyPair,
}
fn bad() -> Error {
    Error::Configuration(ConfigIssue::Commands)
}
impl Content {
    pub fn open(config: &Config, tenant: &str) -> Result<Self, Error> {
        if config.trusted_keys.is_empty()
            || config.trusted_keys.len() > 16
            || config.trusted_keys.iter().any(|(id, key)| {
                id.is_empty()
                    || id.len() > 128
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    || base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(key)
                        .map_or(true, |key| key.len() != 32)
            })
            || config.key_id.is_empty()
            || config.key_id.len() > 128
            || !config.directory.is_absolute()
            || !config.directory.is_dir()
            || fs::symlink_metadata(&config.directory)
                .map_err(|_| bad())?
                .file_type()
                .is_symlink()
        {
            return Err(bad());
        }
        let private = crate::config::read(&config.private_key_file, 4096, true)?;
        let key = Ed25519KeyPair::from_pkcs8(&private).map_err(|_| bad())?;
        let expected = config.trusted_keys.get(&config.key_id).ok_or_else(bad)?;
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(expected)
            .map_err(|_| bad())?;
        if expected != key.public_key().as_ref() {
            return Err(bad());
        }
        let directory = config.directory.join(tenant);
        fs::create_dir_all(&directory).map_err(|_| bad())?;
        if fs::symlink_metadata(&directory)
            .map_err(|_| bad())?
            .file_type()
            .is_symlink()
        {
            return Err(bad());
        }
        Ok(Self {
            directory,
            key_id: config.key_id.clone(),
            key,
        })
    }
    pub fn sign(&self, payload: TaskPayload) -> Result<SignedTask, Error> {
        let bytes = payload
            .signing_bytes(&self.key_id)
            .map_err(|_| Error::Malformed)?;
        Ok(SignedTask {
            payload,
            key_id: self.key_id.clone(),
            signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(self.key.sign(&bytes).as_ref()),
        })
    }
    fn path(&self, artifact: &Artifact) -> PathBuf {
        self.directory.join(
            artifact
                .digest()
                .bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
    }
    pub fn put(&self, artifact: &Artifact, bytes: &[u8]) -> Result<(), Error> {
        artifact.verify(bytes).map_err(|_| Error::Malformed)?;
        if bytes.len() > 16_777_216 {
            return Err(Error::Malformed);
        }
        let final_path = self.path(artifact);
        if final_path.exists() {
            self.read(artifact)?;
            return Ok(());
        }
        let temporary = self
            .directory
            .join(format!(".upload-{}", uuid::Uuid::new_v4()));
        let outcome = (|| {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary).map_err(|_| bad())?;
            file.write_all(bytes).map_err(|_| bad())?;
            file.sync_all().map_err(|_| bad())?;
            match fs::hard_link(&temporary, &final_path) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    self.read(artifact)?;
                }
                Err(_) => return Err(bad()),
            }
            fs::File::open(&self.directory)
                .and_then(|d| d.sync_all())
                .map_err(|_| bad())?;
            Ok(())
        })();
        let _ = fs::remove_file(temporary);
        outcome
    }
    pub fn read(&self, artifact: &Artifact) -> Result<Vec<u8>, Error> {
        use std::io::Read;
        if artifact.length() > 16_777_216 {
            return Err(Error::Malformed);
        }
        let path = self.path(artifact);
        let metadata = fs::symlink_metadata(&path).map_err(|_| Error::NotFound)?;
        if !metadata.is_file() || metadata.len() != artifact.length() {
            return Err(Error::Conflict);
        }
        let mut file = fs::File::open(path).map_err(|_| Error::NotFound)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(artifact.length() + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| bad())?;
        artifact.verify(&bytes).map_err(|_| Error::Conflict)?;
        Ok(bytes)
    }
}
/// Accept exactly one RFC byte range; no multipart or unsatisfiable normalization.
pub(super) fn range(header: Option<&str>, length: usize) -> Result<(usize, usize), Error> {
    let Some(header) = header else {
        return Ok((0, length));
    };
    let (start, end) = header
        .strip_prefix("bytes=")
        .and_then(|s| s.split_once('-'))
        .ok_or(Error::Malformed)?;
    if length == 0 || start.contains(',') || end.contains(',') {
        return Err(Error::Malformed);
    }
    if start.is_empty() {
        let suffix = end.parse::<usize>().map_err(|_| Error::Malformed)?;
        if suffix == 0 {
            return Err(Error::Malformed);
        }
        return Ok((length.saturating_sub(suffix), length));
    }
    let start = start.parse::<usize>().map_err(|_| Error::Malformed)?;
    let end = if end.is_empty() {
        length
    } else {
        end.parse::<usize>()
            .map_err(|_| Error::Malformed)?
            .checked_add(1)
            .ok_or(Error::Malformed)?
            .min(length)
    };
    if start >= end || start >= length {
        return Err(Error::Malformed);
    }
    Ok((start, end))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn single_range_is_exact_and_rejects_multiple_or_overflow() {
        assert_eq!(range(Some("bytes=2-4"), 10).unwrap(), (2, 5));
        assert_eq!(range(Some("bytes=5-"), 10).unwrap(), (5, 10));
        assert_eq!(range(Some("bytes=-3"), 10).unwrap(), (7, 10));
        for input in [
            "bytes=0-1,3-4",
            "bytes=10-11",
            "bytes=-0",
            "bytes=9-8",
            "bytes=0-18446744073709551615",
        ] {
            assert!(range(Some(input), 10).is_err());
        }
    }
}
