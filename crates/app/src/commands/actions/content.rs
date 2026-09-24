//! Local immutable artifacts and signing authority, with no URL or ambient download grant.
use crate::{ConfigIssue, Error, Failure};
use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rss_mdm_agent_wire::{SignedTask, TaskPayload};
use rss_mdm_resource::Artifact;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
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
fn storage() -> Error {
    Error::Unavailable(Failure::CommandStorage)
}
fn invariant() -> Error {
    Error::Unavailable(Failure::CommandInvariant)
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
        Self::clean_uploads(&directory)?;
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
        Self::with_lock(&self.directory, || {
            Self::clean_uploads_locked(&self.directory)?;
            let final_path = self.path(artifact);
            if final_path.exists() {
                self.read(artifact)?;
                return Ok(());
            }
            let temporary = self
                .directory
                .join(format!(".upload-{}", uuid::Uuid::new_v4()));
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let outcome = (|| {
                let mut file = options.open(&temporary).map_err(|_| storage())?;
                file.write_all(bytes).map_err(|_| storage())?;
                file.sync_all().map_err(|_| storage())?;
                match fs::hard_link(&temporary, &final_path) {
                    Ok(()) => (),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        self.read(artifact)?;
                    }
                    Err(_) => return Err(storage()),
                }
                Ok(())
            })();
            let cleanup = if temporary.exists() {
                fs::remove_file(&temporary).map_err(|_| storage())
            } else {
                Ok(())
            };
            let sync = Self::sync_directory(&self.directory);
            outcome.and(cleanup).and(sync)
        })
    }

    fn with_lock<T>(
        directory: &Path,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        let path = directory.join(".upload.lock");
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(&path).map_err(|_| storage())?;
        if fs::symlink_metadata(path)
            .map_err(|_| storage())?
            .file_type()
            .is_symlink()
        {
            return Err(storage());
        }
        lock.lock().map_err(|_| storage())?;
        let outcome = operation();
        let unlocked = lock.unlock().map_err(|_| storage());
        outcome.and_then(|value| unlocked.map(|()| value))
    }

    fn sync_directory(directory: &Path) -> Result<(), Error> {
        fs::File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| storage())
    }

    fn clean_uploads(directory: &Path) -> Result<(), Error> {
        Self::with_lock(directory, || Self::clean_uploads_locked(directory))
    }

    fn clean_uploads_locked(directory: &Path) -> Result<(), Error> {
        let mut removed = false;
        for entry in fs::read_dir(directory).map_err(|_| storage())? {
            let entry = entry.map_err(|_| storage())?;
            let name = entry.file_name();
            let Some(suffix) = name.to_str().and_then(|name| name.strip_prefix(".upload-")) else {
                continue;
            };
            let Ok(id) = uuid::Uuid::parse_str(suffix) else {
                continue;
            };
            if id.hyphenated().to_string() != suffix
                || !fs::symlink_metadata(entry.path())
                    .map_err(|_| storage())?
                    .file_type()
                    .is_file()
            {
                continue;
            }
            fs::remove_file(entry.path()).map_err(|_| storage())?;
            removed = true;
        }
        if removed {
            Self::sync_directory(directory)?;
        }
        Ok(())
    }
    pub fn read(&self, artifact: &Artifact) -> Result<Vec<u8>, Error> {
        use std::io::Read;
        if artifact.length() > 16_777_216 {
            return Err(Error::Malformed);
        }
        let path = self.path(artifact);
        let metadata = fs::symlink_metadata(&path).map_err(|_| storage())?;
        if !metadata.is_file() || metadata.len() != artifact.length() {
            return Err(invariant());
        }
        let mut file = fs::File::open(path).map_err(|_| storage())?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(artifact.length() + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| storage())?;
        artifact.verify(&bytes).map_err(|_| invariant())?;
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
    use ring::rand::SystemRandom;
    use std::{sync::mpsc, time::Duration};

    fn content(directory: PathBuf) -> Content {
        let key = Ed25519KeyPair::from_pkcs8(
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        Content {
            directory,
            key_id: "test".into(),
            key,
        }
    }

    fn artifact(bytes: &[u8]) -> Artifact {
        Artifact::new(
            rss_mdm_resource::Id::new("artifact").unwrap(),
            bytes.len() as u64,
            rss_mdm_resource::Digest::of(bytes),
        )
        .unwrap()
    }

    #[test]
    fn read_distinguishes_missing_storage_from_corrupt_content() {
        let directory = tempfile::tempdir().unwrap();
        let content = content(directory.path().to_owned());
        let artifact = artifact(b"expected");

        assert!(matches!(
            content.read(&artifact),
            Err(Error::Unavailable(Failure::CommandStorage))
        ));

        fs::write(content.path(&artifact), b"corrupt!").unwrap();
        assert!(matches!(
            content.read(&artifact),
            Err(Error::Unavailable(Failure::CommandInvariant))
        ));
    }

    #[test]
    fn put_reports_runtime_io_as_storage_failure() {
        let directory = tempfile::tempdir().unwrap();
        let content = content(directory.path().join("missing"));
        let bytes = b"content";
        assert!(matches!(
            content.put(&artifact(bytes), bytes),
            Err(Error::Unavailable(Failure::CommandStorage))
        ));
    }

    #[test]
    fn cleanup_waits_for_directory_lock_and_only_removes_owned_uploads() {
        let directory = tempfile::tempdir().unwrap();
        let owned = directory
            .path()
            .join(format!(".upload-{}", uuid::Uuid::new_v4()));
        let unrelated = directory.path().join(".upload-not-a-uuid");
        fs::write(&owned, b"partial").unwrap();
        fs::write(&unrelated, b"keep").unwrap();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.path().join(".upload.lock"))
            .unwrap();
        lock.lock().unwrap();
        let path = directory.path().to_owned();
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || send.send(Content::clean_uploads(&path)).unwrap());
        assert!(matches!(
            receive.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        lock.unlock().unwrap();
        receive
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert!(!owned.exists());
        assert!(unrelated.exists());
    }

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
