//! One tenant-scoped immutable store. No signing keys, task authority, or implicit grants.
//! ref: axum axum-v0.8.9/examples/stream-to-file/src/main.rs
mod range;
pub(crate) use range::range;
mod bundle;
mod cleanup;
mod event;
pub(crate) mod http;
#[cfg(test)]
mod tests;
mod upload;
use crate::{ConfigIssue, Error, Failure};
use rss_mdm_resource::Artifact;
use rss_request_context::{Clock, Deadline};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub directory: PathBuf,
    pub imports: std::collections::BTreeMap<
        String,
        Vec<rss_mdm_software_service::publication::ArtifactOrigin>,
    >,
    pub max_artifact_bytes: u64,
    pub max_temporary_bytes: u64,
    pub max_uploads: usize,
    pub transfer_seconds: u64,
    pub retention_seconds: u64,
    pub max_bundle_bytes: u64,
    pub max_bundle_entries: usize,
    pub max_expansion_ratio: u64,
}
pub(crate) struct Store {
    directory: PathBuf,
    pub(crate) config: Config,
    transfers: Arc<Semaphore>,
    timer: Arc<dyn Clock>,
}
fn storage() -> Error {
    Error::Unavailable(Failure::CommandStorage)
}
fn invariant() -> Error {
    Error::Unavailable(Failure::CommandInvariant)
}
fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn regular(path: &Path) -> Result<(), Error> {
    if !fs::symlink_metadata(path).map_err(|_| storage())?.is_file() {
        return Err(invariant());
    }
    Ok(())
}
fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
}
fn lock(path: &Path) -> Result<File, Error> {
    let file = options()
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|_| storage())?;
    regular(path)?;
    file.try_lock().map_err(|_| Error::Conflict)?;
    Ok(file)
}
fn sync_dir(path: &Path) -> Result<(), Error> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| storage())
}
/// A shared file lock stays alive until the response body is dropped.
pub(crate) struct Verified {
    pub(crate) file: File,
    pub(crate) artifact: Artifact,
    _guard: File,
    _permit: Option<OwnedSemaphorePermit>,
    deadline: Deadline,
}
impl Verified {
    pub(crate) fn matches(&self, artifact: &Artifact) -> bool {
        &self.artifact == artifact
    }
    pub(crate) fn etag(&self) -> String {
        format!("\"{}\"", hex(self.artifact.digest().bytes()))
    }
    pub(crate) async fn body(mut self, start: u64, end: u64) -> Result<axum::body::Body, Error> {
        use futures::StreamExt;
        use tokio::io::AsyncReadExt;
        if start >= end || end > self.artifact.length() {
            return Err(Error::Malformed);
        }
        self.file
            .seek(SeekFrom::Start(start))
            .map_err(|_| storage())?;
        let file = tokio::fs::File::from_std(self.file);
        let guard = self._guard;
        let permit = self._permit;
        let cutoff = self.deadline;
        let reader = tokio_util::io::ReaderStream::with_capacity(file.take(end - start), 65_536);
        let stream = futures::stream::unfold(
            (reader, false, guard, permit),
            move |(mut reader, done, guard, permit)| async move {
                if done {
                    return None;
                }
                match tokio::time::timeout_at(cutoff.instant().into(), reader.next()).await {
                    Ok(Some(chunk)) => Some((chunk, (reader, false, guard, permit))),
                    Ok(None) => None,
                    Err(_) => Some((
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "content transfer deadline",
                        )),
                        (reader, true, guard, permit),
                    )),
                }
            },
        );
        Ok(axum::body::Body::from_stream(stream))
    }
}
impl Store {
    pub(crate) fn open(
        config: &Config,
        tenant: &str,
        timer: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, Error> {
        let bad = || Error::Configuration(ConfigIssue::Execution);
        let tenant = rss_request_context::TenantId::parse(tenant)
            .map_err(|_| bad())?
            .to_string();
        if !config.directory.is_absolute()
            || !config.directory.is_dir()
            || fs::symlink_metadata(&config.directory)
                .map_err(|_| bad())?
                .file_type()
                .is_symlink()
            || config.max_artifact_bytes == 0
            || config.max_artifact_bytes > 1_099_511_627_776
            || config.max_temporary_bytes < config.max_artifact_bytes
            || config.max_temporary_bytes > 17_592_186_044_416
            || !(1..=64).contains(&config.max_uploads)
            || !(1..=86400).contains(&config.transfer_seconds)
            || !(config.transfer_seconds..=604800).contains(&config.retention_seconds)
            || config.max_bundle_bytes == 0
            || config.max_bundle_bytes > 1_099_511_627_776
            || !(1..=4096).contains(&config.max_bundle_entries)
            || !(1..=1000).contains(&config.max_expansion_ratio)
        {
            return Err(bad());
        }
        if config.imports.len() > 16 {
            return Err(bad());
        }
        for (source, origins) in &config.imports {
            rss_mdm_resource::Id::new(source).map_err(|_| bad())?;
            rss_mdm_software_service::publication::ArtifactReader::new(
                origins.clone(),
                config.max_artifact_bytes,
                std::time::Duration::from_secs(config.transfer_seconds.min(3600)),
            )
            .map_err(|_| bad())?;
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
        Ok(Arc::new(Self {
            directory,
            config: config.clone(),
            transfers: Arc::new(Semaphore::new(config.max_uploads)),
            timer,
        }))
    }
    fn blob_lock(&self, digest: [u8; 32]) -> PathBuf {
        self.directory.join(format!(".blob-{}.lock", hex(digest)))
    }
    fn path(&self, a: &Artifact) -> PathBuf {
        self.directory.join(hex(a.digest().bytes()))
    }
    fn deadline(&self) -> Result<Deadline, Error> {
        Deadline::from_timeout(
            self.timer.as_ref(),
            std::time::Duration::from_secs(self.config.transfer_seconds),
        )
        .map_err(|_| storage())
    }
    pub(crate) async fn verify(self: &Arc<Self>, artifact: &Artifact) -> Result<Verified, Error> {
        let store = self.clone();
        let artifact = artifact.clone();
        let permit = self
            .transfers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Conflict)?;
        let deadline = self.deadline()?;
        tokio::task::spawn_blocking(move || {
            let mut verified = store.verify_sync(&artifact, deadline)?;
            verified._permit = Some(permit);
            Ok(verified)
        })
        .await
        .map_err(|_| storage())?
    }
    fn verify_sync(&self, artifact: &Artifact, deadline: Deadline) -> Result<Verified, Error> {
        if artifact.length() > self.config.max_artifact_bytes {
            return Err(Error::Malformed);
        }
        let guard = options()
            .create(true)
            .truncate(false)
            .open(self.blob_lock(artifact.digest().bytes()))
            .map_err(|_| storage())?;
        guard.try_lock_shared().map_err(|_| Error::Conflict)?;
        let path = self.path(artifact);
        regular(&path)?;
        let mut opts = OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = opts.open(&path).map_err(|_| storage())?;
        verify_file(&mut file, artifact, self.timer.as_ref(), deadline)?;
        Ok(Verified {
            file,
            artifact: artifact.clone(),
            _guard: guard,
            _permit: None,
            deadline,
        })
    }
}
fn verify_file(
    file: &mut File,
    artifact: &Artifact,
    timer: &dyn Clock,
    deadline: Deadline,
) -> Result<(), Error> {
    if !file.metadata().map_err(|_| storage())?.is_file()
        || file.metadata().map_err(|_| storage())?.len() != artifact.length()
    {
        return Err(invariant());
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| storage())?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65_536];
    let mut count = 0u64;
    loop {
        if timer.now() >= deadline.instant() {
            return Err(storage());
        }
        let n = file.read(&mut buffer).map_err(|_| storage())?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).ok_or_else(invariant)?;
        if count > artifact.length() {
            return Err(invariant());
        }
        hash.update(&buffer[..n]);
    }
    if count != artifact.length() || hash.finalize().as_slice() != artifact.digest().bytes() {
        return Err(invariant());
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| storage())?;
    Ok(())
}
pub(crate) use upload::{Binding, Upload};
