//! Sequential durable upload frontier; unacknowledged file tails are discarded on resume.
use super::*;
use rss_mdm_resource::{Digest as ResourceDigest, Id};
use std::io::Write;
use uuid::Uuid;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadBinding {
    pub resource: String,
    pub version: String,
    pub variant: String,
    pub platform: rss_mdm_resource::Platform,
    pub architecture: rss_mdm_resource::Architecture,
    pub resource_digest: [u8; 32],
    pub source: Option<rss_mdm_resource::SoftwareSource>,
    pub origin: Option<String>,
    pub reference: String,
    pub length: u64,
    pub sha256: [u8; 32],
    pub actor: String,
}
impl UploadBinding {
    pub fn artifact(&self) -> Result<Artifact, Error> {
        Artifact::new(
            Id::new(&self.reference).map_err(|_| Error::Malformed)?,
            self.length,
            ResourceDigest::from_bytes(self.sha256),
        )
        .map_err(|_| Error::Malformed)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upload {
    pub id: Uuid,
    pub binding: UploadBinding,
    pub offset: u64,
    pub expires: i64,
    pub complete: bool,
}
pub(super) fn storage_key(actor: &str, id: Uuid) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"rss-mdm.upload/v1\0");
    digest.update(actor.as_bytes());
    digest.update(id.as_bytes());
    let digest = digest.finalize();
    Uuid::from_bytes(digest[..16].try_into().expect("digest prefix"))
}
impl Upload {
    fn storage_key(&self) -> Uuid {
        storage_key(&self.binding.actor, self.id)
    }
}
impl Store {
    pub(super) fn upload_path(&self, id: Uuid, extension: &str) -> PathBuf {
        self.directory.join(format!(".upload-{id}.{extension}"))
    }
    pub(super) fn load_upload(&self, id: Uuid, now: i64) -> Result<Upload, Error> {
        let path = self.upload_path(id, "json");
        regular(&path)?;
        let file = options().open(path).map_err(|_| Error::Metadata)?;
        if file.metadata().map_err(|_| Error::Metadata)?.len() > 16_384 {
            return Err(Error::Metadata);
        }
        let upload: Upload = serde_json::from_reader(file).map_err(|_| Error::Metadata)?;
        if upload.storage_key() != id || upload.expires <= now {
            return Err(Error::Conflict);
        }
        Ok(upload)
    }
    fn save_upload(&self, upload: &Upload) -> Result<(), Error> {
        let temporary = self.upload_path(upload.storage_key(), "next");
        let mut file = options()
            .create(true)
            .truncate(true)
            .open(&temporary)
            .map_err(|_| storage())?;
        serde_json::to_writer(&mut file, upload).map_err(|_| storage())?;
        file.flush().map_err(|_| storage())?;
        file.sync_all().map_err(|_| storage())?;
        fs::rename(temporary, self.upload_path(upload.storage_key(), "json"))
            .map_err(|_| storage())?;
        sync_dir(&self.directory)
    }
    pub async fn begin(
        self: &Arc<Self>,
        id: Uuid,
        binding: UploadBinding,
        now: i64,
    ) -> Result<Upload, Error> {
        if id.is_nil()
            || binding.actor.is_empty()
            || binding.actor.len() > 1024
            || binding.length > self.config.max_artifact_bytes
        {
            return Err(Error::Malformed);
        }
        binding.artifact()?;
        let key = storage_key(&binding.actor, id);
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let _lock = lock(&store.directory.join(".upload.lock"))?;
            store.clean_partials_locked(now)?;
            if store.upload_path(key, "json").exists() {
                let old = store.load_upload(key, now)?;
                if old.binding != binding {
                    return Err(Error::Conflict);
                }
                return Ok(old);
            }
            let (reserved, count) = store.temporary_usage_locked()?;
            if count >= store.config.max_uploads
                || reserved
                    .checked_add(binding.length)
                    .is_none_or(|n| n > store.config.max_temporary_bytes)
            {
                return Err(Error::Conflict);
            }
            let upload = Upload {
                id,
                binding,
                offset: 0,
                expires: now
                    .checked_add(store.config.retention_seconds as i64)
                    .ok_or(Error::Malformed)?,
                complete: false,
            };
            let file = options()
                .create(true)
                .truncate(true)
                .open(store.upload_path(key, "part"))
                .map_err(|_| storage())?;
            file.sync_all().map_err(|_| storage())?;
            store.save_upload(&upload)?;
            Ok(upload)
        })
        .await
        .map_err(|_| storage())?
    }
    pub async fn status(
        self: &Arc<Self>,
        actor: &str,
        id: Uuid,
        now: i64,
    ) -> Result<Upload, Error> {
        let id = storage_key(actor, id);
        let s = self.clone();
        tokio::task::spawn_blocking(move || s.load_upload(id, now))
            .await
            .map_err(|_| storage())?
    }
    pub async fn append<R>(
        self: &Arc<Self>,
        actor: &str,
        id: Uuid,
        expected: u64,
        now: i64,
        mut body: R,
    ) -> Result<Upload, Error>
    where
        R: tokio::io::AsyncRead + Unpin + Send,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _permit = self
            .transfers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Conflict)?;
        let id = storage_key(actor, id);
        let s = self.clone();
        let (mut upload, file) = tokio::task::spawn_blocking(move || {
            let file = lock(&s.upload_path(id, "part"))?;
            let upload = s.load_upload(id, now)?;
            if upload.complete || upload.offset != expected {
                return Err(Error::Conflict);
            }
            if file.metadata().map_err(|_| storage())?.len() < expected {
                return Err(invariant());
            }
            file.set_len(expected).map_err(|_| storage())?;
            let mut file = file;
            file.seek(SeekFrom::Start(expected))
                .map_err(|_| storage())?;
            Ok((upload, file))
        })
        .await
        .map_err(|_| storage())??;
        let mut file = tokio::fs::File::from_std(file);
        tokio::time::timeout(
            std::time::Duration::from_secs(self.config.transfer_seconds),
            async {
                let mut buffer = [0u8; 65_536];
                let start = upload.offset;
                loop {
                    let n = body.read(&mut buffer).await.map_err(|_| storage())?;
                    if n == 0 {
                        break;
                    }
                    upload.offset = upload
                        .offset
                        .checked_add(n as u64)
                        .ok_or(Error::Malformed)?;
                    if upload.offset > upload.binding.length {
                        return Err(Error::Malformed);
                    }
                    file.write_all(&buffer[..n]).await.map_err(|_| storage())?;
                }
                if upload.offset == start {
                    return Err(Error::Malformed);
                }
                file.flush().await.map_err(|_| storage())?;
                file.sync_all().await.map_err(|_| storage())?;
                let s = self.clone();
                let value = upload.clone();
                let guard = file.into_std().await;
                tokio::task::spawn_blocking(move || {
                    let _guard = guard;
                    s.save_upload(&value)
                })
                .await
                .map_err(|_| storage())??;
                Ok(upload)
            },
        )
        .await
        .map_err(|_| Error::Deadline)?
    }
    pub async fn finish(
        self: &Arc<Self>,
        actor: &str,
        id: Uuid,
        now: i64,
    ) -> Result<Upload, Error> {
        let id = storage_key(actor, id);
        let s = self.clone();
        let deadline = self.deadline()?;
        let permit = self
            .transfers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Conflict)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let old = s.load_upload(id, now)?;
            if old.complete {
                s.verify_sync(&old.binding.artifact()?, deadline)?;
                return Ok(old);
            }
            let mut file = lock(&s.upload_path(id, "part"))?;
            let mut upload = s.load_upload(id, now)?;
            let artifact = upload.binding.artifact()?;
            if upload.complete {
                s.verify_sync(&artifact, deadline)?;
                return Ok(upload);
            }
            let _blob = lock(&s.blob_lock(artifact.digest().bytes()))?;
            if upload.offset != upload.binding.length {
                return Err(Error::Conflict);
            }
            verify_file(&mut file, &artifact, s.timer.as_ref(), deadline)
                .map_err(|_| Error::Malformed)?;
            file.sync_all().map_err(|_| storage())?;
            match fs::hard_link(s.upload_path(id, "part"), s.path(&artifact)) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let mut existing = options().open(s.path(&artifact)).map_err(|_| storage())?;
                    verify_file(&mut existing, &artifact, s.timer.as_ref(), deadline)?;
                }
                Err(_) => return Err(storage()),
            }
            sync_dir(&s.directory)?;
            upload.complete = true;
            s.save_upload(&upload)?;
            fs::remove_file(s.upload_path(id, "part")).map_err(|_| storage())?;
            sync_dir(&s.directory)?;
            Ok(upload)
        })
        .await
        .map_err(|_| storage())?
    }
}
pub use UploadBinding as Binding;

impl Store {
    // Called only while holding the existing cross-process upload reservation lock.
    fn temporary_usage_locked(&self) -> Result<(u64, usize), Error> {
        let mut reserved = 0u64;
        let mut count = 0usize;
        for entry in fs::read_dir(&self.directory).map_err(|_| storage())? {
            let entry = entry.map_err(|_| storage())?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(raw) = name
                .strip_prefix(".upload-")
                .and_then(|s| s.strip_suffix(".json"))
            else {
                continue;
            };
            let Ok(other) = Uuid::parse_str(raw) else {
                continue;
            };
            // Expired uploads still occupy space until explicitly reclaimed.
            let value = self.load_upload(other, i64::MIN)?;
            if !value.complete || self.upload_path(other, "part").exists() {
                reserved = reserved
                    .checked_add(value.binding.length)
                    .ok_or_else(invariant)?;
                count += 1;
            }
        }
        Ok((reserved, count))
    }
    pub(super) fn native_temporary_space(&self, bytes: u64) -> Result<File, Error> {
        let guard = lock(&self.directory.join(".upload.lock"))?;
        let (reserved, _) = self.temporary_usage_locked()?;
        if reserved
            .checked_add(bytes)
            .is_none_or(|value| value > self.config.max_temporary_bytes)
        {
            return Err(Error::Conflict);
        }
        // Holding this lock makes simultaneous nested verification and new uploads
        // obey the same disk budget, including other Store handles and processes.
        Ok(guard)
    }
}
