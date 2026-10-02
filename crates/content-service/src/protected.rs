//! Bounded Configuration content. The acknowledged tail lives in the authenticated checkpoint;
//! complete records only append after the committed physical frontier.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
const BLOCK: u64 = 65_536;
const OVERHEAD: u64 = 68;
const NATIVE_LIMIT: u64 = 16 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Checkpoint {
    physical_end: u64,
    tail: Option<String>,
    mac: Vec<u8>,
}
impl Checkpoint {
    pub(super) fn empty() -> Self {
        Self {
            physical_end: 0,
            tail: None,
            mac: vec![],
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Saved {
    upload: Upload,
    storage_class: StorageClass,
    native: Option<Checkpoint>,
}
impl Saved {
    pub(super) fn new(store: &Store, upload: &Upload) -> Result<Self, Error> {
        if serde_json::to_vec(upload)
            .map_err(|_| Error::Metadata)?
            .len()
            > 16_384
        {
            return Err(Error::Metadata);
        }
        let mut native = upload.native.clone();
        if let Some(checkpoint) = &mut native {
            checkpoint.mac = store.checkpoint_mac(upload, checkpoint)?.to_vec();
        }
        Ok(Self {
            upload: upload.clone(),
            storage_class: upload.binding.storage_class,
            native,
        })
    }
    pub(super) fn open(mut self, store: &Store) -> Result<Upload, Error> {
        self.upload.binding.storage_class = self.storage_class;
        match (self.storage_class, &self.native) {
            (StorageClass::Artifact, None) => {}
            (StorageClass::NativeConfiguration, Some(checkpoint)) => {
                reservation(&self.upload.binding)?;
                let expected = store.checkpoint_mac(&self.upload, checkpoint)?;
                if !bool::from(expected.as_slice().ct_eq(&checkpoint.mac))
                    || self.upload.offset > self.upload.binding.length
                    || if self.upload.complete {
                        self.upload.offset != self.upload.binding.length
                            || checkpoint.tail.is_some()
                            || checkpoint.physical_end != encoded_length(self.upload.offset)?
                    } else {
                        checkpoint.physical_end != (self.upload.offset / BLOCK) * (BLOCK + OVERHEAD)
                            || checkpoint.tail.is_some() == self.upload.offset.is_multiple_of(BLOCK)
                    }
                {
                    return Err(Error::Metadata);
                }
            }
            _ => return Err(Error::Metadata),
        }
        self.upload.native = self.native;
        Ok(self.upload)
    }
}
pub(super) fn reservation(binding: &Binding) -> Result<u64, Error> {
    if binding.storage_class == StorageClass::Artifact {
        return Ok(binding.length);
    }
    if binding.length > NATIVE_LIMIT {
        return Err(Error::Malformed);
    }
    // Both checkpoint files may coexist; the .part and final hard link share an inode.
    let tail = binding
        .length
        .min(BLOCK - 1)
        .checked_add(OVERHEAD)
        .ok_or(Error::Malformed)?;
    let checkpoint = 16_384 + tail.div_ceil(3) * 4;
    encoded_length(binding.length)?
        .checked_add(2 * checkpoint)
        .ok_or(Error::Malformed)
}
fn encoded_length(length: u64) -> Result<u64, Error> {
    length
        .checked_add(
            length
                .div_ceil(BLOCK)
                .checked_mul(OVERHEAD)
                .ok_or(Error::Malformed)?,
        )
        .ok_or(Error::Malformed)
}
fn chunk_aad(
    tenant: rss_request_context::TenantId,
    artifact: &Artifact,
    offset: u64,
    count: u64,
) -> Result<DerivedAad, Error> {
    let owner =
        serde_json::to_string(&(artifact.digest().bytes(), artifact.length(), offset, count))
            .map_err(|_| invariant())?;
    ProtectionContext::new(tenant, &owner, "content.native-configuration.chunk/v1", 1)
        .map(|v| v.derive())
        .map_err(|_| invariant())
}
fn read_records(
    file: &mut File,
    protection: &Protector,
    tenant: rss_request_context::TenantId,
    artifact: &Artifact,
    count: u64,
    timer: &dyn Clock,
    deadline: Deadline,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if artifact.length() > NATIVE_LIMIT || count > artifact.length() {
        return Err(Error::Malformed);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| storage())?;
    let mut output = Zeroizing::new(Vec::with_capacity(count as usize));
    let mut offset = 0;
    while offset < count {
        if timer.now() >= deadline.instant() {
            return Err(Error::Deadline);
        }
        let length = (count - offset).min(BLOCK);
        let mut sealed = vec![0; (length + OVERHEAD) as usize];
        file.read_exact(&mut sealed).map_err(|_| invariant())?;
        let plain = protection
            .open_bytes(&sealed, &chunk_aad(tenant, artifact, offset, length)?)
            .map_err(|_| invariant())?;
        if plain.expose().len() as u64 != length {
            return Err(invariant());
        }
        output.extend_from_slice(plain.expose());
        offset += length;
    }
    Ok(output)
}
fn verify_bytes(bytes: &[u8], artifact: &Artifact) -> Result<(), Error> {
    if bytes.len() as u64 != artifact.length()
        || Sha256::digest(bytes).as_slice() != artifact.digest().bytes()
    {
        return Err(invariant());
    }
    Ok(())
}
impl Store {
    fn checkpoint_mac(&self, upload: &Upload, checkpoint: &Checkpoint) -> Result<[u8; 32], Error> {
        let aad = ProtectionContext::new(
            self.tenant,
            &upload.storage_key().to_string(),
            "content.native-configuration.checkpoint/v1",
            1,
        )
        .map_err(|_| invariant())?
        .derive();
        let bytes = serde_json::to_vec(&(
            StorageClass::NativeConfiguration,
            upload,
            checkpoint.physical_end,
            &checkpoint.tail,
        ))
        .map_err(|_| Error::Metadata)?;
        self.protection
            .mac(&bytes, &aad)
            .map_err(|_| Error::Metadata)
    }
    pub(super) fn path_class(&self, artifact: &Artifact, class: StorageClass) -> PathBuf {
        match class {
            StorageClass::Artifact => self.path(artifact),
            StorageClass::NativeConfiguration => self
                .directory
                .join(format!("native-{}", hex(artifact.digest().bytes()))),
        }
    }
    pub(super) fn class_lock(&self, digest: [u8; 32], class: StorageClass) -> PathBuf {
        match class {
            StorageClass::Artifact => self.blob_lock(digest),
            StorageClass::NativeConfiguration => self
                .directory
                .join(format!(".native-lock-{:02x}", digest[0])),
        }
    }
    fn tail(&self, upload: &Upload) -> Result<Zeroizing<Vec<u8>>, Error> {
        let checkpoint = upload.native.as_ref().ok_or(Error::Metadata)?;
        let length = upload.offset % BLOCK;
        let Some(encoded) = &checkpoint.tail else {
            return if length == 0 {
                Ok(Zeroizing::new(Vec::new()))
            } else {
                Err(Error::Metadata)
            };
        };
        let sealed = STANDARD.decode(encoded).map_err(|_| Error::Metadata)?;
        if sealed.len() as u64 != length + OVERHEAD {
            return Err(Error::Metadata);
        }
        let plain = self
            .protection
            .open_bytes(
                &sealed,
                &chunk_aad(
                    self.tenant,
                    &upload.binding.artifact()?,
                    upload.offset - length,
                    length,
                )?,
            )
            .map_err(|_| Error::Metadata)?;
        if plain.expose().len() as u64 != length {
            return Err(Error::Metadata);
        }
        Ok(Zeroizing::new(plain.expose().to_vec()))
    }
    pub(super) async fn append_native<R: tokio::io::AsyncRead + Unpin + Send>(
        self: &Arc<Self>,
        mut upload: Upload,
        file: File,
        mut body: R,
    ) -> Result<Upload, Error> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        if upload.offset >= upload.binding.length {
            return Err(Error::Conflict);
        }
        let mut buffer = self.tail(&upload)?;
        let frontier = upload.native.as_ref().ok_or(Error::Metadata)?.physical_end;
        if file.metadata().map_err(|_| storage())?.len() < frontier {
            return Err(invariant());
        }
        file.set_len(frontier).map_err(|_| storage())?;
        let mut file = file;
        file.seek(SeekFrom::Start(frontier))
            .map_err(|_| storage())?;
        let mut file = tokio::fs::File::from_std(file);
        let start = upload.offset;
        let artifact = upload.binding.artifact()?;
        tokio::time::timeout(
            std::time::Duration::from_secs(self.config.transfer_seconds),
            async {
                let mut filled = buffer.len();
                buffer.resize(BLOCK as usize, 0);
                loop {
                    let count = body
                        .read(&mut buffer[filled..])
                        .await
                        .map_err(|_| storage())?;
                    if count == 0 {
                        break;
                    }
                    upload.offset = upload
                        .offset
                        .checked_add(count as u64)
                        .ok_or(Error::Malformed)?;
                    if upload.offset > upload.binding.length {
                        return Err(Error::Malformed);
                    }
                    filled += count;
                    if filled == BLOCK as usize {
                        let sealed = self
                            .protection
                            .seal_bytes(
                                &buffer,
                                &chunk_aad(self.tenant, &artifact, upload.offset - BLOCK, BLOCK)?,
                            )
                            .map_err(|_| storage())?;
                        file.write_all(&sealed).await.map_err(|_| storage())?;
                        filled = 0;
                    }
                }
                if upload.offset == start {
                    return Err(Error::Malformed);
                }
                buffer.truncate(filled);
                let tail = if filled == 0 {
                    None
                } else {
                    Some(
                        STANDARD.encode(
                            self.protection
                                .seal_bytes(
                                    &buffer,
                                    &chunk_aad(
                                        self.tenant,
                                        &artifact,
                                        upload.offset - filled as u64,
                                        filled as u64,
                                    )?,
                                )
                                .map_err(|_| storage())?,
                        ),
                    )
                };
                upload.native = Some(Checkpoint {
                    physical_end: (upload.offset / BLOCK) * (BLOCK + OVERHEAD),
                    tail,
                    mac: vec![],
                });
                file.flush().await.map_err(|_| storage())?;
                file.sync_all().await.map_err(|_| storage())?;
                let guard = file.into_std().await;
                let store = self.clone();
                let copy = upload.clone();
                tokio::task::spawn_blocking(move || {
                    let _guard = guard;
                    store.save_upload(&copy)
                })
                .await
                .map_err(|_| storage())??;
                Ok(upload)
            },
        )
        .await
        .map_err(|_| Error::Deadline)?
    }
    pub(super) fn finish_native(
        &self,
        mut upload: Upload,
        mut file: File,
        deadline: Deadline,
    ) -> Result<Upload, Error> {
        use std::io::Write;
        let artifact = upload.binding.artifact()?;
        let class = StorageClass::NativeConfiguration;
        let _blob = lock(&self.class_lock(artifact.digest().bytes(), class))?;
        if upload.offset != artifact.length() {
            return Err(Error::Conflict);
        }
        let checkpoint = upload.native.as_ref().ok_or(Error::Metadata)?;
        if file.metadata().map_err(|_| storage())?.len() < checkpoint.physical_end {
            return Err(invariant());
        }
        let full_length = (upload.offset / BLOCK) * BLOCK;
        let mut bytes = read_records(
            &mut file,
            &self.protection,
            self.tenant,
            &artifact,
            full_length,
            self.timer.as_ref(),
            deadline,
        )?;
        bytes.extend_from_slice(&self.tail(&upload)?);
        verify_bytes(&bytes, &artifact)?;
        let path = self.path_class(&artifact, class);
        if path.exists() {
            // A previous commit-unknown finish may already have linked this very inode.
            // Never truncate it back to the checkpoint frontier.
            regular(&path)?;
            let mut existing = options().open(&path).map_err(|_| storage())?;
            if existing.metadata().map_err(|_| storage())?.len()
                != encoded_length(artifact.length())?
            {
                return Err(invariant());
            }
            let existing = read_records(
                &mut existing,
                &self.protection,
                self.tenant,
                &artifact,
                artifact.length(),
                self.timer.as_ref(),
                deadline,
            )?;
            verify_bytes(&existing, &artifact)?;
        } else {
            file.set_len(checkpoint.physical_end)
                .map_err(|_| storage())?;
            file.seek(SeekFrom::Start(checkpoint.physical_end))
                .map_err(|_| storage())?;
            if let Some(tail) = &checkpoint.tail {
                file.write_all(&STANDARD.decode(tail).map_err(|_| Error::Metadata)?)
                    .map_err(|_| storage())?;
            }
            file.sync_all().map_err(|_| storage())?;
            fs::hard_link(self.upload_path(upload.storage_key(), "part"), &path)
                .map_err(|_| storage())?;
            sync_dir(&self.directory)?;
        }
        upload.complete = true;
        upload.native = Some(Checkpoint {
            physical_end: encoded_length(upload.offset)?,
            tail: None,
            mac: vec![],
        });
        self.save_upload(&upload)?;
        fs::remove_file(self.upload_path(upload.storage_key(), "part")).map_err(|_| storage())?;
        sync_dir(&self.directory)?;
        Ok(upload)
    }
    pub async fn verify_class(
        self: &Arc<Self>,
        artifact: &Artifact,
        class: StorageClass,
    ) -> Result<Verified, Error> {
        if class == StorageClass::Artifact {
            return self.verify(artifact).await;
        }
        let store = self.clone();
        let artifact = artifact.clone();
        let deadline = self.deadline()?;
        let permit = self
            .transfers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Conflict)?;
        tokio::task::spawn_blocking(move || {
            let mut v = store.verify_class_sync(&artifact, class, deadline)?;
            v._permit = Some(permit);
            Ok(v)
        })
        .await
        .map_err(|_| storage())?
    }
    pub(super) fn verify_class_sync(
        &self,
        artifact: &Artifact,
        class: StorageClass,
        deadline: Deadline,
    ) -> Result<Verified, Error> {
        if class == StorageClass::Artifact {
            return self.verify_sync(artifact, deadline);
        }
        if artifact.length() > NATIVE_LIMIT || artifact.length() > self.config.max_artifact_bytes {
            return Err(Error::Malformed);
        }
        let guard = options()
            .create(true)
            .truncate(false)
            .open(self.class_lock(artifact.digest().bytes(), class))
            .map_err(|_| storage())?;
        guard.try_lock_shared().map_err(lock_error)?;
        let path = self.path_class(artifact, class);
        regular(&path)?;
        let file = options().open(path).map_err(|_| storage())?;
        let verified = Verified {
            file,
            native: Some((self.protection.clone(), self.tenant)),
            timer: self.timer.clone(),
            artifact: artifact.clone(),
            _guard: guard,
            _permit: None,
            deadline,
        };
        verified.read_plaintext(NATIVE_LIMIT as usize)?;
        Ok(verified)
    }
}
impl Verified {
    /// Configuration content never becomes a plaintext filesystem object.
    pub fn read_plaintext(&self, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.artifact.length() > limit as u64 {
            return Err(Error::Malformed);
        }
        let mut file = self.file.try_clone().map_err(|_| storage())?;
        if let Some((protection, tenant)) = &self.native {
            if file.metadata().map_err(|_| storage())?.len()
                != encoded_length(self.artifact.length())?
            {
                return Err(invariant());
            }
            let bytes = read_records(
                &mut file,
                protection,
                *tenant,
                &self.artifact,
                self.artifact.length(),
                self.timer.as_ref(),
                self.deadline,
            )?;
            verify_bytes(&bytes, &self.artifact)?;
            Ok(bytes)
        } else {
            verify_file(
                &mut file,
                &self.artifact,
                self.timer.as_ref(),
                self.deadline,
            )?;
            file.seek(SeekFrom::Start(0)).map_err(|_| storage())?;
            let mut bytes = Zeroizing::new(Vec::new());
            file.take(limit as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| storage())?;
            verify_bytes(&bytes, &self.artifact)?;
            Ok(bytes)
        }
    }
    pub(super) async fn native_stream(
        self,
        start: u64,
        end: u64,
    ) -> Result<futures::stream::BoxStream<'static, Result<bytes::Bytes, std::io::Error>>, Error>
    {
        use futures::StreamExt;
        let (verified, bytes) = tokio::task::spawn_blocking(move || {
            let bytes = self.read_plaintext(NATIVE_LIMIT as usize)?;
            Ok::<_, Error>((self, bytes))
        })
        .await
        .map_err(|_| storage())??;
        Ok(futures::stream::unfold(
            (verified, bytes, start as usize, end as usize, false),
            |(verified, bytes, at, end, done)| async move {
                if done || at == end {
                    return None;
                }
                if verified.timer.now() >= verified.deadline.instant() {
                    return Some((
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "content transfer deadline",
                        )),
                        (verified, bytes, at, end, true),
                    ));
                }
                let next = (at + BLOCK as usize).min(end);
                let value = bytes::Bytes::copy_from_slice(&bytes[at..next]);
                Some((Ok(value), (verified, bytes, next, end, false)))
            },
        )
        .boxed())
    }
}
