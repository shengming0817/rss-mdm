//! Logical reads hold PostgreSQL pins; every emitted block uses the original transfer deadline.
use super::*;
use futures::StreamExt;
use journal::{Manifest, Piece};
use uuid::Uuid;
use zeroize::Zeroizing;
pub struct Verified {
    store: Store,
    pub artifact: Artifact,
    class: StorageClass,
    manifest: Manifest,
    pin: Uuid,
    pub(super) deadline: Deadline,
    plaintext: Option<Zeroizing<Vec<u8>>>,
    _permit: Option<TransferLease>,
}
/// Release scarce transfer capacity at its absolute deadline, even when HTTP backpressure
/// stops polling the body. The timer performs only this synchronous release; the lease
/// owns and aborts it on drop. Storage pins already carry the same persisted deadline.
/// ref: tokio tokio/src/runtime/task/join.rs (owned task cancellation).
struct TransferLease {
    permit: Arc<std::sync::Mutex<Option<OwnedSemaphorePermit>>>,
    expiry: tokio::task::JoinHandle<()>,
}
impl TransferLease {
    fn new(permit: OwnedSemaphorePermit, deadline: Deadline) -> Self {
        let permit = Arc::new(std::sync::Mutex::new(Some(permit)));
        let release = permit.clone();
        let expiry = tokio::spawn(async move {
            tokio::time::sleep_until(deadline.instant().into()).await;
            release.lock().unwrap_or_else(|e| e.into_inner()).take();
        });
        Self { permit, expiry }
    }
}
impl Drop for TransferLease {
    fn drop(&mut self) {
        self.permit.lock().unwrap_or_else(|e| e.into_inner()).take();
        self.expiry.abort();
    }
}
impl Drop for Verified {
    fn drop(&mut self) {
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let s = self.store.clone();
            let id = self.pin;
            runtime.spawn(async move {
                let _ = s.unpin(id).await;
            });
        }
    }
}
pub(super) struct Temporary {
    pub file: tempfile::NamedTempFile,
    store: Store,
    pin: Uuid,
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let s = self.store.clone();
            let id = self.pin;
            runtime.spawn(async move {
                let _ = s.unpin(id).await;
            });
        }
    }
}
impl Store {
    pub(super) async fn check_pieces(
        &self,
        pieces: &[Piece],
        a: &Artifact,
        c: StorageClass,
        deadline: Deadline,
    ) -> Result<(Option<Zeroizing<Vec<u8>>>, [u8; 32]), Error> {
        if pieces.is_empty() || pieces.len() > 8193 || (c.protected() && pieces.len() != 1) {
            return Err(Error::Invariant);
        }
        let mut offset = 0;
        let mut hash = Sha256::new();
        let mut small = if a.length() <= protected::NATIVE_LIMIT {
            Some(Zeroizing::new(Vec::new()))
        } else {
            None
        };
        for (index, p) in pieces.iter().enumerate() {
            self.check_deadline(deadline)?;
            if p.offset != offset
                || p.length == 0
                || (!c.protected()
                    && (p.content.length != p.length
                        || p.length > journal::CHUNK
                        || (index + 1 < pieces.len() && p.length != journal::CHUNK)))
            {
                return Err(Error::Invariant);
            }
            let physical = self
                .backend
                .read(&p.coordinate, p.content, 0, p.content.length, deadline)
                .await?;
            if physical.len() as u64 != p.content.length
                || Sha256::digest(&physical).as_slice() != p.content.sha256
            {
                return Err(Error::Invariant);
            }
            let logical = if c.protected() {
                self.plaintext(&physical, a, c, p.length)?
            } else {
                Zeroizing::new(physical)
            };
            if logical.len() as u64 != p.length {
                return Err(Error::Invariant);
            }
            hash.update(&logical);
            if let Some(small) = &mut small {
                small.extend_from_slice(&logical);
            }
            offset = offset.checked_add(p.length).ok_or(Error::Invariant)?;
        }
        self.check_deadline(deadline)?;
        if offset != a.length() {
            return Err(Error::Invariant);
        }
        Ok((small, hash.finalize().into()))
    }
    pub async fn verify(self: &Arc<Self>, a: &Artifact) -> Result<Verified, Error> {
        self.verify_class(a, StorageClass::Artifact).await
    }
    pub async fn verify_class(
        self: &Arc<Self>,
        a: &Artifact,
        c: StorageClass,
    ) -> Result<Verified, Error> {
        let permit = self
            .transfers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Conflict)?;
        let d = self.deadline()?;
        let mut v = self.verify_at(a, c, d).await?;
        v._permit = Some(TransferLease::new(permit, d));
        Ok(v)
    }
    async fn verify_at(
        &self,
        a: &Artifact,
        c: StorageClass,
        d: Deadline,
    ) -> Result<Verified, Error> {
        if a.length() > self.config.max_artifact_bytes
            || (c.protected() && a.length() > protected::NATIVE_LIMIT)
        {
            return Err(Error::Malformed);
        }
        let (manifest, pin) = self.pin(a, c, d, 0).await?;
        let mut verified = Verified {
            store: self.clone(),
            artifact: a.clone(),
            class: c,
            manifest,
            pin,
            deadline: d,
            plaintext: None,
            _permit: None,
        };
        let (plaintext, digest) = self
            .check_pieces(&verified.manifest.pieces, a, c, d)
            .await?;
        if digest != a.digest().bytes() {
            return Err(Error::Invariant);
        }
        verified.plaintext = plaintext;
        Ok(verified)
    }
    pub async fn verify_materials(
        &self,
        artifacts: &[(Artifact, StorageClass)],
    ) -> Result<Vec<Verified>, Error> {
        if artifacts.len() > 128 {
            return Err(Error::Malformed);
        }
        let permit = self
            .transfers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Conflict)?;
        let d = self.deadline()?;
        let mut out = Vec::new();
        for (a, c) in artifacts {
            out.push(self.verify_at(a, *c, d).await?);
        }
        if let Some(v) = out.first_mut() {
            v._permit = Some(TransferLease::new(permit, d));
        }
        Ok(out)
    }
}
impl Verified {
    pub fn matches(&self, a: &Artifact) -> bool {
        self.store.check_deadline(self.deadline).is_ok()
            && self.artifact.length() == a.length()
            && self.artifact.digest() == a.digest()
    }
    pub fn etag(&self) -> String {
        format!("\"{}\"", hex(self.artifact.digest().bytes()))
    }
    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }
    pub fn read_plaintext(&self, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.store.check_deadline(self.deadline)?;
        if self.artifact.length() > limit as u64 {
            return Err(Error::Malformed);
        }
        self.plaintext
            .as_ref()
            .map(|b| Zeroizing::new(b.to_vec()))
            .ok_or(Error::Malformed)
    }
    pub(super) async fn materialize(&self, extra: u64) -> Result<Temporary, Error> {
        if self.class.protected() {
            return Err(Error::Malformed);
        }
        let (_, pin) = self
            .store
            .pin(
                &self.artifact,
                self.class,
                self.deadline,
                self.artifact
                    .length()
                    .checked_add(extra)
                    .ok_or(Error::Malformed)?,
            )
            .await?;
        let mut tmp = Temporary {
            file: tempfile::NamedTempFile::new().map_err(|_| storage())?,
            store: self.store.clone(),
            pin,
        };
        use std::io::Write;
        for p in &self.manifest.pieces {
            self.store.check_deadline(self.deadline)?;
            let bytes = self
                .store
                .backend
                .read(&p.coordinate, p.content, 0, p.content.length, self.deadline)
                .await?;
            tmp.file
                .as_file_mut()
                .write_all(&bytes)
                .map_err(|_| storage())?;
        }
        tmp.file
            .as_file_mut()
            .seek(SeekFrom::Start(0))
            .map_err(|_| storage())?;
        Ok(tmp)
    }
    pub async fn stream(
        self,
        start: u64,
        end: u64,
    ) -> Result<futures::stream::BoxStream<'static, Result<bytes::Bytes, std::io::Error>>, Error>
    {
        if start > end || end > self.artifact.length() {
            return Err(Error::Malformed);
        }
        let stream = futures::stream::unfold(
            (self, start, end, Zeroizing::new(Vec::new()), 0usize, false),
            |(v, mut at, end, mut buffer, mut cursor, failed)| async move {
                if at >= end || failed {
                    return None;
                }
                let result = async {
                    v.store.check_deadline(v.deadline)?;
                    if cursor >= buffer.len() {
                        buffer = Zeroizing::new(if let Some(plain) = &v.plaintext {
                            plain[at as usize..end as usize].to_vec()
                        } else {
                            let p = v
                                .manifest
                                .pieces
                                .iter()
                                .find(|p| p.offset <= at && at < p.offset + p.length)
                                .ok_or(Error::Invariant)?;
                            v.store
                                .backend
                                .read(
                                    &p.coordinate,
                                    p.content,
                                    at - p.offset,
                                    (end - p.offset).min(p.length),
                                    v.deadline,
                                )
                                .await?
                        });
                        cursor = 0;
                    }
                    let n = (buffer.len() - cursor).min(65536);
                    if n == 0 {
                        return Err(Error::Invariant);
                    }
                    let bytes = bytes::Bytes::copy_from_slice(&buffer[cursor..cursor + n]);
                    cursor += n;
                    at += n as u64;
                    v.store.check_deadline(v.deadline)?;
                    Ok(bytes)
                }
                .await;
                let failed = result.is_err();
                Some((
                    result.map_err(std::io::Error::other),
                    (v, at, end, buffer, cursor, failed),
                ))
            },
        );
        Ok(stream.boxed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct RuntimeTimer;
    impl Clock for RuntimeTimer {
        #[allow(
            clippy::disallowed_methods,
            reason = "test concrete Tokio clock provider"
        )]
        fn now(&self) -> std::time::Instant {
            tokio::time::Instant::now().into_std()
        }
    }
    #[tokio::test]
    async fn transfer_capacity_expires_without_polling_and_releases_on_drop() {
        let slots = Arc::new(Semaphore::new(1));
        let deadline = Deadline::at(RuntimeTimer.now() + std::time::Duration::from_millis(30));
        let lease = TransferLease::new(slots.clone().try_acquire_owned().unwrap(), deadline);
        assert!(slots.clone().try_acquire_owned().is_err());
        let restored = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            slots.clone().acquire_owned(),
        )
        .await
        .unwrap()
        .unwrap();
        drop(restored);
        assert_eq!(slots.available_permits(), 1);
        drop(lease);
        let lease = TransferLease::new(
            slots.clone().try_acquire_owned().unwrap(),
            Deadline::at(RuntimeTimer.now() + std::time::Duration::from_secs(60)),
        );
        drop(lease);
        assert_eq!(slots.available_permits(), 1);
    }
}
