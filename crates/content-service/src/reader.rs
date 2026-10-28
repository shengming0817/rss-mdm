//! Logical reads hold PostgreSQL pins; every emitted block uses the original transfer deadline.
use super::*;
use futures::StreamExt;
use journal::{Manifest, Piece};
use uuid::Uuid;
use zeroize::Zeroizing;
/// A deletion pin on a previously completed signed content manifest. Does not read bytes.
pub struct Pinned {
    store: Store,
    pin: Uuid,
    pub(super) manifest: Manifest,
    artifact: Artifact,
    _admission: Arc<crate::gate::Permit>,
}
impl Pinned {
    pub(super) fn new(
        store: Store,
        pin: Uuid,
        manifest: Manifest,
        artifact: Artifact,
        admission: Arc<crate::gate::Permit>,
    ) -> Self {
        Self {
            store,
            pin,
            manifest,
            artifact,
            _admission: admission,
        }
    }
    pub fn matches(&self, artifact: &Artifact) -> bool {
        self.artifact.length() == artifact.length() && self.artifact.digest() == artifact.digest()
    }
}
impl Drop for Pinned {
    fn drop(&mut self) {
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let store = self.store.clone();
            let pin = self.pin;
            runtime.spawn(async move {
                let _ = store.unpin(pin).await;
            });
        }
    }
}
pub struct Verified {
    store: Store,
    pub artifact: Artifact,
    manifest: Manifest,
    pin: Uuid,
    pub(super) deadline: Deadline,
    plaintext: Option<Zeroizing<Vec<u8>>>,
    _permit: Option<TransferLease>,
}
/// Release idle body capacity at its deadline, even under HTTP backpressure.
/// Actual blocking work owns a separate Arc until its buffers and files have closed.
/// ref: tokio tokio/src/runtime/task/join.rs (owned task cancellation).
struct ReadWork {
    _capacity: Arc<OwnedSemaphorePermit>,
    _admission: Arc<crate::gate::Permit>,
}
struct TransferLease {
    permit: Arc<std::sync::Mutex<Option<Arc<ReadWork>>>>,
    expiry: tokio::task::JoinHandle<()>,
}
impl TransferLease {
    fn new(
        permit: Arc<OwnedSemaphorePermit>,
        admission: Arc<crate::gate::Permit>,
        deadline: Deadline,
    ) -> Self {
        let permit = Arc::new(std::sync::Mutex::new(Some(Arc::new(ReadWork {
            _capacity: permit,
            _admission: admission,
        }))));
        let release = permit.clone();
        let expiry = tokio::spawn(async move {
            tokio::time::sleep_until(deadline.instant().into()).await;
            release.lock().unwrap_or_else(|e| e.into_inner()).take();
        });
        Self { permit, expiry }
    }
    fn work(&self) -> Result<Arc<ReadWork>, Error> {
        self.permit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or(Error::Deadline)
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
// Return values (including buffers and open files) must drop before the work permit.
pub(super) fn blocking<G: Send + 'static, T: Send + 'static>(
    guard: G,
    work: impl FnOnce() -> T + Send + 'static,
) -> tokio::task::JoinHandle<(T, G)> {
    tokio::task::spawn_blocking(move || (work(), guard))
}
impl Store {
    async fn pin_ready_in(&self, a: &Artifact, c: StorageClass) -> Result<Pinned, Error> {
        let admission = self.admit(crate::gate::Kind::Read).await?;
        let (manifest, pin) = self.pin(a, c, self.deadline()?, 0).await?;
        Ok(Pinned {
            store: self.clone(),
            pin,
            manifest,
            artifact: a.clone(),
            _admission: admission,
        })
    }
    pub async fn pin_materials(
        &self,
        artifacts: &[(Artifact, StorageClass)],
    ) -> Result<Vec<Pinned>, Error> {
        if artifacts.len() > 128 {
            return Err(Error::Malformed);
        }
        let mut files = Vec::new();
        for (a, c) in artifacts {
            files.push(self.pin_ready(a, *c).await?);
        }
        Ok(files)
    }
    async fn verify_ready_report_in(&self, a: &Artifact) -> Result<Zeroizing<Vec<u8>>, Error> {
        let permit = Arc::new(
            self.transfers
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Conflict)?,
        );
        let pin = self.pin_ready(a, StorageClass::Artifact).await?;
        let (bytes, digest, _) = self
            .check_pieces(
                &pin.manifest.pieces,
                a,
                StorageClass::Artifact,
                self.deadline()?,
                None,
                (permit, pin._admission.clone()),
            )
            .await?;
        if digest != a.digest().bytes() {
            return Err(Error::Invariant);
        }
        bytes.ok_or(Error::Malformed)
    }
    pub(super) async fn check_pieces<G: Clone + Send + 'static>(
        &self,
        pieces: &[Piece],
        a: &Artifact,
        c: StorageClass,
        deadline: Deadline,
        mut spool: Option<File>,
        guard: G,
    ) -> Result<(Option<Zeroizing<Vec<u8>>>, [u8; 32], Option<File>), Error> {
        if pieces.is_empty() || pieces.len() > 8193 || (c.protected() && pieces.len() != 1) {
            return Err(Error::Invariant);
        }
        let available = deadline
            .instant()
            .saturating_duration_since(self.timer.now());
        let spool_cutoff = deadline.instant() - available / 4;
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
                .read(
                    &self.coordinate(p).await?,
                    p.content,
                    0,
                    p.content.length,
                    deadline,
                    guard.clone(),
                )
                .await?;
            let class = c;
            let store = self.clone();
            let artifact = a.clone();
            let length = p.length;
            let (checked, _work) = blocking(guard.clone(), move || {
                let logical = if class.protected() {
                    protected::plaintext(
                        &store.protection,
                        store.tenant,
                        &physical,
                        &artifact,
                        class,
                        length,
                    )?
                } else {
                    Zeroizing::new(physical)
                };
                if logical.len() as u64 != length {
                    return Err(Error::Invariant);
                }
                hash.update(&logical);
                Ok((hash, logical))
            })
            .await
            .map_err(|_| Error::Storage)?;
            let (next_hash, logical) = checked?;
            hash = next_hash;
            self.check_deadline(deadline)?;
            if let Some(small) = &mut small {
                small.extend_from_slice(&logical);
            }
            if let Some(mut file) = spool.take().filter(|_| self.timer.now() < spool_cutoff) {
                let task = blocking(guard.clone(), move || {
                    std::io::Write::write_all(&mut file, &logical)
                        .ok()
                        .map(|()| file)
                });
                spool = match tokio::time::timeout_at(spool_cutoff.into(), task).await {
                    Ok(Ok((file, _work))) => file,
                    _ => None,
                };
            }
            offset = offset.checked_add(p.length).ok_or(Error::Invariant)?;
        }
        self.check_deadline(deadline)?;
        if offset != a.length() {
            return Err(Error::Invariant);
        }
        Ok((small, hash.finalize().into(), spool))
    }
    pub async fn verify(self: &Arc<Self>, a: &Artifact) -> Result<Verified, Error> {
        self.verify_class(a, StorageClass::Artifact, self.deadline()?)
            .await
    }
    async fn verify_class_in(
        self: &Arc<Self>,
        a: &Artifact,
        c: StorageClass,
        d: Deadline,
    ) -> Result<Verified, Error> {
        let permit = Arc::new(
            self.transfers
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Conflict)?,
        );
        let admission = self.admit(crate::gate::Kind::Read).await?;
        let mut v = self
            .verify_at(a, c, d, permit.clone(), admission.clone())
            .await?;
        v._permit = Some(TransferLease::new(permit, admission, d));
        Ok(v)
    }
    async fn verify_at(
        &self,
        a: &Artifact,
        c: StorageClass,
        d: Deadline,
        permit: Arc<OwnedSemaphorePermit>,
        admission: Arc<crate::gate::Permit>,
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
            manifest,
            pin,
            deadline: d,
            plaintext: None,
            _permit: None,
        };
        let (plaintext, digest, _) = self
            .check_pieces(
                &verified.manifest.pieces,
                a,
                c,
                d,
                None,
                (permit, admission),
            )
            .await?;
        if digest != a.digest().bytes() {
            return Err(Error::Invariant);
        }
        verified.plaintext = plaintext;
        Ok(verified)
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
                                    &v.store.coordinate(p).await?,
                                    p.content,
                                    at - p.offset,
                                    (end - p.offset).min(p.length),
                                    v.deadline,
                                    v._permit.as_ref().ok_or(Error::Invariant)?.work()?,
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
    async fn cancelled_blocking_work_keeps_file_and_capacity_until_exit() {
        let slots = Arc::new(Semaphore::new(1));
        let permit = Arc::new(slots.clone().try_acquire_owned().unwrap());
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_owned();
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, stopped) = std::sync::mpsc::channel();
        let task = blocking(permit, move || {
            entered.send(()).unwrap();
            let _ = stopped.recv();
            std::io::Write::write_all(file.as_file_mut(), b"owned work").unwrap();
            file
        });
        started.await.unwrap();
        drop(task);
        assert!(path.exists());
        assert!(slots.clone().try_acquire_owned().is_err());
        release.send(()).unwrap();
        let restored =
            tokio::time::timeout(std::time::Duration::from_secs(1), slots.acquire_owned())
                .await
                .unwrap()
                .unwrap();
        assert!(
            !path.exists(),
            "the file must close before capacity returns"
        );
        drop(restored);
    }

    #[tokio::test]
    async fn transfer_capacity_expires_without_polling_and_releases_on_drop() {
        let slots = Arc::new(Semaphore::new(1));
        let deadline = Deadline::at(RuntimeTimer.now());
        let work = Arc::new(slots.clone().try_acquire_owned().unwrap());
        let admission = crate::gate::Permit::test();
        let observed = Arc::downgrade(&admission);
        let lease = TransferLease::new(work.clone(), admission, deadline);
        assert!(slots.clone().try_acquire_owned().is_err());
        drop(work);
        let restored = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            slots.clone().acquire_owned(),
        )
        .await
        .unwrap()
        .unwrap();
        drop(restored);
        assert!(
            observed.upgrade().is_none(),
            "idle body must release admission without polling"
        );
        assert_eq!(slots.available_permits(), 1);
        drop(lease);
        let lease = TransferLease::new(
            Arc::new(slots.clone().try_acquire_owned().unwrap()),
            crate::gate::Permit::test(),
            Deadline::at(RuntimeTimer.now() + std::time::Duration::from_secs(60)),
        );
        drop(lease);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn cancelled_transfer_releases_capacity() {
        let slots = Arc::new(Semaphore::new(1));
        let lease = TransferLease::new(
            Arc::new(slots.clone().try_acquire_owned().unwrap()),
            crate::gate::Permit::test(),
            Deadline::at(RuntimeTimer.now() + std::time::Duration::from_secs(60)),
        );
        let task = tokio::spawn(async move {
            let _lease = lease;
            std::future::pending::<()>().await;
        });
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(slots.available_permits(), 1);
    }
}

impl Store {
    pub async fn pin_ready(&self, a: &Artifact, c: StorageClass) -> Result<Pinned, Error> {
        self.current().await?.pin_ready_in(a, c).await
    }
    pub async fn verify_class(
        self: &Arc<Self>,
        a: &Artifact,
        c: StorageClass,
        d: Deadline,
    ) -> Result<Verified, Error> {
        Arc::new(self.current().await?)
            .verify_class_in(a, c, d)
            .await
    }
}

impl Store {
    pub(super) async fn verify_ready_report(
        &self,
        a: &Artifact,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.current().await?.verify_ready_report_in(a).await
    }
}
