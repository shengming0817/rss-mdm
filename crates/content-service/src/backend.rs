//! Exact immutable pieces; no upload journal, authorization or retention decisions.
use super::*;
use futures::StreamExt;
use rss_mdm_content_s3 as s3;
use uuid::Uuid;
/// Product backend selection. Secrets are file references interpreted only by the host.
#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Storage {
    Volume { directory: PathBuf },
    S3(Box<S3Storage>),
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Storage {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub namespace: String,
    pub credentials_reference: String,
    pub access_key_file: PathBuf,
    pub secret_key_file: PathBuf,
    pub session_token_file: Option<PathBuf>,
    pub private_ca_file: Option<PathBuf>,
    pub max_concurrent: usize,
    pub connect_seconds: u64,
}
impl Storage {
    pub fn volume_directory(&self) -> Option<&Path> {
        match self {
            Self::Volume { directory } => Some(directory),
            _ => None,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Coordinate {
    Volume { scope: [u8; 32], id: Uuid },
    S3 { object: s3::Object },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Intent {
    Volume { scope: [u8; 32], id: Uuid },
    S3 { write: s3::Write },
}
#[derive(Clone)]
pub(super) enum Backend {
    Volume {
        directory: PathBuf,
        scope: [u8; 32],
        timer: Arc<dyn Clock>,
    },
    S3 {
        store: Arc<s3::Store>,
        timer: Arc<dyn Clock>,
    },
}
fn error(e: s3::Error) -> Error {
    match e {
        s3::Error::Configuration | s3::Error::Denied => Error::Configuration,
        s3::Error::Integrity => Error::Invariant,
        s3::Error::Input => Error::Malformed,
        s3::Error::Busy | s3::Error::Conflict => Error::Conflict,
        s3::Error::Budget => Error::Deadline,
        s3::Error::Transient | s3::Error::Missing => Error::Storage,
    }
}
// Keep the lock inode after deletion: its durable marker fences even a cancelled,
// queued spawn_blocking writer. Removing it would allow a new lock inode and resurrection.
fn volume_lock(
    directory: &Path,
    id: Uuid,
    timer: &dyn Clock,
    deadline: Deadline,
) -> Result<File, Error> {
    let file = options()
        .create(true)
        .truncate(false)
        .open(directory.join(format!(".{id}.lock")))
        .map_err(|_| storage())?;
    if !file.metadata().map_err(|_| storage())?.is_file() {
        return Err(invariant());
    }
    loop {
        if timer.now() >= deadline.instant() {
            return Err(Error::Deadline);
        }
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
            }
            Err(_) => return Err(storage()),
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
struct TemporaryPiece(PathBuf);
impl Drop for TemporaryPiece {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
impl Backend {
    fn timer(&self) -> &dyn Clock {
        match self {
            Self::Volume { timer, .. } | Self::S3 { timer, .. } => timer.as_ref(),
        }
    }

    pub fn identity(&self) -> Result<serde_json::Value, Error> {
        match self {
            Self::Volume { scope, .. } => Ok(serde_json::json!({"kind":"volume","scope":scope})),
            Self::S3 { store, .. } => Ok(
                serde_json::json!({"kind":"s3","scope":store.target("identity").map_err(error)?}),
            ),
        }
    }
    pub async fn open(
        config: &Storage,
        tenant: rss_request_context::TenantId,
        timer: Arc<dyn Clock>,
        seconds: u64,
        secrets: Option<Arc<dyn s3::Secrets>>,
    ) -> Result<Self, Error> {
        match config {
            Storage::Volume { directory } => {
                if !directory.is_absolute()
                    || !directory.is_dir()
                    || fs::symlink_metadata(directory)
                        .map_err(|_| Error::Configuration)?
                        .file_type()
                        .is_symlink()
                {
                    return Err(Error::Configuration);
                }
                let directory = directory.join(tenant.to_string());
                fs::create_dir_all(&directory).map_err(|_| storage())?;
                if fs::symlink_metadata(&directory)
                    .map_err(|_| storage())?
                    .file_type()
                    .is_symlink()
                {
                    return Err(Error::Configuration);
                }
                let scope = Sha256::digest(directory.as_os_str().as_encoded_bytes()).into();
                Ok(Self::Volume {
                    directory,
                    scope,
                    timer,
                })
            }
            Storage::S3(config) => {
                let S3Storage {
                    endpoint,
                    region,
                    bucket,
                    namespace,
                    credentials_reference,
                    private_ca_file,
                    max_concurrent,
                    connect_seconds,
                    ..
                } = config.as_ref();
                let private_ca_pem = private_ca_file
                    .as_ref()
                    .map(|p| {
                        let mut opts = OpenOptions::new();
                        opts.read(true);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::OpenOptionsExt;
                            opts.custom_flags(libc::O_NOFOLLOW);
                        }
                        let f = opts.open(p).map_err(|_| Error::Configuration)?;
                        if !f.metadata().map_err(|_| Error::Configuration)?.is_file()
                            || f.metadata().map_err(|_| Error::Configuration)?.len() > 1048576
                        {
                            return Err(Error::Configuration);
                        }
                        let mut bytes = Vec::new();
                        f.take(1048577)
                            .read_to_end(&mut bytes)
                            .map_err(|_| Error::Configuration)?;
                        if bytes.len() > 1048576 {
                            return Err(Error::Configuration);
                        }
                        Ok(bytes)
                    })
                    .transpose()?;
                let config = s3::Config {
                    endpoint: endpoint.clone(),
                    region: region.clone(),
                    bucket: bucket.clone(),
                    namespace: format!("{namespace}/{tenant}"),
                    credentials_reference: credentials_reference.clone(),
                    private_ca_pem,
                    max_concurrent: *max_concurrent,
                    connect_timeout: std::time::Duration::from_secs(*connect_seconds),
                };
                let budget = s3::Budget::new(
                    timer.clone(),
                    std::time::Duration::from_secs(seconds),
                    std::time::Duration::from_secs(seconds.min(30)),
                    0,
                    1,
                )
                .map_err(error)?;
                Ok(Self::S3 {
                    store: Arc::new(
                        s3::Store::connect(
                            config,
                            secrets.ok_or(Error::Configuration)?,
                            timer.clone(),
                            budget,
                        )
                        .await
                        .map_err(error)?,
                    ),
                    timer,
                })
            }
        }
    }
    fn budget(&self, store: &s3::Store, deadline: Deadline) -> Result<s3::Budget, Error> {
        let remaining = deadline
            .instant()
            .saturating_duration_since(self.timer().now());
        store
            .budget(
                remaining,
                std::time::Duration::from_secs(30),
                super::journal::CHUNK + 65536,
                1,
            )
            .map_err(error)
    }
    pub fn intent(&self, id: Uuid, content: s3::Content) -> Result<Intent, Error> {
        match self {
            Self::Volume { scope, .. } => Ok(Intent::Volume { scope: *scope, id }),
            Self::S3 { store, .. } => {
                let target = store.target(&format!("pieces/{id}")).map_err(error)?;
                Ok(Intent::S3 {
                    write: store
                        .write(target, &id.to_string(), content)
                        .map_err(error)?,
                })
            }
        }
    }
    pub fn write<'a>(
        &'a self,
        intent: &'a Intent,
        content: s3::Content,
        bytes: Vec<u8>,
        deadline: Deadline,
    ) -> futures::future::BoxFuture<'a, Result<Coordinate, Error>> {
        Box::pin(self.write_inner(intent, content, bytes, deadline))
    }
    async fn write_inner(
        &self,
        intent: &Intent,
        content: s3::Content,
        bytes: Vec<u8>,
        deadline: Deadline,
    ) -> Result<Coordinate, Error> {
        match (self, intent) {
            (
                Self::Volume {
                    directory, scope, ..
                },
                Intent::Volume {
                    scope: expected,
                    id,
                },
            ) if scope == expected => {
                let directory = directory.clone();
                let id = *id;
                let expected = *expected;
                let timer = match self {
                    Self::Volume { timer, .. } => timer.clone(),
                    _ => unreachable!(),
                };
                tokio::task::spawn_blocking(move || {
                    use std::io::Write;
                    let lock = volume_lock(&directory, id, timer.as_ref(), deadline)?;
                    if lock.metadata().map_err(|_| storage())?.len() != 0 {
                        return Err(Error::Conflict);
                    }
                    let target = directory.join(id.to_string());
                    if !target.exists() {
                        let temporary = directory.join(format!(".{id}.tmp"));
                        let mut file = options()
                            .create_new(true)
                            .open(&temporary)
                            .map_err(|_| storage())?;
                        let temporary = TemporaryPiece(temporary);
                        file.write_all(&bytes).map_err(|_| storage())?;
                        file.sync_all().map_err(|_| storage())?;
                        if timer.now() >= deadline.instant() {
                            return Err(Error::Deadline);
                        }
                        fs::hard_link(&temporary.0, &target).map_err(|_| storage())?;
                        fs::remove_file(&temporary.0).map_err(|_| storage())?;
                        sync_dir(&directory)?;
                    }
                    verify_volume(&target, content, timer.as_ref(), deadline)?;
                    Ok(Coordinate::Volume {
                        scope: expected,
                        id,
                    })
                })
                .await
                .map_err(|_| storage())?
            }
            (Self::S3 { store, .. }, Intent::S3 { write }) => {
                let source =
                    futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
                let result = store
                    .put(write, source, self.budget(store, deadline)?)
                    .await
                    .map_err(error)?;
                match result {
                    s3::Mutation::Confirmed(s3::Written::Verified(v)) => Ok(Coordinate::S3 {
                        object: v.object().clone(),
                    }),
                    s3::Mutation::Confirmed(s3::Written::Unverified { object, .. }) => {
                        Ok(Coordinate::S3 { object })
                    }
                    s3::Mutation::Unknown(_) => self
                        .recover(intent, content, deadline)
                        .await?
                        .ok_or(Error::CommitUnknown),
                }
            }
            _ => Err(Error::Configuration),
        }
    }
    pub fn recover<'a>(
        &'a self,
        intent: &'a Intent,
        content: s3::Content,
        deadline: Deadline,
    ) -> futures::future::BoxFuture<'a, Result<Option<Coordinate>, Error>> {
        Box::pin(self.recover_inner(intent, content, deadline))
    }
    async fn recover_inner(
        &self,
        intent: &Intent,
        _content: s3::Content,
        deadline: Deadline,
    ) -> Result<Option<Coordinate>, Error> {
        match (self, intent) {
            (
                Self::Volume { scope, .. },
                Intent::Volume {
                    scope: expected,
                    id,
                },
            ) if scope == expected => {
                // The volume coordinate is determined by the intent before I/O. GC can
                // fence and delete this exact ID even if only a partial tmp (or no file)
                // exists; content verification remains mandatory for reads/publication.
                if self.timer().now() >= deadline.instant() {
                    return Err(Error::Deadline);
                }
                Ok(Some(Coordinate::Volume {
                    scope: *scope,
                    id: *id,
                }))
            }
            (Self::S3 { store, .. }, Intent::S3 { write }) => match store
                .recover(write, self.budget(store, deadline)?)
                .await
                .map_err(error)?
            {
                s3::Recovery::Matched(s3::Written::Verified(v)) => Ok(Some(Coordinate::S3 {
                    object: v.object().clone(),
                })),
                s3::Recovery::Matched(s3::Written::Unverified { object, .. }) => {
                    Ok(Some(Coordinate::S3 { object }))
                }
                s3::Recovery::Unresolved => Ok(None),
            },
            _ => Err(Error::Configuration),
        }
    }
    pub fn read<'a>(
        &'a self,
        coordinate: &'a Coordinate,
        content: s3::Content,
        start: u64,
        end: u64,
        deadline: Deadline,
    ) -> futures::future::BoxFuture<'a, Result<Vec<u8>, Error>> {
        Box::pin(self.read_inner(coordinate, content, start, end, deadline))
    }
    async fn read_inner(
        &self,
        coordinate: &Coordinate,
        content: s3::Content,
        start: u64,
        end: u64,
        deadline: Deadline,
    ) -> Result<Vec<u8>, Error> {
        if start > end || end > content.length {
            return Err(Error::Invariant);
        }
        match (self, coordinate) {
            (
                Self::Volume {
                    directory, scope, ..
                },
                Coordinate::Volume {
                    scope: expected,
                    id,
                },
            ) if scope == expected => {
                let path = directory.join(id.to_string());
                let timer = match self {
                    Self::Volume { timer, .. } => timer.clone(),
                    _ => unreachable!(),
                };
                tokio::task::spawn_blocking(move || {
                    verify_volume(&path, content, timer.as_ref(), deadline)?;
                    let mut file = options().open(path).map_err(|_| storage())?;
                    file.seek(SeekFrom::Start(start)).map_err(|_| storage())?;
                    let mut out = vec![0; (end - start) as usize];
                    file.read_exact(&mut out).map_err(|_| storage())?;
                    Ok(out)
                })
                .await
                .map_err(|_| storage())?
            }
            (Self::S3 { store, .. }, Coordinate::S3 { object }) => {
                let v = store
                    .verify(object, content, self.budget(store, deadline)?)
                    .await
                    .map_err(error)?;
                let mut stream = store
                    .read(&v, start, end, self.budget(store, deadline)?)
                    .await
                    .map_err(error)?;
                let mut out = Vec::with_capacity((end - start) as usize);
                while let Some(chunk) = stream.next().await {
                    out.extend_from_slice(&chunk.map_err(error)?);
                }
                Ok(out)
            }
            _ => Err(Error::Configuration),
        }
    }
    pub fn delete<'a>(
        &'a self,
        coordinate: &'a Coordinate,
        deadline: Deadline,
    ) -> futures::future::BoxFuture<'a, Result<bool, Error>> {
        Box::pin(self.delete_inner(coordinate, deadline))
    }
    async fn delete_inner(
        &self,
        coordinate: &Coordinate,
        deadline: Deadline,
    ) -> Result<bool, Error> {
        match (self, coordinate) {
            (
                Self::Volume {
                    directory, scope, ..
                },
                Coordinate::Volume {
                    scope: expected,
                    id,
                },
            ) if scope == expected => {
                let directory = directory.clone();
                let id = *id;
                let timer = match self {
                    Self::Volume { timer, .. } => timer.clone(),
                    _ => unreachable!(),
                };
                tokio::task::spawn_blocking(move || {
                    use std::io::Write;
                    let mut lock = volume_lock(&directory, id, timer.as_ref(), deadline)?;
                    lock.rewind().map_err(|_| storage())?;
                    lock.write_all(b"D").map_err(|_| storage())?;
                    lock.sync_all().map_err(|_| storage())?;
                    sync_dir(&directory)?;
                    for path in [
                        directory.join(id.to_string()),
                        directory.join(format!(".{id}.tmp")),
                    ] {
                        match fs::remove_file(path) {
                            Ok(()) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(_) => return Err(Error::Cleanup),
                        }
                    }
                    sync_dir(&directory)?;
                    Ok(true)
                })
                .await
                .map_err(|_| storage())?
            }
            (Self::S3 { store, .. }, Coordinate::S3 { object }) => Ok(matches!(
                store
                    .delete(object, self.budget(store, deadline)?)
                    .await
                    .map_err(error)?,
                s3::Mutation::Confirmed(())
            )),
            _ => Err(Error::Configuration),
        }
    }
}
fn verify_volume(
    path: &Path,
    content: s3::Content,
    timer: &dyn Clock,
    deadline: Deadline,
) -> Result<(), Error> {
    regular(path)?;
    let mut file = options().open(path).map_err(|_| storage())?;
    if file.metadata().map_err(|_| storage())?.len() != content.length {
        return Err(invariant());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        if timer.now() >= deadline.instant() {
            return Err(Error::Deadline);
        }
        let n = file.read(&mut buffer).map_err(|_| storage())?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    if hash.finalize().as_slice() != content.sha256 {
        return Err(invariant());
    }
    Ok(())
}
