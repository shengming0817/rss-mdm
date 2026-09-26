//! Reclaim only expired sessions and unreferenced immutable blobs, under cross-process locks.
use super::*;
use uuid::Uuid;
pub(crate) struct Garbage {
    path: PathBuf,
    _guard: File,
    pub digest: [u8; 32],
}
impl Garbage {
    pub(crate) async fn remove(self) -> Result<(), Error> {
        tokio::task::spawn_blocking(move || {
            let _guard = self._guard;
            let parent = self.path.parent().ok_or_else(storage)?;
            fs::remove_file(&self.path).map_err(|_| storage())?;
            sync_dir(parent)
        })
        .await
        .map_err(|_| storage())?
    }
}
impl Store {
    fn clean_orphan(&self, id: Uuid, path: &Path, now: i64) -> Result<(), Error> {
        let metadata = fs::symlink_metadata(path).map_err(|_| storage())?;
        let age = metadata
            .modified()
            .map_err(|_| storage())?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| storage())?
            .as_secs();
        if !metadata.is_file()
            || now < 0
            || (now as u64).saturating_sub(age) < self.config.retention_seconds
        {
            return Ok(());
        }
        let _guard = match lock(&self.upload_path(id, "part")) {
            Ok(f) => f,
            Err(Error::Conflict) => return Ok(()),
            Err(e) => return Err(e),
        };
        for extension in ["next", "part"] {
            let path = self.upload_path(id, extension);
            if path.exists() {
                regular(&path)?;
                fs::remove_file(path).map_err(|_| storage())?;
            }
        }
        sync_dir(&self.directory)
    }
    pub(super) fn clean_partials_locked(&self, now: i64) -> Result<(), Error> {
        for entry in fs::read_dir(&self.directory).map_err(|_| storage())? {
            let entry = entry.map_err(|_| storage())?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(raw) = name
                .strip_prefix(".upload-")
                .and_then(|v| v.strip_suffix(".part").or_else(|| v.strip_suffix(".next")))
            {
                if let Ok(id) = Uuid::parse_str(raw)
                    && id.to_string() == raw
                    && !self.upload_path(id, "json").exists()
                {
                    self.clean_orphan(id, &entry.path(), now)?;
                }
                continue;
            }
            let Some(raw) = name
                .strip_prefix(".upload-")
                .and_then(|v| v.strip_suffix(".json"))
            else {
                continue;
            };
            let Ok(id) = Uuid::parse_str(raw) else {
                continue;
            };
            if id.to_string() != raw {
                continue;
            }
            let upload = self.load_upload(id, i64::MIN)?;
            if upload.complete && self.upload_path(id, "part").exists() {
                match lock(&self.upload_path(id, "part")) {
                    Ok(_guard) => {
                        fs::remove_file(self.upload_path(id, "part")).map_err(|_| storage())?;
                        sync_dir(&self.directory)?;
                    }
                    Err(Error::Conflict) => continue,
                    Err(e) => return Err(e),
                }
            }
            if upload.expires > now {
                continue;
            }
            let path = self.upload_path(id, "part");
            let guard = match lock(&path) {
                Ok(f) => f,
                Err(Error::Conflict) => continue,
                Err(e) => return Err(e),
            };
            // The per-session lock excludes an in-flight append/finalize across all processes.
            for extension in ["json", "next", "part"] {
                let path = self.upload_path(id, extension);
                if path.exists() {
                    regular(&path)?;
                    fs::remove_file(path).map_err(|_| storage())?;
                }
            }
            drop(guard);
            sync_dir(&self.directory)?;
        }
        Ok(())
    }
    pub(crate) async fn garbage(self: &Arc<Self>, now: i64) -> Result<Vec<Garbage>, Error> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let _directory = lock(&store.directory.join(".upload.lock"))?;
            store.clean_partials_locked(now)?;
            let mut protected = std::collections::BTreeSet::new();
            let mut candidates = Vec::new();
            for entry in fs::read_dir(&store.directory).map_err(|_| storage())? {
                let entry = entry.map_err(|_| storage())?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if let Some(id) = name
                    .strip_prefix(".upload-")
                    .and_then(|v| v.strip_suffix(".json"))
                    .and_then(|v| Uuid::parse_str(v).ok())
                {
                    protected.insert(store.load_upload(id, i64::MIN)?.binding.sha256);
                } else if name.len() == 64
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    let metadata = fs::symlink_metadata(entry.path()).map_err(|_| storage())?;
                    if !metadata.is_file() {
                        continue;
                    }
                    let modified = metadata
                        .modified()
                        .map_err(|_| storage())?
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| storage())?
                        .as_secs();
                    if now < 0
                        || (now as u64).saturating_sub(modified) < store.config.retention_seconds
                    {
                        continue;
                    }
                    candidates.push((
                        entry.path(),
                        rss_mdm_resource::Digest::parse(&name)
                            .map_err(|_| invariant())?
                            .bytes(),
                    ));
                }
            }
            let mut garbage = Vec::new();
            for (path, digest) in candidates
                .into_iter()
                .filter(|(_, d)| !protected.contains(d))
                .take(128)
            {
                match lock(&store.blob_lock(digest)) {
                    Ok(guard) => garbage.push(Garbage {
                        path,
                        digest,
                        _guard: guard,
                    }),
                    Err(Error::Conflict) => (),
                    Err(e) => return Err(e),
                }
            }
            Ok(garbage)
        })
        .await
        .map_err(|_| storage())?
    }
}
