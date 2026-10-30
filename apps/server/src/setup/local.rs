//! Exclusive, durable installation journal. Only the local deployment operator may use it.
use super::{Error, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

pub(super) struct Journal {
    root: PathBuf,
    _lock: File,
    uid: u32,
}
impl Journal {
    pub(super) fn open(root: &Path) -> Result<Self> {
        if !root.is_absolute() || root.components().any(|p| matches!(p, Component::ParentDir)) {
            return Err(Error::Input);
        }
        // Refuse symlink ancestors before creating anything inside the deployment directory.
        let mut parent = PathBuf::new();
        for part in root.components() {
            parent.push(part);
            match fs::symlink_metadata(&parent) {
                Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                    return Err(Error::Input);
                }
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&parent).map_err(|_| Error::Storage)?;
                    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
                        .map_err(|_| Error::Storage)?;
                }
                Err(_) => return Err(Error::Storage),
            }
        }
        let meta = fs::symlink_metadata(root).map_err(|_| Error::Storage)?;
        if meta.mode() & 0o077 != 0 {
            return Err(Error::Input);
        }
        let uid = meta.uid();
        let lock_path = root.join("install.lock");
        if fs::symlink_metadata(&lock_path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(Error::Input);
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(lock_path)
            .map_err(|_| Error::Storage)?;
        let meta = lock.metadata().map_err(|_| Error::Storage)?;
        if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
            return Err(Error::Input);
        }
        lock.try_lock().map_err(|_| Error::Busy)?;
        Ok(Self {
            root: root.into(),
            _lock: lock,
            uid,
        })
    }
    pub(super) fn path(&self, name: &str) -> Result<PathBuf> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || name == "."
            || name == ".."
        {
            return Err(Error::Input);
        }
        Ok(self.root.join(name))
    }
    pub(super) fn load<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let path = self.path(name)?;
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::Storage),
            Ok(meta) => {
                if !meta.is_file()
                    || meta.uid() != self.uid
                    || meta.mode() & 0o077 != 0
                    || meta.len() > 64 * 1024 * 1024
                {
                    return Err(Error::Input);
                }
                let bytes = crate::config::read(&path, 64 * 1024 * 1024, true)
                    .map_err(|_| Error::Storage)?;
                serde_json::from_slice(&bytes)
                    .map(Some)
                    .map_err(|_| Error::Corrupt)
            }
        }
    }
    pub(super) fn save<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec(value).map_err(|_| Error::Input)?;
        if bytes.len() > 64 * 1024 * 1024 {
            return Err(Error::Input);
        }
        self.replace(name, &bytes)
    }
    pub(super) fn replace(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let target = self.path(name)?;
        let temporary = self.path(&format!("stage-{}", uuid::Uuid::new_v4()))?;
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|_| Error::Storage)?;
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| Error::Storage)?;
            fs::rename(&temporary, target).map_err(|_| Error::Storage)?;
            File::open(&self.root)
                .and_then(|f| f.sync_all())
                .map_err(|_| Error::Storage)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
    /// The journal lock excludes concurrent generation. Existing bytes are never overwritten.
    pub(super) fn secret(&self, name: &str, bytes: &[u8]) -> Result<PathBuf> {
        if bytes.len() > 64 * 1024 * 1024 {
            return Err(Error::Input);
        }
        let path = self.path(name)?;
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.is_file() || meta.uid() != self.uid || meta.mode() & 0o077 != 0 {
                    return Err(Error::Input);
                }
                let existing = crate::config::read(&path, bytes.len() as u64, true)
                    .map_err(|_| Error::Storage)?;
                if existing.as_slice() != bytes {
                    return Err(Error::Conflict);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => self.replace(name, bytes)?,
            Err(_) => return Err(Error::Storage),
        }
        Ok(path)
    }
}
