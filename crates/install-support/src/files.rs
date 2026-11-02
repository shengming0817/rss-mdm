//! Bounded operator material reads. Inspect the opened file, never follow symlinks.
use std::{io::Read, path::Path};
use zeroize::Zeroizing;
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum Error {
    #[error("material file unavailable")]
    Access,
    #[error("material file shape or permissions rejected")]
    Shape,
    #[error("material file budget exceeded")]
    Size,
    #[error("secret encoding rejected")]
    Encoding,
    #[error("secret contents rejected")]
    Contents,
}
pub fn read(path: &Path, limit: u64, private: bool) -> Result<Zeroizing<Vec<u8>>, Error> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Access)?;
    let meta = file.metadata().map_err(|_| Error::Access)?;
    if !meta.is_file() || (private && meta.permissions().mode() & 0o077 != 0) {
        return Err(Error::Shape);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Access)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Size);
    }
    Ok(bytes)
}
pub fn secret(path: &Path) -> Result<Zeroizing<String>, Error> {
    let bytes = read(path, 16384, true)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::Encoding)?
        .trim_end_matches('\n');
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(Error::Contents);
    }
    Ok(Zeroizing::new(text.to_owned()))
}
