//! Bounded ZIP validation without extraction or execution.
//! ref: zip-rs v8.6.0 src/read/zip_archive.rs
use super::*;
use rss_mdm_resource::{BundleManifest, Declaration, SoftwareDefinition, Version};
use rss_mdm_software_service::catalog::{self, ContentPort, VerifiedContent};
use std::collections::BTreeSet;
struct PinnedSoftware {
    digest: [u8; 32],
    _files: Vec<Verified>,
    _permit: OwnedSemaphorePermit,
}
impl VerifiedContent for PinnedSoftware {
    fn resource_digest(&self) -> [u8; 32] {
        self.digest
    }
}
impl ContentPort for Store {
    fn verify<'a>(&'a self, version: &'a Version) -> catalog::ContentFuture<'a> {
        Box::pin(async move {
            let permit = self
                .transfers
                .clone()
                .try_acquire_owned()
                .map_err(|_| catalog::Error::Content)?;
            let directory = self.directory.clone();
            let protection = self.protection.clone();
            let tenant = self.tenant;
            let config = self.config.clone();
            let version = version.clone();
            let timer = self.timer.clone();
            let deadline = self.deadline().map_err(|_| catalog::Error::Content)?;
            tokio::task::spawn_blocking(move || {
                let store = Store {
                    protection,
                    tenant,
                    directory,
                    config,
                    transfers: Arc::new(Semaphore::new(1)),
                    timer,
                };
                let mut files: Vec<Verified> = Vec::new();
                let mut seen = std::collections::BTreeMap::new();
                for variant in version.variants() {
                    let Declaration::Software { definition } = variant.declaration() else {
                        return Err(catalog::Error::Input);
                    };
                    for artifact in definition.materials() {
                        let artifact = artifact.artifact().map_err(|_| catalog::Error::Input)?;
                        let coordinate = (artifact.length(), artifact.digest().bytes());
                        let index = if let Some(index) = seen.get(&coordinate) {
                            *index
                        } else {
                            if files.len() >= 128 {
                                return Err(catalog::Error::Content);
                            }
                            let file = store
                                .verify_sync(&artifact, deadline)
                                .map_err(|_| catalog::Error::Content)?;
                            let index = files.len();
                            files.push(file);
                            seen.insert(coordinate, index);
                            index
                        };
                        if &artifact == definition.primary()
                            && definition.spec().behavior.bundle().is_some()
                        {
                            validate(
                                &mut files[index].file,
                                definition,
                                &store.config,
                                store.timer.as_ref(),
                                deadline,
                            )
                            .map_err(|_| catalog::Error::Content)?;
                        }
                    }
                    if let rss_mdm_resource::SoftwareBehavior::Msix(msix) =
                        &definition.spec().behavior
                    {
                        let coordinate = (
                            definition.primary().length(),
                            definition.primary().digest().bytes(),
                        );
                        let index = *seen.get(&coordinate).ok_or(catalog::Error::Content)?;
                        let _temporary =
                            if let rss_mdm_resource::MsixContainer::Bundle { members, .. } =
                                &msix.container
                            {
                                Some(
                                    store
                                        .native_temporary_space(
                                            members
                                                .iter()
                                                .map(|member| member.length)
                                                .max()
                                                .ok_or(catalog::Error::Content)?,
                                        )
                                        .map_err(|_| catalog::Error::Content)?,
                                )
                            } else {
                                None
                            };
                        super::native::msix(
                            &mut files[index].file,
                            msix,
                            &store.config,
                            store.timer.as_ref(),
                            deadline,
                        )
                        .map_err(|_| catalog::Error::Content)?;
                    }
                }
                Ok(Box::new(PinnedSoftware {
                    digest: version.digest().bytes(),
                    _files: files,
                    _permit: permit,
                }) as Box<dyn VerifiedContent>)
            })
            .await
            .map_err(|_| catalog::Error::Content)?
        })
    }
}
fn invalid() -> Error {
    Error::Malformed
}
fn u16le(b: &[u8]) -> u64 {
    u16::from_le_bytes(b.try_into().expect("fixed field")) as u64
}
fn u32le(b: &[u8]) -> u64 {
    u32::from_le_bytes(b.try_into().expect("fixed field")) as u64
}
fn u64le(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().expect("fixed field"))
}
fn read_at<const N: usize>(file: &mut File, offset: u64) -> Result<[u8; N], Error> {
    let mut b = [0; N];
    file.seek(SeekFrom::Start(offset)).map_err(|_| invalid())?;
    file.read_exact(&mut b).map_err(|_| invalid())?;
    Ok(b)
}
// Check directory budgets and every raw name BEFORE ZipArchive allocates/deduplicates metadata.
pub(super) fn directory(file: &mut File, config: &Config) -> Result<(u64, u64), Error> {
    let length = file.metadata().map_err(|_| invalid())?.len();
    let end = length.checked_sub(22).ok_or_else(invalid)?;
    let e = read_at::<22>(file, end)?;
    if &e[..4] != b"PK\x05\x06" || e[4..8] != [0; 4] || e[20..22] != [0; 2] {
        return Err(invalid());
    }
    let (mut count, mut size, mut offset) =
        (u16le(&e[10..12]), u32le(&e[12..16]), u32le(&e[16..20]));
    let mut directory_end = end;
    if count == 65535 || size == u32::MAX as u64 || offset == u32::MAX as u64 {
        let locator = read_at::<20>(file, end.checked_sub(20).ok_or_else(invalid)?)?;
        if &locator[..4] != b"PK\x06\x07"
            || u32le(&locator[4..8]) != 0
            || u32le(&locator[16..20]) != 1
        {
            return Err(invalid());
        }
        let position = u64le(&locator[8..16]);
        let e = read_at::<56>(file, position)?;
        if &e[..4] != b"PK\x06\x06"
            || u64le(&e[4..12]) != 44
            || position.checked_add(76) != Some(end)
            || e[16..24] != [0; 8]
            || u64le(&e[24..32]) != u64le(&e[32..40])
        {
            return Err(invalid());
        }
        count = u64le(&e[32..40]);
        size = u64le(&e[40..48]);
        offset = u64le(&e[48..56]);
        directory_end = position;
    } else if u16le(&e[8..10]) != count {
        return Err(invalid());
    }
    if count == 0
        || count > config.max_bundle_entries as u64 + 1
        || size > 32 * 1024 * 1024
        || offset.checked_add(size) != Some(directory_end)
    {
        return Err(invalid());
    }
    let mut names = BTreeSet::new();
    let mut position = offset;
    for _ in 0..count {
        let h = read_at::<46>(file, position)?;
        if &h[..4] != b"PK\x01\x02" {
            return Err(invalid());
        }
        let name_len = u16le(&h[28..30]);
        let extra = u16le(&h[30..32]);
        let comment = u16le(&h[32..34]);
        if name_len == 0
            || name_len > 1024
            || extra > 4096
            || comment != 0
            || u16le(&h[34..36]) != 0
        {
            return Err(invalid());
        }
        let mut bytes = vec![0; name_len as usize];
        file.read_exact(&mut bytes).map_err(|_| invalid())?;
        let name = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
        rss_mdm_resource::bundle_path(name).map_err(|_| invalid())?;
        if !names.insert(name.to_ascii_lowercase()) {
            return Err(invalid());
        }
        position = position
            .checked_add(46 + name_len + extra + comment)
            .ok_or_else(invalid)?;
        if position > directory_end {
            return Err(invalid());
        }
    }
    if position != directory_end {
        return Err(invalid());
    }
    Ok((count, offset))
}
pub(super) fn validate(
    file: &mut File,
    definition: &SoftwareDefinition,
    config: &Config,
    timer: &dyn Clock,
    deadline: Deadline,
) -> Result<(), Error> {
    let expected = definition.spec().behavior.bundle().ok_or_else(invalid)?;
    let (count, central) = directory(file, config)?;
    let mut local = file.try_clone().map_err(|_| invalid())?;
    let mut archive = zip::ZipArchive::with_config(
        zip::read::Config {
            archive_offset: zip::read::ArchiveOffset::Known(0),
        },
        file,
    )
    .map_err(|_| invalid())?;
    if archive.len() as u64 != count
        || archive.len() != expected.entries.len() + 1
        || archive.has_overlapping_files().map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let mut total = 0u64;
    for index in 0..archive.len() {
        if timer.now() >= deadline.instant() {
            return Err(storage());
        }
        let entry = archive.by_index_raw(index).map_err(|_| invalid())?;
        if entry.encrypted()
            || !entry.is_file()
            || entry
                .unix_mode()
                .is_some_and(|m| !matches!(m & 0o170000, 0 | 0o100000))
            || !matches!(
                entry.compression(),
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            )
        {
            return Err(invalid());
        }
        let h = read_at::<30>(&mut local, entry.header_start())?;
        if &h[..4] != b"PK\x03\x04" || u16le(&h[26..28]) != entry.name().len() as u64 {
            return Err(invalid());
        }
        let central_header = read_at::<46>(&mut local, entry.central_header_start())?;
        if h[6..10] != central_header[8..12]
            || u16le(&h[6..8]) & !0x080e != 0
            || u16le(&h[28..30]) > 4096
        {
            return Err(invalid());
        }
        let descriptor = u16le(&h[6..8]) & 8 != 0;
        for (local_field, central_field) in [
            (&h[14..18], &central_header[16..20]),
            (&h[18..22], &central_header[20..24]),
            (&h[22..26], &central_header[24..28]),
        ] {
            if local_field != central_field && !(descriptor && u32le(local_field) == 0) {
                return Err(invalid());
            }
        }
        let mut raw = vec![0; entry.name().len()];
        local
            .seek(SeekFrom::Start(entry.header_start() + 30))
            .map_err(|_| invalid())?;
        local.read_exact(&mut raw).map_err(|_| invalid())?;
        if raw != entry.name().as_bytes() {
            return Err(invalid());
        }
        let data = entry.data_start().ok_or_else(invalid)?;
        if data
            .checked_add(entry.compressed_size())
            .is_none_or(|end| end > central)
        {
            return Err(invalid());
        }
        total = total.checked_add(entry.size()).ok_or_else(invalid)?;
        if total > config.max_bundle_bytes
            || entry.size()
                > entry
                    .compressed_size()
                    .max(1)
                    .saturating_mul(config.max_expansion_ratio)
        {
            return Err(invalid());
        }
        drop(entry);
        let mut entry = archive.by_index(index).map_err(|_| invalid())?;
        if entry.name() == "manifest.json" {
            if entry.size() > 1_048_576 {
                return Err(invalid());
            }
            let mut bytes = Vec::new();
            Read::by_ref(&mut entry)
                .take(1_048_577)
                .read_to_end(&mut bytes)
                .map_err(|_| invalid())?;
            let actual: BundleManifest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            if &actual != expected
                || bytes != serde_json::to_vec(expected).map_err(|_| invalid())?
            {
                return Err(invalid());
            }
        } else {
            let expected = expected.entries.get(entry.name()).ok_or_else(invalid)?;
            if entry.size() != expected.length {
                return Err(invalid());
            }
            let mut hash = Sha256::new();
            let mut buffer = [0; 65_536];
            let mut length = 0u64;
            loop {
                if timer.now() >= deadline.instant() {
                    return Err(storage());
                }
                let n = entry.read(&mut buffer).map_err(|_| invalid())?;
                if n == 0 {
                    break;
                }
                length += n as u64;
                if length > expected.length {
                    return Err(invalid());
                }
                hash.update(&buffer[..n]);
            }
            if length != expected.length || hash.finalize().as_slice() != expected.sha256 {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
