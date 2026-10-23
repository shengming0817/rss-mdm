//! Published content pins and bounded ZIP directory location.
//! ref: zip-rs v8.6.0 src/read/zip_archive.rs
use super::*;
use rss_mdm_resource::{Declaration, Version};
use rss_mdm_software_service::catalog::{self, ContentPort, VerifiedContent};
use std::collections::BTreeSet;
struct PinnedSoftware {
    digest: [u8; 32],
    _files: Vec<crate::reader::Pinned>,
}
impl VerifiedContent for PinnedSoftware {
    fn resource_digest(&self) -> [u8; 32] {
        self.digest
    }
}
impl ContentPort for Store {
    fn verify<'a>(&'a self, version: &'a Version) -> catalog::ContentFuture<'a> {
        Box::pin(async move {
            let mut materials = Vec::new();
            for variant in version.variants() {
                let Declaration::Software { definition } = variant.declaration() else {
                    return Err(catalog::Error::Input);
                };
                for material in definition.materials() {
                    let a = material.artifact().map_err(|_| catalog::Error::Input)?;
                    if !materials.contains(&(a.clone(), StorageClass::Artifact)) {
                        materials.push((a, StorageClass::Artifact));
                    }
                }
            }
            let files = self
                .pin_materials(&materials)
                .await
                .map_err(|_| catalog::Error::Content)?;
            for variant in version.variants() {
                let Declaration::Software { definition } = variant.declaration() else {
                    return Err(catalog::Error::Input);
                };
                for signature in &definition.spec().signatures {
                    if let Some(evidence) = &signature.evidence {
                        if evidence.length > 65536 {
                            return Err(catalog::Error::Input);
                        }
                        let artifact = evidence.artifact().map_err(|_| catalog::Error::Input)?;
                        let file = self
                            .verify_ready_report(&artifact)
                            .await
                            .map_err(|_| catalog::Error::Content)?;
                        #[derive(serde::Deserialize)]
                        #[serde(deny_unknown_fields)]
                        struct Report {
                            sha256: [u8; 32],
                            mechanism: rss_mdm_resource::SignatureMechanism,
                            publisher: String,
                            verified: bool,
                        }
                        let report: Report =
                            serde_json::from_slice(&file).map_err(|_| catalog::Error::Content)?;
                        let installer = definition
                            .spec()
                            .artifacts
                            .get(&signature.artifact)
                            .ok_or(catalog::Error::Input)?;
                        if !report.verified
                            || report.sha256 != installer.sha256
                            || report.mechanism != signature.mechanism
                            || report.publisher != signature.publisher
                        {
                            return Err(catalog::Error::Content);
                        }
                    }
                }
            }
            Ok(Box::new(PinnedSoftware {
                digest: version.digest().bytes(),
                _files: files,
            }) as Box<dyn VerifiedContent>)
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
        || count > config.max_bundle_entries as u64
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
