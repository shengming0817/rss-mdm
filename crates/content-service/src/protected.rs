//! Native snapshots contain sealed records only. Logical identity is independent of ciphertext.
use super::*;
use rss_mdm_native_protection::ProtectionContext;
use zeroize::Zeroizing;
pub(super) const NATIVE_LIMIT: u64 = 16 * 1024 * 1024;
const BLOCK: usize = 65536;
const OVERHEAD: usize = 68;
pub(super) fn reservation(b: &Binding) -> Result<u64, Error> {
    if b.class().protected() && b.length > NATIVE_LIMIT {
        return Err(Error::Malformed);
    }
    let physical = if b.class().protected() {
        b.length + b.length.div_ceil(BLOCK as u64) * OVERHEAD as u64
    } else {
        b.length
    };
    physical
        .checked_add(physical.min(journal::CHUNK))
        .ok_or(Error::Malformed)
}
fn aad(
    tenant: rss_request_context::TenantId,
    a: &Artifact,
    c: StorageClass,
    offset: u64,
    count: u64,
) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    let owner = serde_json::to_string(&(a.digest().bytes(), a.length(), offset, count))
        .map_err(|_| invariant())?;
    ProtectionContext::new(
        tenant,
        &owner,
        &format!("{}.chunk/v1", c.protection_domain()),
        1,
    )
    .map(|v| v.derive())
    .map_err(|_| invariant())
}
pub(super) fn seal(
    protection: &rss_mdm_native_protection::Protector,
    tenant: rss_request_context::TenantId,
    bytes: &[u8],
    a: &Artifact,
    c: StorageClass,
) -> Result<Vec<u8>, Error> {
    if bytes.len() as u64 > NATIVE_LIMIT {
        return Err(Error::Malformed);
    }
    let mut out = Vec::new();
    for (i, part) in bytes.chunks(BLOCK).enumerate() {
        out.extend(
            protection
                .seal_bytes(
                    part,
                    &aad(tenant, a, c, (i * BLOCK) as u64, part.len() as u64)?,
                )
                .map_err(|_| storage())?,
        );
    }
    Ok(out)
}
pub(super) fn plaintext(
    protection: &rss_mdm_native_protection::Protector,
    tenant: rss_request_context::TenantId,
    bytes: &[u8],
    a: &Artifact,
    c: StorageClass,
    count: u64,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if count > NATIVE_LIMIT || count > a.length() {
        return Err(Error::Malformed);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(count as usize));
    let mut cursor = 0;
    let mut offset = 0;
    while offset < count {
        let n = (count - offset).min(BLOCK as u64);
        let end = cursor + n as usize + OVERHEAD;
        let sealed = bytes.get(cursor..end).ok_or(Error::Invariant)?;
        let plain = protection
            .open_bytes(sealed, &aad(tenant, a, c, offset, n)?)
            .map_err(|_| Error::Invariant)?;
        if plain.expose().len() as u64 != n {
            return Err(Error::Invariant);
        }
        out.extend_from_slice(plain.expose());
        offset += n;
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(Error::Invariant);
    }
    Ok(out)
}
