//! Native content comparison uses the same process key as protected execution storage.
use crate::{Error, Failure};
use rss_mdm_native_protection::{ProtectionContext, Protector};
use rss_request_context::TenantId;
use serde::Serialize;
use zeroize::Zeroizing;
pub(crate) fn fingerprint(
    protector: &Protector,
    tenant: TenantId,
    owner: &str,
    purpose: &str,
    value: &impl Serialize,
) -> Result<Vec<u8>, Error> {
    let aad = ProtectionContext::new(tenant, owner, purpose, 1)
        .map_err(|_| Error::Malformed)?
        .derive();
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::Malformed)?);
    protector
        .mac(&bytes, &aad)
        .map(Vec::from)
        .map_err(|_| Error::Unavailable(Failure::NativeProtection))
}

pub(crate) fn aad(
    tenant: TenantId,
    purpose: &str,
    identity: &impl Serialize,
) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    let owner = serde_json::to_string(identity).map_err(|_| Error::Malformed)?;
    ProtectionContext::new(tenant, &owner, purpose, 1)
        .map(|c| c.derive())
        .map_err(|_| Error::Malformed)
}
