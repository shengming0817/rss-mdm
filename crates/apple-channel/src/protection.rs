//! All native attempt phases use the same authenticated storage format.
use crate::{Error, Failure};
use rss_mdm_native_protection::{DerivedAad, Plaintext, ProtectionContext, Protector};
use rss_request_context::TenantId;
use uuid::Uuid;
#[derive(Clone, Copy)]
pub(crate) enum Part {
    Request,
    Response,
    Replay,
}
fn failure() -> Error {
    Error::Unavailable(Failure::AppleStorage)
}
pub(crate) fn aad(tenant: &str, device: &str, id: Uuid, part: Part) -> Result<DerivedAad, Error> {
    let tenant = TenantId::parse(tenant).map_err(|_| failure())?;
    let owner = serde_json::to_string(&(device, id)).map_err(|_| failure())?;
    let purpose = match part {
        Part::Request => "apple.attempt.request",
        Part::Response => "apple.attempt.response",
        Part::Replay => "apple.attempt.response-replay",
    };
    ProtectionContext::new(tenant, &owner, purpose, 1)
        .map(|c| c.derive())
        .map_err(|_| failure())
}
pub(crate) fn seal(
    protection: &Protector,
    tenant: &str,
    device: &str,

    id: Uuid,
    part: Part,
    bytes: &[u8],
) -> Result<Vec<u8>, Error> {
    protection
        .seal_bytes(bytes, &aad(tenant, device, id, part)?)
        .map_err(|_| failure())
}
pub(crate) fn open(
    protection: &Protector,
    tenant: &str,
    device: &str,

    id: Uuid,
    part: Part,
    bytes: &[u8],
) -> Result<Plaintext, Error> {
    protection
        .open_bytes(bytes, &aad(tenant, device, id, part)?)
        .map_err(|_| failure())
}
