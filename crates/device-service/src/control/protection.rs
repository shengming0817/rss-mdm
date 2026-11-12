//! Maps shared canonical protection failures into this owner's error vocabulary.
use crate::control::{Error, Failure};
fn error(e: rss_mdm_native_protection::canonical::Error) -> Error {
    match e {
        rss_mdm_native_protection::canonical::Error::Malformed => Error::Malformed,
        rss_mdm_native_protection::canonical::Error::Protection => {
            Error::Unavailable(Failure::NativeProtection)
        }
    }
}
pub fn fingerprint(
    p: &rss_mdm_native_protection::Protector,
    t: rss_request_context::TenantId,
    o: &rss_mdm_agent_wire::DeviceId,
    purpose: &str,
    v: &impl serde::Serialize,
) -> Result<Vec<u8>, Error> {
    rss_mdm_native_protection::canonical::fingerprint(p, t, &o.to_string(), purpose, v)
        .map_err(error)
}
pub fn aad(
    t: rss_request_context::TenantId,
    purpose: &str,
    v: &impl serde::Serialize,
) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    rss_mdm_native_protection::canonical::aad(t, purpose, v).map_err(error)
}
