//! Installation input fingerprint and application revision. Tenant material selection belongs to domain owners.
use super::{Error, Result};
use serde_json::Value;

pub(super) fn fingerprint(runtime: &Value) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut value = runtime.clone();
    value
        .as_object_mut()
        .ok_or(Error::Corrupt)?
        .remove("runtime_binding");
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&value).map_err(|_| Error::Corrupt)?)
    ))
}
