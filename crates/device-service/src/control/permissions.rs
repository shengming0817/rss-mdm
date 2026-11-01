use crate::control::{Error, authorization::Permission as P};
pub(super) fn authorize(
    snapshot: &crate::control::authorization::Snapshot,
    proof: &crate::control::authorization::context::AuthorizedPrincipal,
    device: Option<&str>,
    permission: P,
) -> Result<(), Error> {
    if permission.device() && device.is_none() {
        snapshot.require_all_devices(proof, permission)?;
    } else {
        snapshot.require(proof, permission, device)?;
    }
    Ok(())
}
