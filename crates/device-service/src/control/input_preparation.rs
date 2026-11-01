//! Current permission required by fixed Device controls and unmanage.
use crate::control::Error;
use crate::control::authorization::{Permission, context::AuthorizedPrincipal};
use rss_mdm_policy::Action;
/// Check the execution capabilities required by a prepared action.
pub fn authorize_action(
    snapshot: &crate::control::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    action: &rss_mdm_policy::Action,
) -> std::result::Result<(), crate::control::Error> {
    snapshot.require_all_devices(proof, action_permission(action)?)?;
    Ok(())
}

/// Primary operation permission shared by publication and targeted admission.
pub fn action_permission(action: &Action) -> std::result::Result<Permission, Error> {
    Ok(match *action {
        Action::UnmanageDevice { .. } => Permission::DeviceUnmanage,
        _ => return Err(Error::Unsupported),
    })
}
