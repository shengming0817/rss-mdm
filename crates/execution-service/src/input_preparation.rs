//! Current permission required by the remaining Execution action.
use crate::Error;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use rss_mdm_policy::Action;
/// Check the execution capabilities required by a prepared action.
pub fn authorize_action(
    snapshot: &crate::authorization::Snapshot,
    proof: &AuthorizedPrincipal,
    action: &rss_mdm_policy::Action,
) -> std::result::Result<(), crate::Error> {
    snapshot.require_all_devices(proof, action_permission(action)?)?;
    Ok(())
}

/// Primary operation permission shared by publication and targeted admission.
pub fn action_permission(action: &Action) -> std::result::Result<Permission, Error> {
    Ok(match *action {
        Action::Execution { .. } => Permission::ScriptExecute,
        Action::NativeCollection { .. }
        | Action::AgentCollection { .. }
        | Action::TelemetryProfile { .. } => Permission::InventoryCollect,
        Action::Configuration { .. } => Permission::ConfigurationWrite,

        Action::UnmanageDevice { .. } => Permission::DeviceUnmanage,
        _ => return Err(Error::Unsupported),
    })
}
