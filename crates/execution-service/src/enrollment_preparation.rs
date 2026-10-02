//! Independent Agent policy for the standard MDM enrollment entry.
use crate::{
    Error,
    authorization::{Permission, context::AuthorizedPrincipal},
};
use rss_mdm_authorization_service::UserGrant;
use rss_mdm_policy::Action;

use crate::enrollment::{Entries, FrozenEnrollment};
pub fn freeze(
    proof: &AuthorizedPrincipal,
    snapshot: &crate::authorization::Snapshot,
    action: &Action,
    entries: &Entries,
) -> std::result::Result<FrozenEnrollment, Error> {
    let Action::RequestMdmEnrollment {
        organization,
        schedule,
        run_lifetime_seconds,
    } = action
    else {
        return Err(Error::Malformed);
    };
    if organization.to_string() != proof.tenant_id()
        || (entries.windows.is_none() && entries.macos.is_none())
    {
        return Err(Error::Unsupported);
    }
    entries.validate()?;
    Ok(FrozenEnrollment {
        organization: *organization,
        schedule: schedule.clone(),
        run_lifetime_seconds: *run_lifetime_seconds,
        entries: entries.clone(),
        grant: UserGrant::all_devices(snapshot, proof, Permission::Enrollment)?,
    })
}
