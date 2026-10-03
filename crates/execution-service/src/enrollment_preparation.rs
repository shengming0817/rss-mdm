//! Independent Agent policy for the standard MDM enrollment entry.
use crate::{
    Error, Inputs,
    authorization::{Permission, context::AuthorizedPrincipal},
};
use rss_mdm_authorization_service::UserGrant;
use rss_mdm_policy::schedule::Schedule;
use uuid::Uuid;

use crate::enrollment::FrozenEnrollment;
impl Inputs {
    pub(crate) fn prepare_enrollment(
        &self,
        proof: &AuthorizedPrincipal,
        snapshot: &crate::authorization::Snapshot,
        organization: Uuid,
        schedule: &Schedule,
        lifetime: u32,
    ) -> std::result::Result<FrozenEnrollment, Error> {
        if !self.signing_enabled {
            return Err(Error::Unsupported);
        }
        let entries = &self.enrollment_entries;
        if organization.to_string() != proof.tenant_id()
            || (entries.windows.is_none() && entries.macos.is_none())
        {
            return Err(Error::Unsupported);
        }
        entries.validate()?;
        Ok(FrozenEnrollment {
            organization,
            schedule: schedule.clone(),
            run_lifetime_seconds: lifetime,
            entries: entries.clone(),
            grant: UserGrant::all_devices(snapshot, proof, Permission::Enrollment)?,
        })
    }
}
