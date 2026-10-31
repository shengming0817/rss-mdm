//! Registration-owned enrollment entries and immutable Agent task inputs.
use crate::Error;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_authorization_service::Actor;
use rss_mdm_policy::Platform;
use rss_mdm_policy::schedule::Schedule;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
/// Deployment-owned organization entries. Policies cannot redirect enrollment elsewhere.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entries {
    pub windows: Option<String>,
    pub macos: Option<String>,
}
impl Entries {
    pub fn validate(&self) -> std::result::Result<(), Error> {
        for platform in [Platform::Windows, Platform::Macos] {
            if let Some(entry) = self.for_platform(platform) {
                entry
                    .validate(match platform {
                        Platform::Windows => wire::TaskPlatform::Windows,
                        Platform::Macos => wire::TaskPlatform::Macos,
                    })
                    .map_err(|_| Error::Malformed)?;
            }
        }
        Ok(())
    }
    pub fn for_platform(&self, platform: Platform) -> Option<wire::EnrollmentEntry> {
        match platform {
            Platform::Windows => self
                .windows
                .clone()
                .map(|server| wire::EnrollmentEntry::Windows { server }),
            Platform::Macos => self
                .macos
                .clone()
                .map(|url| wire::EnrollmentEntry::Macos { url }),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenEnrollment {
    pub organization: Uuid,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
    pub entries: Entries,
    pub actor: Actor,
}

/// Freeze the enrollment entry under the publication caller's current authority.
pub fn prepare(
    entries: &Entries,
    signing_enabled: bool,
    proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    snapshot: &rss_mdm_authorization_service::Snapshot,
    organization: Uuid,
    schedule: &Schedule,
    lifetime: u32,
) -> Result<FrozenEnrollment, Error> {
    if !signing_enabled
        || organization.to_string() != proof.tenant_id()
        || (entries.windows.is_none() && entries.macos.is_none())
    {
        return Err(Error::Configuration);
    }
    entries.validate()?;
    snapshot.require_all_devices(proof, rss_mdm_authorization_service::Permission::Enrollment)?;
    Ok(FrozenEnrollment {
        organization,
        schedule: schedule.clone(),
        run_lifetime_seconds: lifetime,
        entries: entries.clone(),
        actor: proof.actor(),
    })
}
