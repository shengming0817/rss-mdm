//! Deployment-owned enrollment entries and immutable execution inputs.
use crate::Error;
use rss_mdm_agent_wire as wire;
use rss_mdm_authorization_service::UserGrant;
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
    pub grant: UserGrant,
}
