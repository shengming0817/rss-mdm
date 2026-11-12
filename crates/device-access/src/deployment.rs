//! Verified native facts are scoped to a DA registration, never an MDM channel identity.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub tenant: Uuid,
    pub installation: Uuid,
    pub device: rss_mdm_agent_wire::DeviceId,
    pub authority: Uuid,
    pub sequence: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
    pub policy: Uuid,
    pub policy_version: Uuid,
    pub deployment: Deployment,
    /// Exact configuration delivery attested by the configured deployment authority.
    pub configuration: Option<ConfigurationDeployment>,
    pub local_session: Option<rss_mdm_agent_wire::runtime::AccessLocalSession>,
    /// Complete macOS PSSO application facts, signed by the deployment authority. These
    /// are business observations, never Agent task acknowledgements or delivery receipts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applications: Vec<rss_mdm_agent_wire::runtime::AccessResult>,
}
/// Independently verified delivery; a configuration signature alone cannot create this fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationDeployment {
    pub artifact: Uuid,
    pub digest: String,
    pub native_digest: String,
    pub delivery: rss_mdm_agent_wire::da::DeliveryPermission,
    pub state: rss_mdm_agent_wire::da::SourceState,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "platform",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Deployment {
    Macos {
        configuration: String,
        application_id: String,
        application_version: String,
        application_installed: bool,
        profile_identifier: String,
        profile_uuid: Uuid,
        profile_matched: bool,
        architecture: String,
        os_version: [u32; 4],
        user_helper: bool,
        system_broker: bool,
    },
    Windows {
        interactive_broker: bool,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlatformConfiguration {
    pub configuration: String,
    pub application_id: String,
    pub application_version: String,
    pub profile_identifier: String,
    pub authorities: std::collections::BTreeMap<Uuid, String>,
}
impl Observation {
    pub fn validate(&self, now: i64) -> Result<(), crate::Error> {
        if let Some(proof) = &self.configuration
            && (proof.artifact.is_nil()
                || !rss_mdm_agent_wire::da::valid_digest(&proof.digest)
                || !rss_mdm_agent_wire::da::valid_digest(&proof.native_digest))
        {
            return Err(crate::Error);
        }

        if self.tenant.is_nil()
            || self.installation.is_nil()
            || self.authority.is_nil()
            || self.policy.is_nil()
            || self.policy_version.is_nil()
            || self.sequence < 1
            || self.issued_at < 0
            || self.issued_at > now
            || self.expires_at <= now
            || self.expires_at.saturating_sub(self.issued_at) > 86400
            || self.applications.len() > 16
            || (!self.applications.is_empty()
                && !matches!(self.deployment, Deployment::Macos { .. }))
        {
            return Err(crate::Error);
        }
        let platform = match self.deployment {
            Deployment::Macos { .. } => rss_mdm_agent_wire::runtime::TaskPlatform::Macos,
            Deployment::Windows { .. } => rss_mdm_agent_wire::runtime::TaskPlatform::Windows,
        };
        let mut bindings = std::collections::BTreeSet::new();
        for application in &self.applications {
            application
                .validate_for(platform)
                .map_err(|_| crate::Error)?;
            if !bindings.insert(application.binding_id)
                || !matches!(
                    application.effect,
                    rss_mdm_agent_wire::runtime::AccessEffect::Applied { .. }
                )
            {
                return Err(crate::Error);
            }
        }
        if let Some(session) = &self.local_session {
            session.validate().map_err(|_| crate::Error)?;
            if !matches!(
                (&self.deployment, &session.account),
                (
                    Deployment::Macos { .. },
                    rss_mdm_agent_wire::runtime::AccessAccount::Macos { .. }
                ) | (
                    Deployment::Windows { .. },
                    rss_mdm_agent_wire::runtime::AccessAccount::Windows { .. }
                )
            ) {
                return Err(crate::Error);
            }
        }
        if let Deployment::Macos {
            configuration,
            application_id,
            application_version,
            profile_identifier,
            profile_uuid,
            architecture,
            ..
        } = &self.deployment
            && (configuration.is_empty()
                || configuration.len() > 256
                || application_id.is_empty()
                || application_id.len() > 256
                || application_version.is_empty()
                || application_version.len() > 128
                || profile_identifier.is_empty()
                || profile_identifier.len() > 256
                || profile_uuid.is_nil()
                || architecture.len() > 32)
        {
            return Err(crate::Error);
        }
        Ok(())
    }
    pub fn qualifies(&self, expected: &PlatformConfiguration, profile: Uuid, now: i64) -> bool {
        self.validate(now).is_ok()
            && !self.revoked
            && match &self.deployment {
                Deployment::Macos {
                    configuration,
                    application_id,
                    application_version,
                    application_installed,
                    profile_identifier,
                    profile_uuid,
                    profile_matched,
                    architecture,
                    os_version,
                    user_helper,
                    system_broker,
                } => {
                    configuration == &expected.configuration
                        && application_id == &expected.application_id
                        && application_version == &expected.application_version
                        && *application_installed
                        && profile_identifier == &expected.profile_identifier
                        && *profile_uuid == profile
                        && *profile_matched
                        && architecture == "aarch64"
                        && *os_version >= [26, 4, 0, 0]
                        && *user_helper
                        && *system_broker
                }
                Deployment::Windows { .. } => false,
            }
    }
    pub fn windows_session(&self, now: i64) -> bool {
        self.validate(now).is_ok()
            && !self.revoked
            && matches!(
                self.deployment,
                Deployment::Windows {
                    interactive_broker: true
                }
            )
            && self.local_session.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_qualification_requires_platform_and_bounded_current_evidence() {
        let configuration = PlatformConfiguration {
            configuration: "config".into(),
            application_id: "com.example.da".into(),
            application_version: "1".into(),
            profile_identifier: "com.example.psso".into(),
            authorities: Default::default(),
        };
        let profile = Uuid::new_v4();
        let mut proof = Observation {
            configuration: None,
            tenant: Uuid::new_v4(),
            installation: Uuid::new_v4(),
            device: rss_mdm_agent_wire::DeviceId::parse("2393c3f3-4e8c-5c75-b7cf-f4978eb921df")
                .unwrap(),

            authority: Uuid::new_v4(),
            sequence: 1,
            issued_at: 100,
            expires_at: 200,
            revoked: false,
            policy: Uuid::new_v4(),
            policy_version: Uuid::new_v4(),
            deployment: Deployment::Macos {
                configuration: configuration.configuration.clone(),
                application_id: configuration.application_id.clone(),
                application_version: configuration.application_version.clone(),
                application_installed: true,
                profile_identifier: configuration.profile_identifier.clone(),
                profile_uuid: profile,
                profile_matched: true,
                architecture: "aarch64".into(),
                os_version: [26, 4, 0, 0],
                user_helper: true,
                system_broker: true,
            },
            local_session: None,
            applications: Vec::new(),
        };
        assert!(proof.qualifies(&configuration, profile, 199));
        assert!(!proof.qualifies(&configuration, profile, 200));
        assert!(!proof.qualifies(&configuration, Uuid::new_v4(), 199));
        if let Deployment::Macos { os_version, .. } = &mut proof.deployment {
            *os_version = [26, 3, 99, 0];
        }
        assert!(!proof.qualifies(&configuration, profile, 199));
        proof.deployment = Deployment::Windows {
            interactive_broker: true,
        };
        assert!(!proof.qualifies(&configuration, profile, 199));
        assert!(!proof.windows_session(199));
        proof.local_session = Some(rss_mdm_agent_wire::runtime::AccessLocalSession {
            account: rss_mdm_agent_wire::runtime::AccessAccount::Windows {
                sid: "S-1-5-21-1-2-3-1001".into(),
                authority: rss_mdm_agent_wire::runtime::AccessWindowsAuthority::Local,
            },
            session_id: Uuid::new_v4(),
        });
        assert!(proof.windows_session(199));
        proof.revoked = true;
        assert!(!proof.windows_session(199));
        proof.revoked = false;
        proof.expires_at = 100 + 86401;
        assert!(proof.validate(199).is_err());
    }
}
