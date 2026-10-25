//! Exact persisted execution publication shape shared with Policy orchestration.
use crate::{action_contract::*, agent_install, configuration, enrollment};
use rss_mdm_policy::{Exit, Frequency};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frozen {
    DeviceAccess {
        configuration: rss_mdm_agent_wire::runtime::AccessConfiguration,
    },
    UnmanageDevice {
        schedule: rss_mdm_policy::schedule::Schedule,
        run_lifetime_seconds: u32,
        actor: crate::authorization::Actor,
    },
    Credential {
        action: Box<crate::credential_tasks::FrozenCredential>,
        frequency: Frequency,
    },
    AgentCollection {
        action: Box<FrozenAgentCollection>,
        frequency: Frequency,
    },
    NativeCollection {
        action: Box<FrozenNativeCollection>,
        frequency: Frequency,
    },
    Execution {
        action: Box<FrozenAction>,
        frequency: Frequency,
    },
    Configuration {
        #[serde(rename = "native_sealed")]
        native: configuration::Protected,
        platform: Platform,
        exit: Exit,
        resource_digest: [u8; 32],
    },
    Software {
        action: Box<FrozenSoftwareAction>,
    },
    AgentInstall {
        action: Box<agent_install::FrozenInstall>,
    },
    MdmEnrollment {
        action: Box<enrollment::FrozenEnrollment>,
    },
}

use crate::{Error, authorization::context::AuthorizedPrincipal};
impl Frozen {
    pub(crate) fn authorize_native(
        &mut self,
        proof: &AuthorizedPrincipal,
        snapshot: &crate::authorization::Snapshot,
        devices: Option<&std::collections::BTreeSet<String>>,
        key: &rss_mdm_native_protection::Protector,
        tenant: rss_request_context::TenantId,
        owner: configuration::Owner,
    ) -> std::result::Result<(), Error> {
        let mut permissions = match self {
            Self::Software { .. } => vec![crate::authorization::Permission::SoftwareDeploy],
            Self::Credential { action, .. } => vec![action.permission()],
            Self::Configuration { native, .. } => {
                let native = native.open(key, tenant, owner)?;
                let mut permissions = native.apply.permissions()?;
                if let Some(remove) = &native.remove {
                    permissions.extend(remove.permissions()?);
                }
                permissions
            }
            Self::NativeCollection { action, .. } => action.permissions()?,
            Self::AgentCollection { action, .. } => action.permissions(),
            _ => return Ok(()),
        };
        permissions.sort();
        permissions.dedup();
        if let Some(devices) = devices {
            for device in devices {
                for &permission in &permissions {
                    crate::permissions::authorize(snapshot, proof, Some(device), permission)?;
                }
            }
        } else {
            for permission in permissions {
                crate::permissions::authorize(snapshot, proof, None, permission)?;
            }
        }
        Ok(())
    }
}
