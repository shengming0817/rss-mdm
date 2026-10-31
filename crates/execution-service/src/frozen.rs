//! Exact persisted execution publication shape shared with Policy orchestration.
use crate::{action_contract::*, agent_install, enrollment};
use rss_mdm_policy::Frequency;
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
        action: Box<rss_mdm_script_service::FrozenScript>,
        frequency: Frequency,
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
    ) -> std::result::Result<(), Error> {
        let mut permissions = match self {
            Self::Software { .. } => vec![crate::authorization::Permission::SoftwareDeploy],
            Self::Credential { action, .. } => vec![action.permission()],

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
