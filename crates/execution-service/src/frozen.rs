//! Exact persisted execution publication shape shared with Policy orchestration.
use crate::{action_contract::*, agent_install, configuration, enrollment};
use rss_mdm_policy::{Exit, Frequency};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frozen {
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
        grants: std::collections::BTreeMap<String, Vec<crate::authorization::UserGrant>>,
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
    pub fn authorize_native(
        &mut self,
        proof: &AuthorizedPrincipal,
        snapshot: &crate::authorization::Snapshot,
        devices: Option<&std::collections::BTreeSet<String>>,
        key: &rss_mdm_native_protection::Protector,
        tenant: rss_request_context::TenantId,
        owner: Option<configuration::Owner>,
    ) -> std::result::Result<(), Error> {
        let (mut permissions, grants) = match self {
            Self::Configuration { native, grants, .. } => {
                let native = native.open(key, tenant, owner.ok_or(Error::Malformed)?)?;
                let mut permissions = native.apply.permissions()?;
                if let Some(remove) = &native.remove {
                    permissions.extend(remove.permissions()?);
                }
                (permissions, grants)
            }
            Self::NativeCollection { action, .. } => (action.permissions()?, &mut action.grants),
            _ => return Ok(()),
        };
        permissions.sort();
        permissions.dedup();
        if let Some(devices) = devices {
            for device in devices {
                grants.insert(
                    device.clone(),
                    permissions
                        .iter()
                        .map(|&permission| {
                            crate::permissions::grant(snapshot, proof, Some(device), permission)
                        })
                        .collect::<std::result::Result<_, _>>()?,
                );
            }
        } else {
            grants.insert(
                "*".into(),
                permissions
                    .iter()
                    .map(|&permission| crate::permissions::grant(snapshot, proof, None, permission))
                    .collect::<std::result::Result<_, _>>()?,
            );
        }
        Ok(())
    }
}
