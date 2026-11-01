use rss_mdm_policy::schedule::Schedule;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
/// Enterprise software input frozen at Policy publication, before per-device admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenSoftwareAction {
    pub native_packages: BTreeMap<rss_mdm_policy::SoftwareTarget, super::native::Package>,
    pub channel: rss_mdm_policy::SoftwareChannel,
    pub delivery: rss_mdm_policy::SoftwareDelivery,
    pub resource: String,
    pub version: String,
    pub variants: BTreeMap<rss_mdm_policy::SoftwareTarget, String>,
    pub resource_digest: [u8; 32],
    pub intent: rss_mdm_policy::SoftwareIntent,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Published {
    Software {
        action: Box<FrozenSoftwareAction>,
    },
    AgentInstall {
        action: Box<crate::installation::package::FrozenInstall>,
    },
}
