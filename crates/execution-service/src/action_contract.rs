//! Frozen execution contract. It deliberately excludes authors, authority rows and Scope internals.
use rss_mdm_policy::schedule::Schedule;
pub use rss_mdm_policy::{Architecture, Platform};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionInput {
    pub platform: Platform,
    pub architecture: Architecture,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
}
/// Enterprise software input frozen at Policy publication, before per-device admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenSoftwareAction {
    pub native_packages: BTreeMap<rss_mdm_policy::SoftwareTarget, crate::native_software::Package>,
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

pub trait ScheduledInput {
    fn schedule(&self) -> &Schedule;
}
