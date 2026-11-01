//! Device-owned immutable retirement publication, consumed by Policy and the Device worker.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frozen {
    UnmanageDevice {
        schedule: rss_mdm_policy::schedule::Schedule,
        run_lifetime_seconds: u32,
        actor: crate::control::authorization::Actor,
    },
}
