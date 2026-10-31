//! Published execution contract. It deliberately excludes authors, authority rows and Scope internals.
use rss_mdm_policy::schedule::Schedule;
pub use rss_mdm_policy::{Architecture, Platform};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionInput {
    pub platform: Platform,
    pub architecture: Architecture,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
}
pub trait ScheduledInput {
    fn schedule(&self) -> &Schedule;
}
