use rss_mdm_software_release as rel;
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Change {
    Candidate {
        resource: String,
        version: String,
        expected_resource_revision: u64,
        resource_digest: [u8; 32],
    },
    Validate {
        ring: Ring,
    },
    Approve {
        ring: Ring,
        publisher_subject: String,
    },
    Authorize {
        ring: Ring,
    },
    Publish {
        ring: Ring,
        publication: [u8; 32],
        attempt: u64,
    },
    Recover {
        ring: Ring,
        publication: [u8; 32],
        attempt: u64,
    },
    Retry {
        ring: Ring,
        attempt: u64,
    },
    Withdraw {
        ring: Ring,
    },
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ring {
    Test,
    Pilot,
    Production,
}
impl Ring {
    pub(super) fn core(self) -> rel::Ring {
        match self {
            Self::Test => rel::Ring::Test,
            Self::Pilot => rel::Ring::Pilot,
            Self::Production => rel::Ring::Production,
        }
    }
}
