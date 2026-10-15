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
    Publish {
        ring: Ring,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn direct_publication_rejects_retired_actions_and_actor_fields() {
        for action in ["validate", "approve", "authorize"] {
            assert!(
                serde_json::from_value::<Change>(json!({"action":action,"ring":"test"})).is_err()
            );
        }
        for field in [
            "publisherSubject",
            "approval",
            "evidence",
            "publication",
            "attempt",
        ] {
            let mut value = json!({"action":"publish","ring":"test"});
            value[field] = json!("retired");
            assert!(serde_json::from_value::<Change>(value).is_err());
        }
        assert!(
            serde_json::from_value::<Change>(json!({"action":"publish","ring":"test"})).is_ok()
        );
    }
}
