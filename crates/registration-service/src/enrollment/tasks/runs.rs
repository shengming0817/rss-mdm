//! A Enrollment Run is the stable task identity; collection reports are per attempt.
use crate::enrollment::tasks::Target;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::activity::{ActivityOrigin, ActivityUser};
use rss_mdm_task_state::RunState;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    #[serde(deserialize_with = "required_activity_user")]
    pub activity_user: Option<ActivityUser>,
    pub authorization: wire::TaskAuthorization,
    pub pending_scope: Option<Uuid>,
}

fn required_activity_user<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<ActivityUser>, D::Error> {
    Option::<ActivityUser>::deserialize(deserializer)
}

pub struct Run {
    pub id: Uuid,
    pub policy_version: Uuid,
    /// Logical resource identity is frozen at admission, independent of Policy/version.
    pub origin: ActivityOrigin,
    pub target: Target,
    pub available_at: i64,
    pub deadline: i64,
    pub state: RunState,
    pub result: Option<wire::EnrollmentEntryOutcome>,
    pub invocation: Option<Invocation>,
    pub source_objects: Vec<crate::participants::scope::DeviceObject>,
}
