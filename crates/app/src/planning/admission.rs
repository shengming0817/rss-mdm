//! Planning's bounded execution projection for all command paths.
use super::*;
use crate::planning::error::{PlanFailureReason as Reason, PlanStage};
use sqlx::{PgConnection, Row};

pub(crate) struct Admission {
    pub plan: PlanExecutionAdmission,
    pub saved_revision: Option<i64>,
    pub current: bool,
}
pub(crate) async fn read_on(
    c: &mut PgConnection,
    id: Uuid,
) -> std::result::Result<Option<Admission>, Error> {
    let row = sqlx::query("SELECT * FROM mdm_planning.plan_execution_admission($1::uuid)")
        .bind(id.to_string())
        .fetch_optional(c)
        .await
        .map_err(crate::database::db)?;
    row.map(|r| {
        let bad_data = || Error::Unavailable(Failure::PlanningStorage);
        let plan: PlanExecutionAdmission =
            serde_json::from_value(r.try_get("document").map_err(|_| bad_data())?)
                .map_err(|_| bad_data())?;
        if plan.id != id
            || plan.devices.len() > MAX_TARGETS
            || plan.plan.intents.len() > MAX_EXECUTIONS
        {
            return Err(bad_data());
        }
        Ok(Admission {
            plan,
            saved_revision: r.try_get("saved_revision").map_err(|_| bad_data())?,
            current: r.try_get("current").map_err(|_| bad_data())?,
        })
    })
    .transpose()
}
pub(super) async fn read_in(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    stage: PlanStage,
) -> Result<Admission> {
    tx.with_connection(move |c| Box::pin(async move { Ok(read_on(c, id).await) }))
        .await??
        .ok_or_else(|| Reason::StalePlan.at(None, stage).into())
}

impl Planning {
    pub(super) async fn freeze_execution_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        resolution: Uuid,
        candidate: &rss_mdm_policy_postgres::Candidate,
    ) -> Result<()> {
        use rss_mdm_policy_postgres::IntentKind;
        let policy = checked(self.policies.get_in(tx, &candidate.request.policy).await?)?
            .ok_or(Error::Conflict)?;
        // Generic policy candidates remain paged and may cover a million devices.
        if self
            .freeze_firewall(tx, policy.policy(), &[])
            .await?
            .is_none()
        {
            return Ok(());
        }
        if policy.storage_revision() != candidate.request.expected_revision {
            return Err(Reason::StalePlan.at(None, PlanStage::Preview).into());
        }
        if candidate.target_count > MAX_TARGETS as u64 {
            return Err(Error::Planning(crate::planning::error::PlanningError::TargetLimit).into());
        }
        let devices = checked(
            self.policies
                .candidate_targets_in(tx, &candidate.request.id, None, MAX_TARGETS + 1)
                .await?,
        )?;
        let configuration = self.freeze_firewall(tx, policy.policy(), &devices).await?;
        let mut intents = Vec::new();
        for kind in [
            IntentKind::Add,
            IntentKind::Supersede,
            IntentKind::Cancel,
            IntentKind::Retain,
        ] {
            let mut after = None;
            loop {
                let rows = checked(
                    self.policies
                        .candidate_intents_in(tx, &candidate.request.id, kind, after, 1000)
                        .await?,
                )?;
                if rows.is_empty() {
                    break;
                }
                if intents.len() + rows.len() > MAX_EXECUTIONS {
                    return Err(Error::Planning(
                        crate::planning::error::PlanningError::TargetLimit,
                    )
                    .into());
                }
                after = rows.last().map(|r| r.position.clone());
                intents.extend(
                    rows.into_iter()
                        .map(|row| freeze_intent(row.intent))
                        .collect::<Result<Vec<_>>>()?,
                );
            }
        }
        let plan = PlanExecutionAdmission {
            id: task,
            policy: candidate.request.policy.value().into(),
            devices,
            configuration,
            plan: FrozenPlan {
                id: candidate
                    .plan
                    .ok_or(Error::Conflict)?
                    .bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                scheduling_open: policy.policy().status() == rss_mdm_policy::Status::Active,
                intents,
                dispatch: Dispatch::NotRequested,
            },
        };
        let tenant = self.tenant.to_string();
        let revision = candidate.request.expected_revision as i64;
        let document = stored(serde_json::to_value(&plan))?;
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_planning.firewall_plans(tenant_id,id,policy,resolution,revision,document) VALUES($1::uuid,$2::uuid,$3,$4::uuid,$5,$6) ON CONFLICT DO NOTHING")
                .bind(tenant).bind(task.to_string()).bind(plan.policy).bind(resolution.to_string()).bind(revision).bind(document).execute(c).await?; Ok(())
        })).await?;
        Ok(())
    }
    pub(super) async fn validate_execution_save_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
    ) -> Result<()> {
        let admission = tx
            .with_connection(move |c| Box::pin(async move { Ok(read_on(c, task).await) }))
            .await??;
        if let Some(admission) = admission {
            if !admission.current {
                return Err(Reason::StalePlan.at(None, PlanStage::Save).into());
            }
            if let Some(configuration) = admission.plan.configuration {
                for (device, expected) in configuration.devices {
                    if configuration::evidence(tx, &device, PlanStage::Save).await? != expected {
                        return Err(Reason::StalePlan.at(Some(&device), PlanStage::Save).into());
                    }
                }
            }
        }
        Ok(())
    }
}

fn freeze_intent(intent: rss_mdm_policy_postgres::CandidateIntent) -> Result<FrozenIntent> {
    use rss_mdm_policy_postgres::CandidateIntent;
    Ok(match intent {
        CandidateIntent::Desired {
            device,
            version,
            supersedes,
        } => {
            if supersedes {
                FrozenIntent::Supersede {
                    device: device.value().into(),
                    version,
                }
            } else {
                FrozenIntent::Add {
                    device: device.value().into(),
                    version,
                }
            }
        }
        CandidateIntent::Cancel { execution, reason } => FrozenIntent::Cancel {
            device: execution.device().value().into(),
            version: execution.version().number(),
            reason: match reason {
                rss_mdm_policy::CancelReason::ScopeExit => CancelReason::ScopeExit,
                rss_mdm_policy::CancelReason::Archived => CancelReason::Archived,
                rss_mdm_policy::CancelReason::Superseded => CancelReason::Superseded,
            },
        },
        CandidateIntent::Retain { execution, reason } => FrozenIntent::Retain {
            device: execution.device().value().into(),
            version: execution.version().number(),
            reason: match reason {
                rss_mdm_policy::RetainReason::Current => RetainReason::Current,
                rss_mdm_policy::RetainReason::Paused => RetainReason::Paused,
                rss_mdm_policy::RetainReason::Historical => RetainReason::Historical,
            },
        },
        CandidateIntent::Predecessor { .. } => {
            return Err(Error::Unavailable(Failure::PlanningStorage).into());
        }
    })
}

use serde::{Deserialize, Serialize};
pub(crate) const MAX_TARGETS: usize = 32;
pub(crate) const MAX_EXECUTIONS: usize = 10_000;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Evidence {
    pub registration: Uuid,
    pub generation: i64,
    pub os_version: String,
    pub edition: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FrozenConfiguration {
    pub enabled: bool,
    pub policy_status: String,
    pub version: u64,
    pub resource_digest: Vec<u8>,
    pub ddf: String,
    pub compiled_digest: [u8; 32],
    pub devices: std::collections::BTreeMap<String, Evidence>,
}
/// Planning owns the immutable, bounded command execution contract.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanExecutionAdmission {
    pub id: Uuid,
    pub policy: String,
    pub devices: Vec<String>,
    pub configuration: Option<FrozenConfiguration>,
    pub plan: FrozenPlan,
}

/// Immutable product projection of every RSS Policy intent.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenPlan {
    pub id: String,
    pub scheduling_open: bool,
    pub intents: Vec<FrozenIntent>,
    pub dispatch: Dispatch,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dispatch {
    NotRequested,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FrozenIntent {
    Add {
        device: String,
        version: u64,
    },
    Supersede {
        device: String,
        version: u64,
    },
    Cancel {
        device: String,
        version: u64,
        reason: CancelReason,
    },
    Retain {
        device: String,
        version: u64,
        reason: RetainReason,
    },
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelReason {
    ScopeExit,
    Archived,
    Superseded,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainReason {
    Current,
    Paused,
    Historical,
}
impl FrozenIntent {
    pub fn device(&self) -> &str {
        match self {
            Self::Add { device, .. }
            | Self::Supersede { device, .. }
            | Self::Cancel { device, .. }
            | Self::Retain { device, .. } => device,
        }
    }
    pub fn cancellation(&self, preview: &PlanExecutionAdmission) -> Option<(&str, u64)> {
        match self {
            Self::Cancel {
                device, version, ..
            } => Some((device, *version)),
            Self::Retain {
                device,
                version,
                reason: RetainReason::Historical,
            } if preview
                .configuration
                .as_ref()
                .is_some_and(|c| c.policy_status == "archived")
                || !preview.devices.contains(device) =>
            {
                Some((device, *version))
            }
            Self::Add { .. } | Self::Supersede { .. } | Self::Retain { .. } => None,
        }
    }
}
#[cfg(test)]
mod frozen_tests {
    use super::*;
    #[test]
    fn unknown_intents_fields_and_reasons_are_rejected() {
        for intent in [
            serde_json::json!({"kind":"unknown","device":"d","version":1}),
            serde_json::json!({"kind":"add","device":"d","version":1,"extra":true}),
            serde_json::json!({"kind":"cancel","device":"d","version":1,"reason":"unknown"}),
            serde_json::json!({"kind":"supersede","device":"d"}),
        ] {
            assert!(serde_json::from_value::<FrozenIntent>(intent).is_err());
        }
    }
}

/// Recheck the frozen product prerequisites without granting execution ownership.
pub(crate) fn validate_configuration(
    frozen: &FrozenConfiguration,
    current: &Evidence,
    device: &str,
    stage: PlanStage,
) -> std::result::Result<(), Error> {
    use sha2::{Digest, Sha256};
    let platform =
        rss_mdm_windows_mdm::configuration::Platform::new(&current.os_version, current.edition)
            .map_err(|_| Reason::PlatformUnsupported.at(Some(device), stage))?;
    let compiled = rss_mdm_windows_mdm::configuration::Firewall::compile(frozen.enabled, &platform)
        .map_err(|_| Reason::PlatformUnsupported.at(Some(device), stage))?;
    if Sha256::digest(compiled.identity()).as_slice() != frozen.compiled_digest {
        return Err(Reason::StalePlan.at(Some(device), stage));
    }
    Ok(())
}
