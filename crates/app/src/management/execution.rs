//! Management's bounded execution projection for all command paths.
use super::*;
use crate::{PlanFailureReason as Reason, PlanStage};
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
    let row = sqlx::query("SELECT * FROM mdm_management.plan_execution_admission($1::uuid)")
        .bind(id.to_string())
        .fetch_optional(c)
        .await
        .map_err(crate::access_store::db)?;
    row.map(|r| {
        let invalid = || Error::Unavailable(Failure::ManagementStorage);
        let plan: PlanExecutionAdmission =
            serde_json::from_value(r.try_get("document").map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        if plan.id != id
            || plan.devices.len() > configuration::MAX_TARGETS
            || plan.plan.intents.len() > configuration::MAX_EXECUTIONS
        {
            return Err(invalid());
        }
        Ok(Admission {
            plan,
            saved_revision: r.try_get("saved_revision").map_err(|_| invalid())?,
            current: r.try_get("current").map_err(|_| invalid())?,
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

impl Management {
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
        if candidate.target_count > configuration::MAX_TARGETS as u64 {
            return Err(Error::ConfigurationTargetLimit.into());
        }
        let devices = checked(
            self.policies
                .candidate_targets_in(
                    tx,
                    &candidate.request.id,
                    None,
                    configuration::MAX_TARGETS + 1,
                )
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
                if intents.len() + rows.len() > configuration::MAX_EXECUTIONS {
                    return Err(Error::ConfigurationTargetLimit.into());
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
            sqlx::query("INSERT INTO mdm_management.firewall_plans(tenant_id,id,policy,resolution,revision,document) VALUES($1::uuid,$2::uuid,$3,$4::uuid,$5,$6) ON CONFLICT DO NOTHING")
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
            return Err(Error::Unavailable(Failure::ManagementStorage).into());
        }
    })
}
