use super::*;
use rss_mdm_policy as p;
use rss_mdm_policy_postgres as pg;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::management) struct PolicyPage {
    result: Uuid,
    policy: String,
    plan: String,
    total_targets: u64,
    total_executions: u64,
    page: PolicyItems,
    next_cursor: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PolicyItems {
    Targets { items: Vec<String> },
    Intents { items: Vec<Intent> },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Intent {
    Predecessor {
        execution: Execution,
        successor_version: u64,
    },
    Add {
        device: String,
        version: u64,
    },
    Supersede {
        device: String,
        version: u64,
    },
    Retain {
        execution: Execution,
        reason: String,
    },
    Cancel {
        execution: Execution,
        reason: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Execution {
    device: String,
    version: u64,
    progress: String,
    effect: String,
}
fn execution(record: p::ExecutionRecord) -> Execution {
    Execution {
        device: record.device().value().into(),
        version: record.version().number(),
        progress: match record.progress() {
            p::Progress::Planned => "planned",
            p::Progress::Running => "running",
            p::Progress::Unknown => "unknown",
            p::Progress::Succeeded => "succeeded",
            p::Progress::Failed => "failed",
            p::Progress::Cancelled => "cancelled",
        }
        .into(),
        effect: match record.effect() {
            p::Effect::Unverified => "unverified",
            p::Effect::Unknown => "unknown",
            p::Effect::VerifiedPresent => "verified_present",
            p::Effect::VerifiedAbsent => "verified_absent",
        }
        .into(),
    }
}
impl Management {
    pub(in crate::management) async fn policy_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        policy: &str,
        result: Uuid,
        kind: PolicyPageKind,
        query: &PageQuery,
    ) -> Result<Value> {
        if !(1..=1000).contains(&query.limit) {
            return Err(Error::Malformed.into());
        }
        let tenant = self.tenant.to_string();
        let binding = ResultBinding::Policy {
            policy: policy.into(),
            kind,
        };
        let after = query
            .cursor
            .as_ref()
            .map(|token| decode(&self.asset_cursor_key, token, &tenant, result, &binding))
            .transpose()?;
        let id = input(p::RequestId::new(self.tenant, result.to_string()))?;
        let candidate = match self.policies.candidate_in(tx, &id).await? {
            Ok(candidate) => candidate,
            Err(pg::Rejection::NotFound) => {
                return Err(Error::ManagementNotFound(Missing::Preview).into());
            }
            Err(_) => return Err(Error::Conflict.into()),
        };
        if candidate.request.policy.value() != policy {
            return Err(Error::NotFound.into());
        }
        let plan = candidate.plan.ok_or(Error::Conflict)?;
        let (page, next) = if kind == PolicyPageKind::Targets {
            let items = checked(
                self.policies
                    .candidate_targets_in(tx, &id, after, query.limit)
                    .await?,
            )?;
            let next = items.last().cloned();
            (PolicyItems::Targets { items }, next)
        } else {
            let partition = match kind {
                PolicyPageKind::Add => pg::IntentKind::Add,
                PolicyPageKind::Supersede => pg::IntentKind::Supersede,
                PolicyPageKind::Retain => pg::IntentKind::Retain,
                PolicyPageKind::Cancel => pg::IntentKind::Cancel,
                PolicyPageKind::Predecessors => pg::IntentKind::Predecessors,
                PolicyPageKind::Targets => unreachable!(),
            };
            let after = after
                .map(|s| input(serde_json::from_str::<pg::IntentPosition>(&s)))
                .transpose()?;
            let rows = checked(
                self.policies
                    .candidate_intents_in(tx, &id, partition, after, query.limit)
                    .await?,
            )?;
            let next = rows
                .last()
                .map(|row| input(serde_json::to_string(&row.position)))
                .transpose()?;
            let items = rows
                .into_iter()
                .map(|row| match row.intent {
                    pg::CandidateIntent::Predecessor {
                        execution: record,
                        successor_version,
                    } => Intent::Predecessor {
                        execution: execution(record),
                        successor_version,
                    },
                    pg::CandidateIntent::Desired {
                        device,
                        version,
                        supersedes: false,
                    } => Intent::Add {
                        device: device.value().into(),
                        version,
                    },
                    pg::CandidateIntent::Desired {
                        device,
                        version,
                        supersedes: true,
                    } => Intent::Supersede {
                        device: device.value().into(),
                        version,
                    },
                    pg::CandidateIntent::Retain {
                        execution: e,
                        reason,
                    } => Intent::Retain {
                        execution: execution(e),
                        reason: match reason {
                            p::RetainReason::Current => "current",
                            p::RetainReason::Paused => "paused",
                            p::RetainReason::Historical => "historical",
                        }
                        .into(),
                    },
                    pg::CandidateIntent::Cancel {
                        execution: e,
                        reason,
                    } => Intent::Cancel {
                        execution: execution(e),
                        reason: match reason {
                            p::CancelReason::ScopeExit => "scope_exit",
                            p::CancelReason::Archived => "archived",
                            p::CancelReason::Superseded => "superseded",
                        }
                        .into(),
                    },
                })
                .collect();
            (PolicyItems::Intents { items }, next)
        };
        let next_cursor = next
            .map(|after| {
                encode(
                    &self.asset_cursor_key,
                    Cursor {
                        tenant,
                        result,
                        binding,
                        after,
                    },
                )
            })
            .transpose()?;
        json(&PolicyPage {
            result,
            policy: policy.into(),
            plan: plan.bytes().iter().map(|v| format!("{v:02x}")).collect(),
            total_targets: candidate.target_count,
            total_executions: candidate.fact_count,
            page,
            next_cursor,
        })
    }
}
