use super::*;
use sqlx::Row;
impl Planning {
    pub(crate) async fn task_read_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        target: Option<&str>,
        kind: TaskKind,
    ) -> Result<Value> {
        let missing = || match kind {
            TaskKind::Group => Error::Planning(crate::planning::error::PlanningError::Missing(
                crate::planning::error::Missing::Group,
            )),
            TaskKind::Scope => Error::Planning(crate::planning::error::PlanningError::Missing(
                crate::planning::error::Missing::Scope,
            )),
            TaskKind::Policy => Error::Planning(crate::planning::error::PlanningError::Missing(
                crate::planning::error::Missing::Preview,
            )),
        };
        let (job, done, failure, _, forwarded) = crate::automation::jobs::read_in(tx, id)
            .await
            .map_err(|error| match error {
                Fault::Request(Error::NotFound) => Fault::Request(missing()),
                error => error,
            })?;
        if target.is_some_and(|t| t != job.target())
            || !matches!(
                (kind, &job),
                (TaskKind::Group, JobInput::Group { .. })
                    | (TaskKind::Scope, JobInput::Scope { .. })
                    | (TaskKind::Policy, JobInput::Policy { .. })
            )
        {
            return Err(missing().into());
        }
        let mut processed = 0u64;
        let mut members = 0u64;
        let mut plan = None;
        let mut policy_revision = None;
        if failure.is_none() {
            match &job {
                JobInput::AssetQuery { .. } => return Err(Error::NotFound.into()),
                JobInput::Group { .. } => {
                    let build = checked(
                        self.groups
                            .build_in(
                                tx,
                                checked_input(rss_mdm_group_postgres::OperationId::parse(
                                    &id.to_string(),
                                ))?,
                            )
                            .await?,
                    )?;
                    processed = build.objects as u64;
                    members = build.members as u64;
                }
                JobInput::Scope { .. } => {
                    let tenant = self.tenant.to_string();
                    let row=tx.with_connection(move |c|Box::pin(async move {
                        sqlx::query("SELECT object_count,member_count FROM mdm_planning.scope_runs WHERE tenant_id=$1::uuid AND id=$2::uuid")
                            .bind(tenant).bind(id.to_string()).fetch_optional(c).await
                    })).await?;
                    if let Some(row) = row {
                        processed = row.try_get::<i64, _>("object_count")? as u64;
                        members = row.try_get::<i64, _>("member_count")? as u64;
                    }
                }
                JobInput::Policy { .. } => match self
                    .policies
                    .candidate_in(
                        tx,
                        &checked_input(rss_mdm_policy::RequestId::new(
                            self.tenant,
                            id.to_string(),
                        ))?,
                    )
                    .await?
                {
                    Ok(c) => {
                        policy_revision = Some(c.request.expected_revision);
                        processed = c.target_count + c.fact_count;
                        members = c.target_count;
                        plan = c.plan.map(|id| {
                            id.bytes()
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<String>()
                        });
                    }
                    Err(rss_mdm_policy_postgres::Rejection::NotFound) => {}
                    Err(_) => return Err(Error::Conflict.into()),
                },
            }
        }
        let status = if failure.as_deref() == Some("superseded") {
            "superseded"
        } else if failure.is_some() {
            "failed"
        } else if done {
            "completed"
        } else if forwarded {
            "running"
        } else {
            "pending"
        };
        let execution =
            super::super::admission::read_in(tx, id, crate::planning::error::PlanStage::Preview)
                .await;
        let execution = match execution {
            Ok(a) => Some(a.plan),
            Err(Fault::Request(Error::Planning(crate::planning::error::PlanningError::Plan(
                _,
            )))) => None,
            Err(e) => return Err(e),
        };
        let tenant = self.tenant.to_string();
        let failure_detail: Option<Value> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT failure_detail FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(id.to_string()).fetch_one(c).await
        })).await?;
        Ok(
            serde_json::json!({"execution":execution,"policy_revision":policy_revision,"failure_detail":failure_detail,"task":id,"kind":job.kind(),"target":job.target(),"status":status,"processed":processed,"members":members,"plan":plan,"failure":failure}),
        )
    }
}
