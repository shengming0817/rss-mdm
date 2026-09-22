use super::*;
use sqlx::Row;

pub(super) fn job_target(tenant: TenantId, id: Uuid) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        rss_reconcile::Scope::new(tenant, "mdm.assets").expect("constant domain"),
        format!("job:{id}"),
    )
    .expect("UUID entity")
}
impl Management {
    pub(in crate::management) async fn task_read_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        target: Option<&str>,
        kind: TaskKind,
    ) -> Result<Value> {
        let (job, done, failure, _, forwarded) = self.job_in(tx, id).await?;
        if target.is_some_and(|t| t != job.target())
            || !matches!(
                (kind, &job),
                (TaskKind::AssetQuery, JobInput::AssetQuery { .. })
                    | (TaskKind::Group, JobInput::Group { .. })
                    | (TaskKind::Scope, JobInput::Scope { .. })
                    | (TaskKind::Policy, JobInput::Policy { .. })
            )
        {
            return Err(Error::NotFound.into());
        }
        let mut processed = 0u64;
        let mut members = 0u64;
        let mut plan = None;
        if failure.is_none() {
            match &job {
                JobInput::AssetQuery { .. } => {}
                JobInput::Group { .. } => {
                    let build = checked(
                        self.groups
                            .build_in(
                                tx,
                                input(rss_mdm_group_postgres::OperationId::parse(&id.to_string()))?,
                            )
                            .await?,
                    )?;
                    processed = build.objects as u64;
                    members = build.members as u64;
                }
                JobInput::Scope { .. } => {
                    let tenant = self.tenant.to_string();
                    let row=tx.with_connection(move |c|Box::pin(async move {
                        sqlx::query("SELECT object_count,member_count FROM mdm_management.scope_runs WHERE tenant_id=$1::uuid AND id=$2::uuid")
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
                        &input(rss_mdm_policy::RequestId::new(self.tenant, id.to_string()))?,
                    )
                    .await?
                {
                    Ok(c) => {
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
        Ok(
            serde_json::json!({"task":id,"kind":job.kind(),"target":job.target(),"status":status,"processed":processed,"members":members,"plan":plan,"failure":failure}),
        )
    }
    pub(in crate::management) async fn enqueue_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        input: &JobInput,
    ) -> Result<Value> {
        let tenant = self.tenant.to_string();
        let document = super::super::input(serde_json::to_string(input))?;
        let kind = input.kind();
        let target = input.target();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_management.automation_jobs(tenant_id,id,kind,target,input) VALUES($1::uuid,$2::uuid,$3,$4,$5::jsonb)")
                .bind(tenant).bind(id.to_string()).bind(kind).bind(target).bind(document).execute(c).await?;Ok(())
        })).await?;
        if let JobInput::Policy { policy, .. } = input {
            let tenant = self.tenant.to_string();
            let policy = policy.clone();
            tx.with_connection(move |c|Box::pin(async move {
                sqlx::query("INSERT INTO mdm_management.candidate_heads(tenant_id,policy,desired) VALUES($1::uuid,$2,$3::uuid) ON CONFLICT(tenant_id,policy) DO UPDATE SET desired=excluded.desired")
                    .bind(tenant).bind(policy).bind(id.to_string()).execute(c).await?;Ok(())
            })).await?;
        }
        let status_url = match input {
            JobInput::AssetQuery { .. } => format!("/api/v2/device-queries/{id}"),
            JobInput::Group { group, .. } => format!("/api/v2/groups/{group}/tasks/{id}"),
            JobInput::Scope { scope } => format!("/api/v2/scopes/{scope}/tasks/{id}"),
            JobInput::Policy { .. } => format!("/api/v2/plan-previews/{id}"),
        };
        Ok(
            serde_json::json!({"task":id,"kind":input.kind(),"target":input.target(),"status_url":status_url}),
        )
    }

    pub(super) async fn forward_jobs(&self) -> std::result::Result<usize, Error> {
        let ids=self.runtime.local_tx(self.tenant,deadline(),|tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();
            tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar::<_,String>("SELECT id::text FROM mdm_management.automation_jobs WHERE tenant_id=$1::uuid AND NOT forwarded ORDER BY id LIMIT 64")
                    .bind(tenant).fetch_all(c).await
            })).await
        })).await.fold(Ok,|_|Err(Error::Unavailable(Failure::ManagementStorage)),|_|Err(Error::Unavailable(Failure::ManagementStorage)),|_|Err(Error::CommitUnknown),|_|Err(Error::CommitUnknown),|_|Err(Error::Unavailable(Failure::ManagementStorage)))?;
        let timer = Timer::new();
        let cancel = CancellationToken::new();
        for id in &ids {
            let id =
                Uuid::parse_str(id).map_err(|_| Error::Unavailable(Failure::ManagementStorage))?;
            let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
            rss_reconcile_postgres::messaging::wake_with(&self.runtime,&job_target(self.tenant,id),&control,(),|_,tx|Box::pin(async move {
                let tenant=tx.tenant_id().to_string();
                tx.with_connection(move |c|Box::pin(async move {
                    sqlx::query("UPDATE mdm_management.automation_jobs SET forwarded=true WHERE tenant_id=$1::uuid AND id=$2::uuid AND NOT forwarded")
                        .bind(tenant).bind(id.to_string()).execute(c).await?;Ok(())
                })).await
            })).await.fold(Ok,|_|Err(Error::Unavailable(Failure::ManagementStorage)),|_|Err(Error::Unavailable(Failure::ManagementStorage)),|_|Err(Error::CommitUnknown),|_|Err(Error::CommitUnknown),|_|Err(Error::Unavailable(Failure::ManagementStorage)))?;
        }
        Ok(ids.len())
    }

    pub(super) async fn job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<(JobInput, bool, Option<String>, Option<String>, bool)> {
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT input::text,completed,failure,cursor,forwarded FROM mdm_management.automation_jobs WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(id.to_string()).fetch_optional(c).await
        })).await?.ok_or(Error::NotFound)?;
        Ok((
            stored(serde_json::from_str(row.try_get("input")?))?,
            row.try_get("completed")?,
            row.try_get("failure")?,
            row.try_get("cursor")?,
            row.try_get("forwarded")?,
        ))
    }
    pub(in crate::management) async fn finish_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        failure: Option<&str>,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        let action = match failure {
            None => "automation_completed",
            Some("superseded") => "automation_superseded",
            Some(_) => "automation_failed",
        };
        let outcome = if failure.is_some() {
            "failed"
        } else {
            "success"
        };
        let failure = failure.map(str::to_owned);
        let target:Option<String>=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("UPDATE mdm_management.automation_jobs SET completed=true,failure=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid AND NOT completed RETURNING target")
                .bind(tenant).bind(id.to_string()).bind(failure).fetch_optional(c).await
        })).await?;
        if let Some(target) = target {
            let audit = Audit::new(self.tenant.to_string(), action);
            audit.identify_service("service:asset-automation");
            audit.target(&target);
            audit.operation(id, action);
            tx.with_connection(move |c| {
                Box::pin(async move {
                    let result =
                        crate::access_store::append_on_connection(c, &audit, 200, outcome, None)
                            .await;
                    audit.finalize(None);
                    result.map_err(|_| sqlx::Error::Protocol("automation audit unavailable".into()))
                })
            })
            .await?;
        }
        Ok(())
    }
}
