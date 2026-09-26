use super::*;
use sqlx::Row;
pub(crate) fn job_target(tenant: TenantId, id: Uuid) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        rss_reconcile::Scope::new(tenant, "mdm.assets").expect("constant domain"),
        format!("job:{id}"),
    )
    .expect("UUID entity")
}
pub(crate) async fn forward_jobs(
    runtime: &PgRuntime,
    tenant: TenantId,
    audit_store: &rss_mdm_audit_integration::AuditStore,
) -> std::result::Result<usize, Error> {
    // A policy cannot compute until its Scope is terminal. Keep the durable
    // intent unforwarded instead of spending RSS retries on an unfinished input.
    let ids=runtime.local_tx(tenant,deadline(),|tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();
            tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar::<_,String>("SELECT j.id::text FROM mdm_automation.automation_jobs j WHERE j.tenant_id=$1::uuid AND NOT j.forwarded AND (j.kind<>'policy' OR EXISTS(SELECT 1 FROM mdm_automation.automation_jobs source WHERE source.tenant_id=j.tenant_id AND source.id=(j.input->>'resolution')::uuid AND source.kind='scope' AND source.completed)) ORDER BY j.id LIMIT 64")
                    .bind(tenant).fetch_all(c).await
            })).await
        })).await.fold(Ok,|_|Err(Error::Unavailable(Failure::AutomationStorage)),|_|Err(Error::Unavailable(Failure::AutomationStorage)),|_|Err(Error::CommitUnknown),|_|Err(Error::CommitUnknown),|_|Err(Error::Unavailable(Failure::AutomationStorage)))?;
    let timer = Timer::new();
    let cancel = CancellationToken::new();
    for id in &ids {
        let id = Uuid::parse_str(id).map_err(|_| Error::Unavailable(Failure::AutomationStorage))?;
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        runtime.local_tx_with_context(
    tenant,
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(control.remaining()),
    (audit_store, job_target(tenant,id).clone(), ()),
    |(service, target, context), tx| Box::pin(async move {
        service.lock_in(tx).await.map_err(PgError::from)?;
        rss_reconcile_postgres::messaging::wake_in(tx, target, context, |_,tx|Box::pin(async move {
                let tenant=tx.tenant_id().to_string();
                tx.with_connection(move |c|Box::pin(async move {
                    sqlx::query("UPDATE mdm_automation.automation_jobs SET forwarded=true WHERE tenant_id=$1::uuid AND id=$2::uuid AND NOT forwarded")
                        .bind(tenant).bind(id.to_string()).execute(c).await?;Ok(())
                })).await
            })).await
    }),
).await.fold(Ok,|_|Err(Error::Unavailable(Failure::AutomationStorage)),|_|Err(Error::Unavailable(Failure::AutomationStorage)),|_|Err(Error::CommitUnknown),|_|Err(Error::CommitUnknown),|_|Err(Error::Unavailable(Failure::AutomationStorage)))?;
    }
    Ok(ids.len())
}

pub(crate) async fn read_in(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<(JobInput, bool, Option<String>, Option<String>, bool)> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT input::text,completed,failure,cursor,forwarded FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND id=$2::uuid")
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
pub(crate) async fn enqueue_job_in(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    input: &JobInput,
) -> Result<Value> {
    let tenant = tx.tenant_id().to_string();
    let document = crate::transaction::checked_input(serde_json::to_string(input))?;
    let kind = input.kind();
    let target = input.target();
    tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_automation.automation_jobs(tenant_id,id,kind,target,input) VALUES($1::uuid,$2::uuid,$3,$4,$5::jsonb)")
                .bind(tenant).bind(id.to_string()).bind(kind).bind(target).bind(document).execute(c).await?;Ok(())
        })).await?;
    if let JobInput::Policy { policy, .. } = input {
        let tenant = tx.tenant_id().to_string();
        let policy = policy.clone();
        tx.with_connection(move |c|Box::pin(async move {
                sqlx::query("INSERT INTO mdm_planning.candidate_heads(tenant_id,policy,desired) VALUES($1::uuid,$2,$3::uuid) ON CONFLICT(tenant_id,policy) DO UPDATE SET desired=excluded.desired")
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
pub(crate) async fn finish_job_in(
    tx: &mut PgTransaction<'_>,
    store: &rss_mdm_audit_integration::AuditStore,
    id: Uuid,
    failure: Option<&str>,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
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
    let failure_owned = failure.map(str::to_owned);
    let target:Option<String>=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("UPDATE mdm_automation.automation_jobs SET completed=true,failure=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid AND NOT completed RETURNING target")
                .bind(tenant).bind(id.to_string()).bind(failure_owned).fetch_optional(c).await
        })).await?;
    if target.is_none() {
        let tenant = tx.tenant_id().to_string();
        let exists=tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND id=$2::uuid AND completed)")
                    .bind(tenant).bind(id.to_string()).fetch_one(c).await
            })).await?;
        if !exists {
            return Err(Error::NotFound.into());
        }
    }
    if let Some(target) = target {
        let audit = RequestAudit::new(tx.tenant_id().to_string(), action);
        audit.identify_service("service:asset-automation");
        audit.target(&target);
        audit.operation(id, action);
        let fingerprint =
            serde_json::to_vec(&(id, &target, failure)).expect("closed automation result");
        let fact = rss_mdm_audit_integration::Fact::business(
            &audit,
            &format!("automation:{id}:terminal"),
            &fingerprint,
            200,
            outcome,
            None,
        )
        .map_err(Error::from)?;
        let result = store.append_in(tx, &fact, false).await.map_err(Error::from);
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result?;
    }
    Ok(())
}
