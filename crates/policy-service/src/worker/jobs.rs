use super::*;
pub fn job_target(tenant: TenantId, id: Uuid) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        rss_reconcile::Scope::new(tenant, "mdm.policy").expect("constant domain"),
        format!("job:{id}"),
    )
    .expect("UUID entity")
}
pub(super) async fn forward_jobs_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
) -> Result<()> {
    let tenant = tx.tenant_id();
    for (id, kind) in rss_mdm_policy_postgres::work::pending_in(tx).await? {
        let id =
            Uuid::parse_str(&id).map_err(|_| Error::Unavailable(Failure::AutomationStorage))?;
        let event = kind == "policy_event";
        let target = if event {
            event_target(tenant, id)
        } else {
            job_target(tenant, id)
        };
        reconcile
            .wake_in(tx, &target, event, |event, tx| {
                Box::pin(async move {
                    rss_mdm_policy_postgres::work::forwarded_in(tx, id).await?;
                    crate::worker_wake::notify_in(
                        tx,
                        if *event {
                            crate::worker_wake::Work::Events
                        } else {
                            crate::worker_wake::Work::Automation
                        },
                    )
                    .await
                })
            })
            .await?;
    }
    Ok(())
}

pub async fn read_in(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<(Work, bool, Option<String>, Option<String>, bool)> {
    let row = rss_mdm_policy_postgres::work::read_in(tx, id)
        .await?
        .ok_or(Error::NotFound)?;
    Ok((
        row.input,
        row.completed,
        row.failure,
        row.cursor,
        row.forwarded,
    ))
}
pub async fn enqueue_job_in(tx: &mut PgTransaction<'_>, id: Uuid, input: &Work) -> Result<Value> {
    rss_mdm_policy_postgres::work::enqueue_in(tx, id, input).await?;
    Ok(accepted(id, input))
}
pub fn accepted(id: Uuid, input: &Work) -> Value {
    let status_url = match input {
        Work::PolicyScope { scope, .. } => format!("/api/v1/scopes/{scope}"),
        Work::PolicyEvent { batch } => format!("/api/v1/policy-event-batches/{batch}"),
        Work::Lifecycle { policy, .. } => format!("/api/v1/policies/{policy}"),
        Work::PolicyReconcile { policy } => format!("/api/v1/policies/{policy}"),
    };
    serde_json::json!({"task":id,"kind":input.kind(),"target":input.target(),"statusUrl":status_url})
}
pub async fn finish_job_in(
    tx: &mut PgTransaction<'_>,
    store: &rss_mdm_audit_integration::AuditStore,
    id: Uuid,
    failure: Option<&str>,
) -> Result<()> {
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
    let target = rss_mdm_policy_postgres::work::finish_in(tx, id, failure_owned).await?;
    if target.is_none() {
        let exists = rss_mdm_policy_postgres::work::exists_in(tx, id, true).await?;
        if !exists {
            return Err(Error::NotFound.into());
        }
    }
    if let Some((target, kind)) = target {
        let audit = RequestAudit::new(
            tx.tenant_id().to_string(),
            action,
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("service:asset-automation");
        match kind.as_str() {
            "policy_scope" => {
                audit.resource_target(rss_mdm_audit_integration::TargetKind::Scope, &target)
            }
            "policy_reconcile" => {
                audit.resource_target(rss_mdm_audit_integration::TargetKind::Policy, &target)
            }
            _ => audit.target(&target),
        }
        audit.operation(
            id,
            action,
            rss_mdm_audit_integration::AuditIntent::Management,
        );

        let fact = rss_mdm_audit_integration::Fact::business(
            &audit,
            &format!("automation:{id}:terminal"),
            200,
            outcome,
            None,
        )
        .map_err(Error::from)?;
        let result = store.append_in(tx, &fact).await.map_err(Error::from);
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

pub async fn replacement_in(tx: &mut PgTransaction<'_>, old: Uuid, new: Uuid) -> Result<()> {
    rss_mdm_policy_postgres::work::replacement_in(tx, old, new).await?;
    Ok(())
}

pub const EVENT_SCOPE: &str = "mdm.policy-events";
pub fn event_target(tenant: TenantId, id: Uuid) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        rss_reconcile::Scope::new(tenant, EVENT_SCOPE).expect("constant domain"),
        format!("event:{id}"),
    )
    .expect("UUID entity")
}
pub fn target_job(entity: &str) -> Option<&str> {
    entity
        .strip_prefix("job:")
        .or_else(|| entity.strip_prefix("event:"))
}
