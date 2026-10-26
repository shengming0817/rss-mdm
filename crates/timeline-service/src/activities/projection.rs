use crate::{Error, FactView};
use rss_mdm_audit_integration::activity::Activity;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use uuid::Uuid;

pub(crate) async fn project_activity(
    c: &mut PgConnection,
    tenant: &str,
    event: &rss_audit_core::AuditEventV1,
    view: &FactView,
) -> Result<Option<Activity>, Error> {
    if !view.supported || view.source != "mdm.business" {
        return Ok(None);
    }
    let payload: serde_json::Value = serde_json::from_slice(event.context().payload().as_bytes())
        .map_err(|_| Error::Integrity)?;
    let mut activity = if let Some(value) = payload.pointer("/details/activity") {
        serde_json::from_value::<Activity>(value.clone()).map_err(|_| Error::Integrity)?
    } else {
        return Ok(None);
    };
    if let Some(target) = &activity.target
        && (target.registration.is_nil()
            || target.generation <= 0
            || !crate::model::identifier(&target.device))
    {
        return Err(Error::Integrity);
    }
    if activity.links.steps.len() > 256
        || activity
            .links
            .steps
            .iter()
            .any(|s| !crate::model::identifier(s))
    {
        return Err(Error::Integrity);
    }
    // Only a producer-declared immutable version may resolve its owning Policy.
    if activity.links.policy.is_none()
        && let Some(version) = activity.links.version
    {
        activity.links.policy = sqlx::query_scalar(
            "SELECT policy FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(tenant)
        .bind(version)
        .fetch_optional(c)
        .await?;
    }
    validate(&activity)?;
    Ok(Some(activity))
}

/// Row lock and increment are in the projection transaction, so published revisions follow commit order.
pub(crate) async fn publish_in(
    c: &mut PgConnection,
    tenant: TenantId,
    device: &str,
    position: i64,
) -> Result<(), Error> {
    let tenant = tenant.to_string();
    sqlx::query("INSERT INTO mdm_timeline.activity_streams(tenant_id,device,generation) VALUES($1::uuid,$2,$3) ON CONFLICT DO NOTHING").bind(&tenant).bind(device).bind(Uuid::new_v4()).execute(&mut *c).await?;
    let head:i64=sqlx::query_scalar("SELECT revision FROM mdm_timeline.activity_streams WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE").bind(&tenant).bind(device).fetch_one(&mut *c).await?;
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_timeline.activity_entries WHERE tenant_id=$1::uuid AND device=$2 AND position=$3)").bind(&tenant).bind(device).bind(position).fetch_one(&mut *c).await?;
    if exists {
        return Ok(());
    }
    let revision = head.checked_add(1).ok_or(Error::Integrity)?;
    sqlx::query("INSERT INTO mdm_timeline.activity_entries(tenant_id,device,revision,position) VALUES($1::uuid,$2,$3,$4)").bind(&tenant).bind(device).bind(revision).bind(position).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_timeline.activity_streams SET revision=$3 WHERE tenant_id=$1::uuid AND device=$2").bind(&tenant).bind(device).bind(revision).execute(c).await?;
    Ok(())
}

pub(super) fn summary(
    view: &FactView,
    activity: &Activity,
) -> Result<rss_mdm_agent_wire::activities::ManagementActivity, Error> {
    use rss_mdm_agent_wire::activities::{ActivityLinks, ManagementActivity};
    validate(activity)?;
    Ok(ManagementActivity {
        id: format!("{}:{}", view.source, view.event_id),
        source: view.source.clone(),
        kind: serde_json::to_value(&activity.kind)
            .map_err(|_| Error::Integrity)?
            .as_str()
            .ok_or(Error::Integrity)?
            .into(),
        phase: serde_json::to_value(&activity.phase)
            .map_err(|_| Error::Integrity)?
            .as_str()
            .ok_or(Error::Integrity)?
            .into(),
        recorded_at: view.recorded_at,
        observed_at: view.observed_at,
        origin: activity.origin.clone(),
        target: activity
            .target
            .as_ref()
            .map(|t| rss_mdm_agent_wire::activities::ActivityTarget {
                device: t.device.clone(),
                registration: t.registration,
                generation: t.generation,
            }),
        links: ActivityLinks {
            policy: activity.links.policy,
            version: activity.links.version,
            batch: activity.links.batch,
            member: activity.links.member,
            request: activity.links.request,
            operation: activity.links.operation,
            task: activity.links.task,
            attempt: activity.links.attempt,
            steps: activity.links.steps.clone(),
            operations: activity
                .links
                .operations
                .iter()
                .map(|r| {
                    use rss_mdm_agent_wire::runtime::PolicyEventOperation as W;
                    use rss_mdm_audit_integration::activity::ActivityOperation as A;
                    match r {
                        A::Run { id } => W::Run { id: *id },
                        A::Native { id } => W::Native { id: *id },
                        A::Retirement { id } => W::Retirement { id: *id },
                    }
                })
                .collect(),
        },
        delivery: activity.delivery.clone(),
        execution: activity.execution.clone(),
        effect: activity.effect.clone(),
        reporting: activity.reporting.clone(),
        decision: activity.decision.clone(),
        audit_outcome: view.audit_outcome.clone(),
    })
}

fn validate(a: &Activity) -> Result<(), Error> {
    let allowed = |value: &Option<String>, values: &[&str]| {
        value.as_ref().is_none_or(|v| values.contains(&v.as_str()))
    };
    if !["system", "policy", "human", "ai"].contains(&a.origin.as_str())
        || !allowed(
            &a.delivery,
            &["queued", "offered", "dispatched", "received", "unknown"],
        )
        || !allowed(
            &a.execution,
            &[
                "not_started",
                "running",
                "succeeded",
                "failed",
                "waiting_reboot",
                "unknown",
                "queued",
                "published",
                "received",
                "applied",
                "rejected",
                "timed_out",
                "superseded",
                "cancelled",
            ],
        )
        || !allowed(
            &a.effect,
            &[
                "verified",
                "failed",
                "unknown",
                "waiting_reboot",
                "diverged",
                "waiting",
                "unverifiable",
            ],
        )
        || !allowed(&a.reporting, &["partial", "acknowledged"])
        || !allowed(
            &a.decision,
            &[
                "pending",
                "accepted",
                "no_change",
                "rejected",
                "expired",
                "cancelled",
                "cancellation_requested",
                "assigned",
                "unavailable",
            ],
        )
        || a.links.operations.len() > 256
    {
        return Err(Error::Integrity);
    }
    Ok(())
}
