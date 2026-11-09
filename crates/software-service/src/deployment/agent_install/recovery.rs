//! Recovery creates a new bounded attempt; it never replays an unknown native write.
use super::Package;
use crate::deployment::{Error, database::db};
use rss_mdm_inventory::channel::Current;
use rss_mdm_registration_service::installation::queries::{NativeContact, cleanup_pending_on};
use sqlx::PgConnection;
use uuid::Uuid;

const HEALTH_GRACE_SECONDS: i64 = 300;
const RETRY_PROBE_GRACE_SECONDS: i64 = 60;
const MAX_ATTEMPTS_WITHOUT_CONTACT: i64 = 3;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Signal {
    Absent,
    Unresponsive,
    Healthy,
    Unknown,
}

pub(crate) fn signal(
    fact: &Current,
    package: &Package,
    contact: &NativeContact,
    now: i64,
) -> Signal {
    if contact.active > 1 || contact.last.is_some_and(|at| at > now) {
        return Signal::Unknown;
    }
    if fact.state == "absent" {
        return Signal::Absent;
    }
    let Some(evidence) = &fact.evidence else {
        return Signal::Unknown;
    };
    let version = match &package.identity {
        super::Identity::WindowsMsix { identity, .. } => identity
            .version
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join("."),
        _ => package.version.clone(),
    };
    // Native bundle presence remains unverified. Retained macOS app copies cannot
    // identify the current version. Repair only reuses the Agent identity already
    // bound to this exact MDM registration; it does not authenticate a new identity.
    if contact.bindings == 0
        || evidence.identity != package.detection_identity()
        || (!matches!(package.identity, super::Identity::Macos { .. })
            && evidence.version.as_deref() != Some(version.as_str()))
    {
        return Signal::Unknown;
    }
    if contact.active == 1
        && contact
            .last
            .is_some_and(|at| at > now.saturating_sub(HEALTH_GRACE_SECONDS))
    {
        Signal::Healthy
    } else {
        Signal::Unresponsive
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    Ready,
    Pending(Uuid),
    ObservationPending,
    Exhausted,
}

pub(crate) async fn gate_on(
    c: &mut PgConnection,
    tenant: &str,
    target: (String, Uuid),
    snapshot: Uuid,
    last_contact: Option<i64>,
    now: i64,
) -> Result<Gate, Error> {
    let (device, version) = target;
    // A probe begun before an old attempt ended cannot establish recovery readiness.
    let started: i64 = sqlx::query_scalar("SELECT started_at FROM mdm_access.collection_runs WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND device = $3 AND sealed_at IS NOT NULL")
        .bind(tenant).bind(snapshot).bind(&device).fetch_one(&mut *c).await.map_err(db)?;
    let (pending, deadline, attempts) = sqlx::query_as::<_, (Option<Uuid>, Option<i64>, i64)>(
        "SELECT ((array_agg(o.id ORDER BY d.queued_at DESC, o.id DESC) FILTER (WHERE d.terminal_at IS NULL AND d.deadline > CAST($5 AS bigint) * 1000000)))[1], max(d.deadline / 1000000), count(*) FILTER (WHERE o.policy_version = $3 AND d.queued_at > GREATEST(CAST($4 AS bigint), COALESCE((SELECT max(t.created_at) FROM mdm_policy.triggers AS t WHERE t.tenant_id = o.tenant_id AND t.version = $3 AND t.deadline > CAST($5 AS bigint)), 0)) * 1000000) FROM mdm_software_deployment.operations AS o INNER JOIN rss_device_command.commands AS d ON (d.tenant_id, d.command_id) = (o.tenant_id, CAST(o.id AS text)) WHERE o.tenant_id = CAST($1 AS uuid) AND o.device = $2 AND o.authority ->> 'kind' = 'agent_install'",
    ).bind(tenant).bind(&device).bind(version)
        .bind(last_contact.unwrap_or(0)).bind(now).fetch_one(&mut *c).await.map_err(db)?;
    let cleanup = cleanup_pending_on(c, tenant, &device).await?;
    Ok(decide(pending, deadline, attempts, cleanup, started))
}

fn decide(
    pending: Option<Uuid>,
    deadline: Option<i64>,
    attempts: i64,
    cleanup: bool,
    started: i64,
) -> Gate {
    if let Some(id) = pending {
        return Gate::Pending(id);
    }
    if cleanup || deadline.is_some_and(|at| started <= at.saturating_add(RETRY_PROBE_GRACE_SECONDS))
    {
        return Gate::ObservationPending;
    }
    if attempts >= MAX_ATTEMPTS_WITHOUT_CONTACT {
        Gate::Exhausted
    } else {
        Gate::Ready
    }
}
