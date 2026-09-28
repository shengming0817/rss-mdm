use super::{state::RunState, storage as db};
use crate::Error;
use crate::execution::{ExecutionService, Result, checked_input, messaging_domain};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_mdm_audit_integration::Fact;
use rss_mdm_policy::schedule::Trigger;
use rss_transactional_messaging::{
    message::*,
    outbox::{AppendOutcome, OutboxWriter, PendingMessage},
};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn dispatch(
    tenant: rss_request_context::TenantId,
    source: db::Source,
    id: Uuid,
    target: &super::model::Target,
    now: i64,
) -> Result<PendingMessage<Vec<u8>>> {
    let payload = checked_input(serde_json::to_vec(
        &json!({"version":2,"source":source,"taskId":id,"device":target.device,"registrationId":target.registration,"generation":target.generation}),
    ))?;
    Ok(PendingMessage::new(MessageEnvelope::new(
        checked_input(MessageId::parse(&format!("action.{id}")))?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant,
                checked_input(Timepoint::try_from(now))?,
                messaging_domain(),
                checked_input(MessageRoute::parse("agent.task"))?,
                ContractIdentity::new(
                    checked_input(ContractId::parse("mdm.action-dispatch"))?,
                    ContractVersion::from_static_major(2),
                    checked_input(SchemaDigest::parse(&format!(
                        "sha256:{:x}",
                        Sha256::digest(include_bytes!("dispatch-v2.json"))
                    )))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        payload,
    )))
}

/// Only the authenticated device can cause its own recurring execution to be admitted.
pub(super) async fn accept_for_device(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    policy: &db::ScheduledPolicy,
    target: &super::model::Target,
    request: Uuid,
    now: i64,
) -> Result<()> {
    use rss_mdm_policy::Frequency;
    let db::ScheduledPolicy::Script(definition) = policy else {
        return Ok(());
    };
    let Some(entry) = definition.entry_in(tx, &target.device, now).await? else {
        return Ok(());
    };
    let input = &definition.frozen.input;
    let schedule = &input.schedule;
    let tenant = tx.tenant_id().to_string();
    let version = definition.id;
    let owner = definition.owner;
    let device = target.device.clone();
    let registration = target.registration.to_string();
    let (pending,last)=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_as::<_,(bool,Option<i64>)>("SELECT coalesce(bool_or(state->>'execution'='unknown' OR ((state->>'execution'='running' OR (state->>'execution'='not_started' AND deadline>$4)) AND state->>'cancellation'<>'confirmed')),false),max(created_at) FILTER(WHERE policy_version=$6) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2::uuid AND device=$3 AND registration=$5::uuid")
            .bind(tenant).bind(owner.to_string()).bind(device).bind(now).bind(registration).bind(version).fetch_one(c).await
    })).await?;
    if pending {
        return Ok(());
    }
    let tenant = tx.tenant_id().to_string();
    let version = definition.id;
    let device = target.device.clone();
    let explicit=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_as::<_,(Uuid,i64,i64)>("SELECT t.id,t.created_at,t.deadline FROM mdm_policy.triggers t WHERE t.tenant_id=$1::uuid AND t.version=$2 AND t.deadline>$4 AND NOT EXISTS(SELECT 1 FROM mdm_commands.action_runs r WHERE r.tenant_id=t.tenant_id AND r.policy_version=t.version AND r.device=$3 AND r.occurrence='explicit:'||t.id::text) ORDER BY t.created_at,t.id LIMIT 1").bind(tenant).bind(version).bind(device).bind(now).fetch_optional(c).await
    })).await?;
    let (coordinate, event) = if let Some((id, at, _)) = explicit {
        (at, format!("explicit:{id}"))
    } else {
        match &schedule.trigger {
            Trigger::Manual => return Ok(()),
            Trigger::CheckIn { minimum_seconds } => {
                if last.is_some_and(|t| now.saturating_sub(t) < i64::from(*minimum_seconds)) {
                    return Ok(());
                }
                (now, format!("checkin:{request}"))
            }
            Trigger::Registration => (now, format!("registration:{}", target.registration)),
            Trigger::Once { .. } | Trigger::Interval { .. } | Trigger::Weekly { .. } => {
                let Some(due) = schedule.due(-1, now, target.device.as_bytes())? else {
                    return Ok(());
                };
                (due.coordinate, format!("timer:{}", due.coordinate))
            }
        }
    };
    let occurrence = if explicit.is_some() {
        event.clone()
    } else {
        match definition.frequency {
            Frequency::OncePerVersion => format!("version:{}", target.registration),
            Frequency::OncePerEntry => format!(
                "entry:{}:{entry}:{}",
                definition.entry_source(),
                target.registration
            ),
            Frequency::EveryTrigger => format!("{event}:{}", target.registration),
        }
    };
    let Some(slot) = schedule.occurrence(coordinate, target.device.as_bytes())? else {
        return Ok(());
    };
    let available = slot.available_at.max(now);
    let deadline = available
        .checked_add(i64::from(input.run_lifetime_seconds))
        .ok_or(Error::Malformed)?
        .min(schedule.ends_at())
        .min(slot.window_end.unwrap_or(i64::MAX))
        .min(explicit.map_or(i64::MAX, |v| v.2));
    if deadline <= available {
        return Ok(());
    }
    let tenant = tx.tenant_id().to_string();
    let device = target.device.clone();
    let version = definition.id;
    let key = occurrence.clone();
    let (exists,active)=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_as::<_,(bool,i64)>("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND policy_version=$2::uuid AND device=$3 AND occurrence=$4),(SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND device=$3 AND state->>'execution' IN ('not_started','running') AND state->>'cancellation'<>'confirmed' AND deadline>$5)")
            .bind(tenant).bind(version.to_string()).bind(device).bind(key).bind(now).fetch_one(c).await
    })).await?;
    if exists || active >= 128 {
        return Ok(());
    }
    let id = Uuid::new_v4();
    queue_run_in(
        service,
        tx,
        RunInput {
            source: db::Source::Policy {
                version: definition.id,
            },
            target,
            id,
            occurrence,
            available,
            deadline,
            now,
        },
    )
    .await?;
    crate::planning::policies::storage::wake_execution_in(tx, definition.owner).await?;
    Ok(())
}
pub(in crate::execution) struct RunInput<'a> {
    pub source: db::Source,
    pub target: &'a super::model::Target,
    pub id: Uuid,
    pub occurrence: String,
    pub available: i64,
    pub deadline: i64,
    pub now: i64,
}
pub(in crate::execution) async fn queue_run_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    input: RunInput<'_>,
) -> Result<()> {
    let RunInput {
        source,
        target,
        id,
        occurrence,
        available,
        deadline,
        now,
    } = input;
    let message = dispatch(tx.tenant_id(), source, id, target, now)?;
    let fingerprint = message.fingerprint().as_bytes().to_vec();
    let writer = rss_transactional_messaging_postgres::PgOutboxWriter::new(
        service.runtime.clone(),
        messaging_domain(),
    );
    if writer
        .append(tx, message)
        .await
        .map_err(rss_transactional_messaging_postgres::PgError::from)?
        != AppendOutcome::Inserted
    {
        return Err(Error::Conflict.into());
    }
    let tenant = tx.tenant_id().to_string();
    let registration = target.registration;
    let target = target.clone();
    let digest = fingerprint.clone();
    let (kind, version, remote) = source.columns();
    let state = checked_input(serde_json::to_value(RunState::new(deadline, now)?))?;
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,source_kind,policy_version,remote_operation,device,registration,generation,occurrence,available_at,deadline,state,dispatch_fingerprint,created_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
            .bind(tenant).bind(id).bind(kind).bind(version).bind(remote).bind(target.device).bind(target.registration).bind(target.generation).bind(occurrence).bind(available).bind(deadline).bind(state).bind(digest).bind(now).execute(c).await?;Ok(())
    })).await?;
    let audit =
        rss_mdm_audit_integration::RequestAudit::new(tx.tenant_id().to_string(), "command_accept");
    audit.operation(id, "command_accept");
    audit.identify_service("execution-admission");
    source.audit(&audit);
    audit.target(&id.to_string());
    audit.registration(registration);
    let result: Result<()> = async {
        let fact = Fact::business(
            &audit,
            &format!("action:{id}:accept"),
            &fingerprint,
            202,
            "success",
            None,
        )?;
        service.audit_store.append_in(tx, &fact, false).await?;
        Ok(())
    }
    .await;
    audit.finalize(
        result
            .as_ref()
            .err()
            .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
    );
    result
}
