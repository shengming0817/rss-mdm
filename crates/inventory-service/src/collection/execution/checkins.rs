//! Authenticated check-in events and a durable per-registration Policy sweep.
use super::{CollectionService, admission::TriggerInput as AdmissionTrigger, storage};
use crate::{Error, transaction::Result};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;
pub async fn record(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    p: &rss_mdm_registration_service::DevicePrincipal,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    if p.tenant() != tx.tenant_id() {
        return Err(Error::Unauthorized.into());
    }
    let registration = p.registration();
    let generation = p.generation();
    let event = Uuid::new_v4();
    let at = storage::now(tx).await?;
    let recorded = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_inventory.collection_native_checkins(tenant_id,registration,generation,pending_event,pending_at) SELECT $1::uuid,$2,$3,$4,$5 WHERE EXISTS(SELECT FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND state='enabled' AND definition->'action'->>'kind'='native_collection' AND definition->'action'->'schedule'->'trigger'->>'kind' IN('check_in','registration')) ON CONFLICT(tenant_id,registration,generation) DO UPDATE SET pending_event=excluded.pending_event,pending_at=excluded.pending_at")
            .bind(tenant).bind(registration).bind(generation).bind(event).bind(at).execute(c).await.map(|r|r.rows_affected()>0)
    })).await?;
    if !recorded {
        return Ok(());
    }
    super::wake::entity_in(
        reconcile,
        tx,
        &format!("checkin:{registration}:{generation}"),
    )
    .await
}
pub async fn step(
    service: &CollectionService,
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    generation: i64,
    run_id: Uuid,
) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let device: Option<String> = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT device FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2")
            .bind(tenant).bind(registration).fetch_optional(c).await
    })).await?;
    if device.is_none() {
        return Err(Error::Conflict.into());
    }
    let tenant = tx.tenant_id().to_string();
    let state = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_inventory.collection_native_checkins SET active_event=pending_event,active_at=pending_at,pending_event=NULL,pending_at=NULL,policy_after=NULL WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND active_event IS NULL AND pending_event IS NOT NULL")
            .bind(&tenant).bind(registration).bind(generation).execute(&mut *c).await?;
        sqlx::query("SELECT s.active_event,s.active_at,s.policy_after,r.device,(r.state='active' AND r.generation=s.generation) AS current FROM mdm_inventory.collection_native_checkins s JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(s.tenant_id,s.registration) WHERE s.tenant_id=$1::uuid AND s.registration=$2 AND s.generation=$3 FOR UPDATE OF s")
            .bind(tenant).bind(registration).bind(generation).fetch_optional(c).await
    })).await?;
    let Some(state) = state else { return Ok(false) };
    let current: bool = state.try_get("current")?;
    let event: Option<Uuid> = state.try_get("active_event")?;
    if !current || event.is_none() {
        clear(tx, registration, generation, !current).await?;
        return Ok(false);
    }
    let event = event.ok_or(Error::Malformed)?;
    let at: i64 = state.try_get("active_at")?;
    let after: Option<Uuid> = state.try_get("policy_after")?;
    let device: String = state.try_get("device")?;
    let tenant = tx.tenant_id().to_string();
    let next: Option<(Uuid, Uuid)> = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as("SELECT id,current_version FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND state='enabled' AND definition->'action'->>'kind'='native_collection' AND definition->'action'->'schedule'->'trigger'->>'kind' IN('check_in','registration') AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 1")
            .bind(tenant).bind(after).fetch_optional(c).await
    })).await?;
    let Some((policy, version)) = next else {
        clear(tx, registration, generation, false).await?;
        // A subsequent claim promotes the latest event; never restart this sweep in-place.
        return Ok(false);
    };
    let plan = super::policy::read_in(&service.transactions, tx, version).await?;
    if let super::frozen::Published::NativeCollection { action: native, .. } = &plan.frozen {
        use rss_mdm_policy::schedule::Trigger;
        let trigger = match native.input.schedule.trigger {
            Trigger::CheckIn { .. } => Some(AdmissionTrigger::CheckIn { event, at }),
            Trigger::Registration => Some(AdmissionTrigger::Registration { at }),
            _ => None,
        };
        if let Some(trigger) = trigger {
            let target = super::model::Target {
                device,
                registration,
                generation,
            };
            let now = storage::now(tx).await?;
            let id = run_id;
            super::admission::accept_for_device(
                &service.transactions,
                tx,
                &plan,
                &target,
                trigger,
                now,
                id,
            )
            .await?;
        }
    }
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_inventory.collection_native_checkins SET policy_after=$4 WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
            .bind(tenant).bind(registration).bind(generation).bind(policy).execute(c).await?;
        Ok(())
    })).await?;
    Ok(true)
}
async fn clear(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    generation: i64,
    stale: bool,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_inventory.collection_native_checkins SET active_event=NULL,active_at=NULL,policy_after=NULL,pending_event=CASE WHEN $4 THEN NULL ELSE pending_event END,pending_at=CASE WHEN $4 THEN NULL ELSE pending_at END WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
            .bind(tenant).bind(registration).bind(generation).bind(stale).execute(c).await?;
        Ok(())
    })).await?;
    Ok(())
}
