//! Authenticated check-in events and a durable per-device Policy sweep.
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
    let device = p.device().to_owned();
    let event = Uuid::new_v4();
    let at = storage::now(tx).await?;
    let wake_device = device;
    let recorded = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_inventory.collection_native_checkins (tenant_id, device, pending_event, pending_at) SELECT CAST($1 AS uuid), $2, $3, $4 WHERE EXISTS (SELECT FROM mdm_policy.policies WHERE tenant_id = CAST($1 AS uuid) AND state = 'enabled' AND definition -> 'action' ->> 'kind' = 'native_collection' AND definition -> 'action' -> 'schedule' -> 'trigger' ->> 'kind' IN ('check_in', 'device')) ON CONFLICT (tenant_id, device) DO UPDATE SET pending_event = excluded.pending_event, pending_at = excluded.pending_at")
            .bind(tenant).bind(device.into_uuid()).bind(event).bind(at).execute(c).await.map(|r|r.rows_affected()>0)
    })).await?;
    if !recorded {
        return Ok(());
    }
    super::wake::entity_in(reconcile, tx, &format!("checkin:{wake_device}")).await
}
pub async fn step(
    service: &CollectionService,
    tx: &mut PgTransaction<'_>,
    device: rss_mdm_agent_wire::DeviceId,
    run_id: Uuid,
) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let current_device = device;
    let state = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_inventory.collection_native_checkins SET active_event = pending_event, active_at = pending_at, pending_event = NULL, pending_at = NULL, policy_after = NULL WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND active_event IS NULL AND pending_event IS NOT NULL")
            .bind(&tenant).bind(current_device.into_uuid()).execute(&mut *c).await?;
        sqlx::query("SELECT s.active_event, s.active_at, s.policy_after, r.id AS device, r.state = 'active' AS current FROM mdm_inventory.collection_native_checkins AS s INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.id) = (s.tenant_id, s.device) WHERE s.tenant_id = CAST($1 AS uuid) AND s.device = $2 FOR UPDATE OF s")
            .bind(tenant).bind(current_device.into_uuid()).fetch_optional(c).await
    })).await?;
    let Some(state) = state else { return Ok(false) };
    let current: bool = state.try_get("current")?;
    let event: Option<Uuid> = state.try_get("active_event")?;
    if !current || event.is_none() {
        clear(tx, device, !current).await?;
        return Ok(false);
    }
    let event = event.ok_or(Error::Malformed)?;
    let at: i64 = state.try_get("active_at")?;
    let after: Option<Uuid> = state.try_get("policy_after")?;
    let device: rss_mdm_agent_wire::DeviceId =
        state.try_get::<uuid::Uuid, _>("device").and_then(|id| {
            rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
        })?;
    let tenant = tx.tenant_id().to_string();
    let next: Option<(Uuid, Uuid)> = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as("SELECT id,current_version FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND state='enabled' AND definition->'action'->>'kind'='native_collection' AND definition->'action'->'schedule'->'trigger'->>'kind' IN('check_in','device') AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 1")
            .bind(tenant).bind(after).fetch_optional(c).await
    })).await?;
    let Some((policy, version)) = next else {
        clear(tx, device, false).await?;
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
            let target = super::model::Target { device };
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
        sqlx::query("UPDATE mdm_inventory.collection_native_checkins SET policy_after = $3 WHERE tenant_id = CAST($1 AS uuid) AND device = $2")
            .bind(tenant).bind(device.into_uuid()).bind(policy).execute(c).await?;
        Ok(())
    })).await?;
    Ok(true)
}
async fn clear(
    tx: &mut PgTransaction<'_>,
    device: rss_mdm_agent_wire::DeviceId,
    stale: bool,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_inventory.collection_native_checkins SET active_event = NULL, active_at = NULL, policy_after = NULL, pending_event = CASE WHEN $3 THEN NULL ELSE pending_event END, pending_at = CASE WHEN $3 THEN NULL ELSE pending_at END WHERE tenant_id = CAST($1 AS uuid) AND device = $2")
            .bind(tenant).bind(device.into_uuid()).bind(stale).execute(c).await?;
        Ok(())
    })).await?;
    Ok(())
}
