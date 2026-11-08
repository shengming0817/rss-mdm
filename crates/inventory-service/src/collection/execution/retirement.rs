//! Cancel exact device work without a second transaction or terminal-result mirror.
use crate::{Error, transaction::Result};
use rss_mdm_audit_integration::{AuditIntent, Fact, RequestAudit};
use sqlx::Row;
use uuid::Uuid;
pub async fn retire_in(
    c: &mut sqlx::PgConnection,
    facts: &mut Vec<Fact>,
    tenant: &str,
    device: String,
) -> Result<()> {
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Background,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        tenant.to_owned(),
        "credential_revoke",
        AuditIntent::Management,
    );
    audit.identify_service("device-retirement");
    audit.target_device(&device);
    let mut after = Uuid::nil();
    loop {
        let rows = sqlx::query("SELECT id, agent_state AS state, native_delivery FROM mdm_inventory.collection_tasks AS a WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND id > $3 AND ((agent_state ->> 'execution' IN ('not_started', 'running', 'waiting_reboot', 'unknown') AND agent_state ->> 'cancellation' = 'none') OR native_delivery IN ('queued', 'prepared')) AND EXISTS (SELECT 1 FROM mdm_access.devices AS r WHERE (r.tenant_id, r.id) = (a.tenant_id, a.device) AND (r.state <> 'active' OR (EXISTS (SELECT 1 FROM mdm_access.devices AS d WHERE (d.tenant_id, d.id) = (r.tenant_id, r.id) AND d.retirement IS NOT NULL) AND NOT EXISTS (SELECT 1 FROM mdm_devices.retirement_work AS w WHERE (w.tenant_id, w.execution) = (a.tenant_id, a.id))))) ORDER BY id LIMIT 64").bind(tenant).bind(&device).bind(after).fetch_all(&mut *c).await?;
        let count = rows.len();
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            after = id;
            let previous: Option<serde_json::Value> = row.try_get("state")?;
            let changed = if let Some(previous) = previous {
                let mut state: rss_mdm_task_state::RunState =
                    crate::transaction::stored(serde_json::from_value(previous.clone()))?;
                state.cancel();
                sqlx::query_scalar::<_, bool>(
                    "SELECT mdm_inventory.save_retired_collection_agent($1,$2,$3,$4)",
                )
                .bind(&device)
                .bind(id)
                .bind(previous)
                .bind(serde_json::to_value(state).map_err(|_| Error::Malformed)?)
                .fetch_one(&mut *c)
                .await?
            } else {
                sqlx::query_scalar::<_, bool>(
                    "SELECT mdm_inventory.cancel_retired_collection($1,$2,$3)",
                )
                .bind(&device)
                .bind(id)
                .bind(row.try_get::<String, _>("native_delivery")?)
                .fetch_one(&mut *c)
                .await?
            };
            if !changed {
                return Err(Error::Conflict.into());
            }
            audit.target(&id.to_string());
            facts.push(Fact::business(
                &audit,
                rss_mdm_audit_integration::operation::OperationOwner::CollectionExecution,
                &format!("device-retirement:{device}:task:{id}"),
                200,
                "success",
                None,
            )?);
        }
        if count < 64 {
            break;
        }
    }
    audit.finalize(None);
    Ok(())
}

/// Pending execution and the first unconfirmed task across every retirement device.
pub async fn progress_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    devices: &[String],
) -> Result<(bool, Option<Uuid>)> {
    let row: (bool, Option<Uuid>) = sqlx::query_as("SELECT count(*) > 0, ((array_agg(t.id ORDER BY t.id) FILTER (WHERE t.agent_state ->> 'execution' = 'unknown' OR (t.native_delivery = 'sent' AND ((report.sealed_at IS NOT NULL AND report.reason <> 'complete') OR (report.sealed_at IS NULL AND t.deadline <= CAST(floor(EXTRACT(EPOCH FROM clock_timestamp())) AS bigint)))))))[1] FROM mdm_inventory.collection_tasks AS t LEFT JOIN mdm_access.collection_runs AS report ON (report.tenant_id, report.id) = (t.tenant_id, t.collection_run) WHERE t.tenant_id = CAST($1 AS uuid) AND t.device = ANY($2) AND (t.agent_state ->> 'execution' IN ('running', 'waiting_reboot', 'unknown') OR (t.native_delivery = 'sent' AND (report.sealed_at IS NULL OR report.reason <> 'complete')))")
        .bind(tenant).bind(devices).fetch_one(c).await?;
    Ok(row)
}
