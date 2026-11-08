//! Cancel exact device work without a second transaction or terminal-result mirror.
use crate::device_access::execution::{Error, transaction::Result};
use rss_mdm_audit_integration::{AuditIntent, Fact, RequestAudit, operation::OperationOwner};
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
        rss_mdm_audit_integration::StorageProfile::Da,
        tenant.to_owned(),
        "credential_revoke",
        AuditIntent::Management,
    );
    audit.identify_service("access-retirement");
    audit.target_device(&device);
    sqlx::query("UPDATE rss_da.agent_delivery SET enabled=false,revision=revision+1 WHERE tenant_id=$1::uuid AND agent_device=$2 AND enabled").bind(tenant).bind(&device).execute(&mut *c).await?;
    let mut after = Uuid::nil();
    loop {
        let rows = sqlx::query("SELECT id, state AS state FROM rss_da.access_runs AS a WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND id > $3 AND (state ->> 'execution' IN ('not_started', 'running', 'waiting_reboot', 'unknown') AND state ->> 'cancellation' = 'none') AND EXISTS (SELECT 1 FROM mdm_access.devices AS r WHERE (r.tenant_id, r.id) = (a.tenant_id, a.device) AND (r.state <> 'active' OR (EXISTS (SELECT 1 FROM mdm_access.devices AS d WHERE (d.tenant_id, d.id) = (r.tenant_id, r.id) AND d.retirement IS NOT NULL) AND NOT EXISTS (SELECT 1 FROM mdm_devices.retirement_work AS w WHERE (w.tenant_id, w.execution) = (a.tenant_id, a.id))))) ORDER BY id LIMIT 64").bind(tenant).bind(&device).bind(after).fetch_all(&mut *c).await?;
        let count = rows.len();
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            after = id;
            let previous: Option<serde_json::Value> = row.try_get("state")?;
            let changed = if let Some(previous) = previous {
                let mut state: rss_mdm_task_state::RunState =
                    crate::device_access::execution::stored(serde_json::from_value(
                        previous.clone(),
                    ))?;
                state.cancel();
                sqlx::query_scalar::<_, bool>("SELECT rss_da.save_retired_access_run($1,$2,$3,$4)")
                    .bind(&device)
                    .bind(id)
                    .bind(previous)
                    .bind(serde_json::to_value(state).map_err(|_| Error::Malformed)?)
                    .fetch_one(&mut *c)
                    .await?
            } else {
                return Err(Error::Conflict.into());
            };
            if !changed {
                return Err(Error::Conflict.into());
            }
            audit.owned_operation(
                OperationOwner::DeviceAccessTask,
                id,
                "credential_revoke",
                AuditIntent::Management,
            );
            facts.push(Fact::business(
                &audit,
                OperationOwner::DeviceAccessTask,
                &format!("access-retirement:{device}:task:{id}"),
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
    let row: (bool, Option<Uuid>) = sqlx::query_as("SELECT count(*) > 0, ((array_agg(t.id ORDER BY t.id) FILTER (WHERE t.state ->> 'execution' = 'unknown')))[1] FROM rss_da.access_runs AS t WHERE t.tenant_id = CAST($1 AS uuid) AND t.device = ANY($2) AND t.state ->> 'execution' IN ('running', 'waiting_reboot', 'unknown')")
        .bind(tenant).bind(devices).fetch_one(c).await?;
    Ok(row)
}
