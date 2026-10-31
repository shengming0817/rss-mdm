//! Cancel exact registration work without a second transaction or terminal-result mirror.
use crate::{Error, transaction::Result};
use rss_mdm_audit_integration::{AuditIntent, Fact, RequestAudit};
use sqlx::Row;
use uuid::Uuid;
pub async fn retire_in(
    c: &mut sqlx::PgConnection,
    facts: &mut Vec<Fact>,
    tenant: &str,
    registration: Uuid,
) -> Result<()> {
    let audit = RequestAudit::new(
        tenant.to_owned(),
        "credential_revoke",
        AuditIntent::Management,
    );
    audit.identify_service("registration-retirement");
    audit.registration(registration);
    let mut after = Uuid::nil();
    loop {
        let rows = sqlx::query("SELECT id,agent_state AS state,native_delivery FROM mdm_inventory.collection_tasks a WHERE tenant_id=$1::uuid AND registration=$2 AND id>$3 AND ((agent_state->>'execution' IN ('not_started','running','waiting_reboot','unknown') AND agent_state->>'cancellation'='none') OR native_delivery IN('queued','prepared')) AND EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE (r.tenant_id,r.id)=(a.tenant_id,a.registration) AND (r.state<>'active' OR (EXISTS(SELECT 1 FROM mdm_access.devices d WHERE (d.tenant_id,d.id)=(r.tenant_id,r.device) AND d.retirement IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE (w.tenant_id,w.execution)=(a.tenant_id,a.id))))) ORDER BY id LIMIT 64").bind(tenant).bind(registration).bind(after).fetch_all(&mut *c).await?;
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
                .bind(registration)
                .bind(id)
                .bind(previous)
                .bind(serde_json::to_value(state).map_err(|_| Error::Malformed)?)
                .fetch_one(&mut *c)
                .await?
            } else {
                sqlx::query_scalar::<_, bool>(
                    "SELECT mdm_inventory.cancel_retired_collection($1,$2,$3)",
                )
                .bind(registration)
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
                &format!("registration-retirement:{registration}:task:{id}"),
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

/// Pending execution and the first unconfirmed task across every retirement registration.
pub async fn progress_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    registrations: &[Uuid],
) -> Result<(bool, Option<Uuid>)> {
    let row: (bool, Option<Uuid>) = sqlx::query_as("SELECT count(*)>0,(array_agg(t.id ORDER BY t.id) FILTER(WHERE t.agent_state->>'execution'='unknown' OR (t.native_delivery='sent' AND ((report.sealed_at IS NOT NULL AND report.reason<>'complete') OR (report.sealed_at IS NULL AND t.deadline<=floor(extract(epoch FROM clock_timestamp()))::bigint)))))[1] FROM mdm_inventory.collection_tasks t LEFT JOIN mdm_access.collection_runs report ON(report.tenant_id,report.id)=(t.tenant_id,t.collection_run) WHERE t.tenant_id=$1::uuid AND t.registration=ANY($2) AND (t.agent_state->>'execution' IN('running','waiting_reboot','unknown') OR (t.native_delivery='sent' AND (report.sealed_at IS NULL OR report.reason<>'complete')))")
        .bind(tenant).bind(registrations).fetch_one(c).await?;
    Ok(row)
}
