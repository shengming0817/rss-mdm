//! Read-only provenance for current optional Agent events; no MDM Policy execution writes DA.
pub async fn parent_current_on(
    c: &mut sqlx::PgConnection,
    device: &rss_mdm_agent_wire::DeviceId,
    id: uuid::Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT FROM rss_da.access_runs WHERE tenant_id = CAST(NULLIF(current_setting('rss.tenant_id', TRUE), '') AS uuid) AND id = $1 AND device = $2 AND state ->> 'execution' = 'running' AND state ->> 'startedAt' IS NOT NULL)")
        .bind(id).bind(device.into_uuid()).fetch_one(c).await
}

pub async fn event_progress_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    id: uuid::Uuid,
) -> super::transaction::Result<rss_mdm_task_state::RunState> {
    Ok(super::storage::read_run(tx, id).await?.state)
}
