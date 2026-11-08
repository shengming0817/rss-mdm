use super::*;
/// Persisted round-robin cursor prevents a bounded policy page starving later assignments.
pub async fn agent_versions_in(
    tx: &mut PgTransaction<'_>,
    registration: String,
) -> Result<Vec<Uuid>> {
    let tenant = tx.tenant_id().to_string();
    let kinds = vec!["software"];
    let ids=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_software_deployment.agent_admission (tenant_id, device) VALUES (CAST($1 AS uuid), CAST($2 AS text)) ON CONFLICT DO NOTHING").bind(&tenant).bind(registration.to_string()).execute(&mut *c).await?;
        let after=sqlx::query_scalar::<_,Option<Uuid>>("SELECT policy_after FROM mdm_software_deployment.agent_admission WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text) FOR UPDATE").bind(&tenant).bind(registration.to_string()).fetch_one(&mut *c).await?;
        let rows=sqlx::query("SELECT id,current_version FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND (state='enabled') AND (definition->'action'->>'kind' =ANY($3) AND definition->'action'->>'channel'='agent') AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 64").bind(&tenant).bind(after).bind(kinds).fetch_all(&mut *c).await?;
        let next=if rows.len()==64 {rows.last().map(|r|r.try_get::<Uuid,_>("id")).transpose()?} else {None};
        sqlx::query("UPDATE mdm_software_deployment.agent_admission SET policy_after = $3 WHERE tenant_id = CAST($1 AS uuid) AND device = CAST($2 AS text)").bind(tenant).bind(registration.to_string()).bind(next).execute(c).await?;
        rows.into_iter().map(|r|r.try_get::<Uuid,_>("current_version")).collect::<std::result::Result<Vec<_>,sqlx::Error>>()
    })).await?;
    Ok(ids)
}
