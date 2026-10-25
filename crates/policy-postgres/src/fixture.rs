//! Current Policy state without publication receipts or business effects.
use crate::{Publication, STORAGE};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
/// Insert a new current Policy and its immutable execution version in the caller's tenant.
pub async fn published_in(tx: &mut PgTransaction<'_>, input: &Publication) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    let p = input.policy.clone();
    let frozen = input
        .frozen
        .clone()
        .ok_or_else(|| STORAGE.fault("fixture.frozen"))?;
    let fingerprint = p
        .definition
        .semantic()
        .map_err(|_| STORAGE.fault("fixture.definition"))?
        .to_vec();
    let definition = STORAGE.json("fixture.definition", serde_json::to_value(&p.definition))?;
    let author = input.author.clone();
    let at = input.at;
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at,execution_binding) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(&tenant).bind(p.id).bind(p.revision).bind(p.version).bind(p.number).bind(p.state.as_str()).bind(definition).bind(author).bind(at).bind(p.execution_binding.map(|v|v.to_vec())).execute(&mut *c).await?;
        sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,resource,resource_version,frozen,fingerprint,action_kind) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(tenant).bind(p.version).bind(p.id).bind(p.number).bind(p.definition.action.resource().map(|r|r.id())).bind(p.definition.action.resource().map(|r|r.version())).bind(frozen).bind(fingerprint).bind(p.definition.action.kind().as_str()).execute(c).await?;
        Ok(())
    })).await
}
