//! Immutable bounded task output fragments on the existing execution transaction.
use crate::Error;
use crate::{FrozenScript, runs::Run};
use crate::{Result, checked_input, stored};
use rss_mdm_agent_wire::runtime as wire;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
fn collection(plan: &FrozenScript, bytes: u32) -> Result<()> {
    let limit = plan.definition.spec().output_bytes;
    if bytes > limit {
        return Err(Error::Malformed.into());
    }
    Ok(())
}
pub async fn append(
    tx: &mut PgTransaction<'_>,
    plan: &FrozenScript,
    run: &Run,
    chunk: &wire::OutputChunk,
) -> Result<()> {
    collection(plan, chunk.manifest().bytes())?;
    append_checked(tx, run, chunk).await
}
async fn append_checked(
    tx: &mut PgTransaction<'_>,
    run: &Run,
    chunk: &wire::OutputChunk,
) -> Result<()> {
    if !matches!(
        run.state.execution,
        rss_mdm_task_state::Execution::Running | rss_mdm_task_state::Execution::Unknown
    ) {
        return Err(Error::Conflict.into());
    }
    let tenant = tx.tenant_id().to_string();
    let attempt = run.state.attempt().ok_or(Error::Conflict)?;
    let chunk = chunk.clone();
    let accepted=tx.with_connection(move|c|Box::pin(async move {
        let manifest=serde_json::to_value(chunk.manifest()).expect("closed manifest");
        let prior:Option<serde_json::Value>=sqlx::query_scalar("SELECT manifest FROM mdm_script.output_chunks WHERE tenant_id=$1::uuid AND attempt=$2 LIMIT 1")
            .bind(&tenant).bind(attempt).fetch_optional(&mut *c).await?;
        if prior.as_ref().is_some_and(|v|v!=&manifest){return Ok(false);}
        let index=i32::from(chunk.index());let bytes=chunk.bytes();
        sqlx::query("INSERT INTO mdm_script.output_chunks(tenant_id,attempt,chunk_index,manifest,bytes) VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
            .bind(&tenant).bind(attempt).bind(index).bind(&manifest).bind(&bytes).execute(&mut *c).await?;
        let existing:Vec<u8>=sqlx::query_scalar("SELECT bytes FROM mdm_script.output_chunks WHERE tenant_id=$1::uuid AND attempt=$2 AND chunk_index=$3")
            .bind(tenant).bind(attempt).bind(index).fetch_one(c).await?;
        Ok(existing==bytes)
    })).await?;
    if !accepted {
        return Err(Error::Conflict.into());
    }
    Ok(())
}
pub async fn assemble(
    tx: &mut PgTransaction<'_>,
    plan: &FrozenScript,
    run: &Run,
    result: &wire::ChunkedTaskResult,
) -> Result<wire::TaskResult> {
    collection(plan, result.manifest().bytes())?;
    let chunks = load_chunks(tx, run).await?;
    checked_input(result.assemble(chunks))
}

async fn load_chunks(tx: &mut PgTransaction<'_>, run: &Run) -> Result<Vec<wire::OutputChunk>> {
    let tenant = tx.tenant_id().to_string();
    let attempt = run.state.attempt().ok_or(Error::Conflict)?;
    let rows=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT manifest,chunk_index,bytes FROM mdm_script.output_chunks WHERE tenant_id=$1::uuid AND attempt=$2 ORDER BY chunk_index LIMIT 65").bind(tenant).bind(attempt).fetch_all(c).await})).await?;
    let chunks = rows
        .into_iter()
        .map(|row| {
            let manifest = stored(serde_json::from_value(row.try_get("manifest")?))?;
            let index = stored(u16::try_from(row.try_get::<i32, _>("chunk_index")?))?;
            stored(wire::OutputChunk::new(
                manifest,
                index,
                &row.try_get::<Vec<u8>, _>("bytes")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(chunks)
}
