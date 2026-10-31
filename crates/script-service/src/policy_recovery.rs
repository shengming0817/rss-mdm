//! Policy changes wake all historical tasks, including after an action kind change.
use crate::{Error, Result, Transactions};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;
/// A fixed revision window prevents a later wake from being acknowledged by an older page.
pub async fn advance_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<bool> {
    service.validate_in(tx)?;
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("SELECT * FROM mdm_script.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 FOR UPDATE").bind(tenant).bind(id).fetch_optional(c).await
    })).await?;
    let Some(row) = row else { return Ok(false) };
    let revision: i64 = row.try_get("input_revision")?;
    let consumed: i64 = row.try_get("input_consumed")?;
    let mut window: i64 = row.try_get("input_window")?;
    let mut after: Option<Uuid> = row.try_get("recovery_after")?;
    let mut done: bool = row.try_get("runs_done")?;
    let fresh = window == consumed;
    if fresh {
        window = revision;
        after = None;
        done = false;
    }
    if window == consumed {
        return Ok(false);
    }
    if !done {
        let tenant = tx.tenant_id().to_string();
        let mut rows=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,Uuid>("SELECT r.id FROM mdm_script.runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::uuid IS NULL OR r.id>$3) ORDER BY r.id LIMIT 33").bind(tenant).bind(id).bind(after).fetch_all(c).await
        })).await?;
        done = rows.len() <= 32;
        rows.truncate(32);
        after = rows.last().copied();
        for run in rows {
            crate::wake::run_in(&service.reconcile_messaging, tx, run).await?;
        }
    }
    let tenant = tx.tenant_id().to_string();
    let consumed = if done { window } else { consumed };
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("UPDATE mdm_script.policy_recovery SET input_consumed=$3,input_window=$4,recovery_after=$5,runs_done=$6 WHERE tenant_id=$1::uuid AND policy=$2")
            .bind(tenant).bind(id).bind(consumed).bind(window).bind(after).bind(done).execute(c).await?;Ok(())
    })).await?;
    Ok(consumed < revision)
}
