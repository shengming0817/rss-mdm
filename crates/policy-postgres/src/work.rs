//! Policy-owned durable work records, borrowed from the initiating transaction.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Policy-local durable work; no cross-domain dispatcher consumes this type.
pub enum Work {
    /// Advance one independently identified event batch.
    PolicyEvent {
        /// Original accepted event batch.
        batch: Uuid,
    },
    /// Recompute assignments for the current Policy.
    PolicyReconcile {
        /// Authored Policy identity.
        policy: Uuid,
    },
    /// Fan out a completed Scope publication.
    PolicyScope {
        /// Source Scope identity.
        scope: Uuid,
        /// Completed publication identity.
        run: Uuid,
    },
}
impl Work {
    /// Stable persisted work kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PolicyScope { .. } => "policy_scope",
            Self::PolicyReconcile { .. } => "policy_reconcile",
            Self::PolicyEvent { .. } => "policy_event",
        }
    }
    /// Business target identifier.
    pub fn target(&self) -> String {
        match self {
            Self::PolicyScope { scope, .. } => scope.to_string(),
            Self::PolicyReconcile { policy } => policy.to_string(),
            Self::PolicyEvent { batch } => batch.to_string(),
        }
    }
}

use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use sqlx::Row;
/// Insert the original work and its commit-delivered notification atomically.
pub async fn enqueue_in(tx: &mut PgTransaction<'_>, id: Uuid, input: &Work) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    let document = serde_json::to_value(input).map_err(|_| crate::STORAGE.fault("work.input"))?;
    let kind = input.kind();
    let target = input.target();
    tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_policy.work(tenant_id,id,kind,target,input) VALUES($1::uuid,$2,$3,$4,$5)").bind(tenant).bind(id).bind(kind).bind(target).bind(document).execute(&mut *c).await?;
        sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'policy_input')").execute(c).await?;
        Ok(())
    })).await
}
/// Durable work observed by the worker; absence is distinct from completion.
pub struct Record {
    /// Original typed work.
    pub input: Work,
    /// Committed terminal state.
    pub completed: bool,
    /// Closed product failure code, when terminal.
    pub failure: Option<String>,
    /// Last committed page boundary.
    pub cursor: Option<String>,
    /// Whether its RSS wake was committed.
    pub forwarded: bool,
}
/// Read one retained task in the initiating tenant.
pub async fn read_in(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Option<Record>, PgError> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT input,completed,failure,cursor,forwarded FROM mdm_policy.work WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_optional(c).await})).await?;
    row.map(|r| {
        Ok(Record {
            input: serde_json::from_value(r.try_get("input")?)
                .map_err(|_| crate::STORAGE.fault("work.decode"))?,
            completed: r.try_get("completed")?,
            failure: r.try_get("failure")?,
            cursor: r.try_get("cursor")?,
            forwarded: r.try_get("forwarded")?,
        })
    })
    .transpose()
}
/// Advance a page only in the transaction that published its effects.
pub async fn cursor_in(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    cursor: Option<String>,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("UPDATE mdm_policy.work SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant)
                .bind(id)
                .bind(cursor)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}

/// Pending work whose wake has not yet committed.
pub async fn pending_in(tx: &mut PgTransaction<'_>) -> Result<Vec<(String, String)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query_as("SELECT id::text,kind FROM mdm_policy.work WHERE tenant_id=$1::uuid AND NOT forwarded ORDER BY id LIMIT 64").bind(tenant).fetch_all(c).await})).await
}
/// Mark forwarding inside the same transaction as the RSS wake.
pub async fn forwarded_in(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_policy.work SET forwarded=true WHERE tenant_id=$1::uuid AND id=$2 AND NOT forwarded").bind(tenant).bind(id).execute(c).await.map(|r|r.rows_affected()>0)})).await
}
/// Transition a task to its terminal result, returning its business audit identity once.
pub async fn finish_in(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    failure: Option<String>,
) -> Result<Option<(String, String)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query_as("UPDATE mdm_policy.work SET completed=true,failure=$3 WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed RETURNING target,kind").bind(tenant).bind(id).bind(failure).fetch_optional(c).await})).await
}
/// Check an exact task identity, optionally requiring terminal state.
pub async fn exists_in(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    completed: bool,
) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_policy.work WHERE tenant_id=$1::uuid AND id=$2 AND (NOT $3 OR completed))").bind(tenant).bind(id).bind(completed).fetch_one(c).await})).await
}
/// Record a replacement without changing either accepted identity.
pub async fn replacement_in(
    tx: &mut PgTransaction<'_>,
    old: Uuid,
    new: Uuid,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(
                "UPDATE mdm_policy.work SET replacement_task=$3 WHERE tenant_id=$1::uuid AND id=$2",
            )
            .bind(tenant)
            .bind(old)
            .bind(new)
            .execute(c)
            .await?;
            Ok(())
        })
    })
    .await
}
/// Bounded queue counts for health reporting.
pub async fn counts_in(tx: &mut PgTransaction<'_>) -> Result<[u64; 5], PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {
 let row:(i64,i64,i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM(SELECT 1 FROM mdm_policy.work WHERE tenant_id=$1::uuid AND failure IS NULL AND NOT completed AND NOT forwarded LIMIT 1001) q),(SELECT count(*) FROM(SELECT 1 FROM mdm_policy.work WHERE tenant_id=$1::uuid AND failure IS NULL AND NOT completed AND forwarded LIMIT 1001) q),(SELECT count(*) FROM(SELECT 1 FROM mdm_policy.work WHERE tenant_id=$1::uuid AND failure IS NULL AND completed LIMIT 1001) q),(SELECT count(*) FROM(SELECT 1 FROM mdm_policy.work WHERE tenant_id=$1::uuid AND failure IS NOT NULL AND failure<>'superseded' LIMIT 1001) q),(SELECT count(*) FROM(SELECT 1 FROM mdm_policy.work WHERE tenant_id=$1::uuid AND failure='superseded' LIMIT 1001) q)").bind(tenant).fetch_one(c).await?;
 Ok([row.0 as u64,row.1 as u64,row.2 as u64,row.3 as u64,row.4 as u64])
 })).await
}
