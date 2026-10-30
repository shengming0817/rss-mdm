//! Immutable query inputs and task progress belong to the asset query run.
use super::*;
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryInput {
    pub query: Query,
    pub scope: ReadScope,
    pub watermark: i64,
    pub as_of: i64,
}
pub struct QueryTask {
    pub input: QueryInput,
    pub summary: Summary,
    pub completed: bool,
    pub failure: Option<String>,
    pub cursor: Option<String>,
    pub started: bool,
}
pub fn target(tenant: TenantId, task: Uuid) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        rss_reconcile::Scope::new(tenant, "mdm.asset-queries").expect("constant scope"),
        format!("task:{task}"),
    )
    .expect("UUID target")
}
impl AssetService {
    fn check_query_transaction(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }
    pub async fn query_task_in(&self, tx: &mut PgTransaction<'_>, task: Uuid) -> Result<QueryTask> {
        self.check_query_transaction(tx)?;
        let tenant = self.tenant.to_string();
        let row = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT input,completed,failure,cursor,started,total,matched,unknown FROM mdm_assets.asset_query_runs WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(task).fetch_optional(c).await
        })).await?.ok_or(Error::NotFound)?;
        Ok(QueryTask {
            summary: Summary {
                total: row.try_get::<i64, _>("total")? as usize,
                matched: row.try_get::<i64, _>("matched")? as usize,
                unknown: row.try_get::<i64, _>("unknown")? as usize,
            },
            input: stored(serde_json::from_value(row.try_get("input")?))?,
            completed: row.try_get("completed")?,
            failure: row.try_get("failure")?,
            cursor: row.try_get("cursor")?,
            started: row.try_get("started")?,
        })
    }
    pub(super) async fn enqueue_query_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        input: &QueryInput,
    ) -> Result<()> {
        self.check_query_transaction(tx)?;
        if task.is_nil() || input.watermark < 0 {
            return Err(Error::Malformed.into());
        }
        let document = checked_input(serde_json::to_string(input))?;
        if document.len() > 1_048_576 {
            return Err(Error::Malformed.into());
        }
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_assets.asset_query_runs(tenant_id,id,input) VALUES($1::uuid,$2,$3::jsonb)")
                .bind(tenant).bind(task).bind(document).execute(c).await?;
            Ok(())
        })).await?;
        self.reconcile_messaging
            .wake_in(
                tx,
                &target(self.tenant, task),
                &rss_reconcile::ResourceSet::empty(self.tenant),
                (),
                |_, _| Box::pin(async { Ok(()) }),
            )
            .await?;
        crate::wake::task(tx, "asset_queries").await?;
        Ok(())
    }
    pub(super) async fn query_cursor_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        cursor: Option<String>,
    ) -> Result<()> {
        self.check_query_transaction(tx)?;
        let tenant = self.tenant.to_string();
        let changed = tx.with_connection(move |c| Box::pin(async move {
            Ok(sqlx::query("UPDATE mdm_assets.asset_query_runs SET cursor=$3,started=true WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed")
                .bind(tenant).bind(task).bind(cursor).execute(c).await?.rows_affected())
        })).await?;
        if changed != 1 {
            return Err(Error::Conflict.into());
        }
        Ok(())
    }
    pub(super) async fn finish_query_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        failure: Option<&str>,
    ) -> Result<()> {
        self.check_query_transaction(tx)?;
        let tenant = self.tenant.to_string();
        let reason = failure.map(str::to_owned);
        let changed = tx.with_connection(move |c| Box::pin(async move {
            Ok(sqlx::query("UPDATE mdm_assets.asset_query_runs SET completed=true,failure=$3 WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed")
                .bind(tenant).bind(task).bind(reason).execute(c).await?.rows_affected())
        })).await?;
        self.clear_evaluation(tx, task).await?;
        if changed == 0 {
            self.query_task_in(tx, task).await?;
            return Ok(());
        }
        let action = match failure {
            None => "automation_completed",
            Some("superseded") => "automation_superseded",
            Some(_) => "automation_failed",
        };
        let audit = RequestAudit::new(
            self.tenant.to_string(),
            action,
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("service:asset-query");
        audit.target(&task.to_string());
        audit.operation(
            task,
            action,
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let fact = rss_mdm_audit_integration::Fact::business(
            &audit,
            &format!("asset-query:{task}:terminal"),
            200,
            if failure.is_some() {
                "failed"
            } else {
                "success"
            },
            None,
        )
        .map_err(Error::from)?;
        let result = self
            .audit_store
            .append_in(tx, &fact)
            .await
            .map_err(Error::from);
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result?;
        Ok(())
    }
}
