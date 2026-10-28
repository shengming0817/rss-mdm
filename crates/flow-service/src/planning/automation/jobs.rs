use super::*;
use sqlx::Row;
impl Planning {
    pub async fn task_read_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        target: Option<&str>,
    ) -> Result<Value> {
        let missing = || {
            Error::Planning(crate::planning::error::PlanningError::Missing(
                crate::planning::error::Missing::Scope,
            ))
        };
        let (job, done, failure, _, forwarded) = crate::automation::jobs::read_in(tx, id).await?;
        if target.is_some_and(|t| t != job.target()) || !matches!(job, JobInput::Scope { .. }) {
            return Err(missing().into());
        }
        let mut processed = 0u64;
        let mut members = 0u64;
        if failure.is_none() {
            let tenant = self.tenant.to_string();
            let row=tx.with_connection(move |c|Box::pin(async move {
                sqlx::query("SELECT object_count,member_count FROM mdm_planning.scope_runs WHERE tenant_id=$1::uuid AND id=$2")
                    .bind(tenant).bind(id).fetch_optional(c).await
            })).await?;
            if let Some(row) = row {
                processed = row.try_get::<i64, _>("object_count")? as u64;
                members = row.try_get::<i64, _>("member_count")? as u64;
            }
        }
        let status = if failure.as_deref() == Some("superseded") {
            "superseded"
        } else if failure.is_some() {
            "failed"
        } else if done {
            "completed"
        } else if forwarded {
            "running"
        } else {
            "pending"
        };
        let tenant = self.tenant.to_string();
        let failure_detail: Option<Value> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT failure_detail FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(id.to_string()).fetch_one(c).await
        })).await?;
        let tenant = self.tenant.to_string();
        let replacement:Option<Uuid>=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT replacement_task FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(c).await
        })).await?;
        Ok(
            serde_json::json!({"replacement_task":replacement,"failure_detail":failure_detail,"task":id,"kind":job.kind(),"target":job.target(),"status":status,"processed":processed,"members":members,"failure":failure}),
        )
    }
}
