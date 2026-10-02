use super::*;
impl super::super::Planning {
    pub async fn advance_assignment_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        policy: Uuid,
        after: Option<String>,
    ) -> Result<()> {
        let Some(p) = storage::read_in(self.policy_store.reader(), tx, policy).await? else {
            return crate::automation::jobs::finish_job_in(tx, &self.audit_store, task, None).await;
        };
        let tenant = tx.tenant_id().to_string();
        let id = p.id.to_string();
        let mut devices=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,String>("WITH wanted AS (SELECT r.device FROM mdm_policy.policies p JOIN mdm_planning.scopes s ON s.tenant_id=p.tenant_id AND s.id=(p.definition->>'scope')::uuid JOIN mdm_planning.scope_results r ON r.tenant_id=s.tenant_id AND r.run=s.resolution WHERE p.tenant_id=$1::uuid AND p.id=$2::uuid UNION SELECT device FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND policy=$2::uuid) SELECT device FROM wanted WHERE device>coalesce($3,'') COLLATE \"C\" ORDER BY device COLLATE \"C\" LIMIT 65")
                .bind(tenant).bind(id).bind(after).fetch_all(c).await
        })).await?;
        let more = devices.len() > 64;
        devices.truncate(64);
        for device in &devices {
            rss_mdm_execution_service::wake::wake_native_in(
                std::sync::Arc::new(crate::planning::execution_source::ExecutionSource),
                tx,
                device,
            )
            .await?;
        }
        if more {
            {
                let tenant = tx.tenant_id().to_string();
                let next = devices.last().cloned();
                tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_automation.automation_jobs SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(task.to_string()).bind(next).execute(c).await?;Ok(())})).await?;
                Ok(())
            }
        } else {
            crate::automation::jobs::finish_job_in(tx, &self.audit_store, task, None).await
        }
    }
}
