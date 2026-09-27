use super::*;
impl super::super::Planning {
    pub(crate) async fn advance_assignment_in(
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
            wake_native_in(tx, device).await?;
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
pub(crate) async fn wake_native_in(tx: &mut PgTransaction<'_>, device: &str) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let name = device.to_owned();
    // Authority ingress exists even without configuration policies. Do not create
    // idle per-device configuration state unless an assignment can use it.
    let changed=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar::<_,i64>("INSERT INTO mdm_planning.configuration_devices(tenant_id,device) SELECT $1::uuid,$2 WHERE EXISTS(SELECT 1 FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=$2) OR EXISTS(SELECT 1 FROM mdm_policy.policies p WHERE p.tenant_id=$1::uuid AND p.enabled AND p.definition->'behavior'->>'kind'='configuration' AND (mdm_planning.scope_admission((p.definition->>'scope')::uuid,$2)->>'state'<>'excluded')) ON CONFLICT(tenant_id,device) DO UPDATE SET input_revision=mdm_planning.configuration_devices.input_revision+1 RETURNING input_revision").bind(tenant).bind(name).fetch_optional(c).await
    })).await?;
    if changed.is_none() {
        return Ok(());
    }
    let target = rss_reconcile::Target::new(
        crate::execution::recovery_scope(tx.tenant_id()),
        format!("configuration:{device}"),
    )
    .map_err(|_| Error::Malformed)?;
    rss_reconcile_postgres::messaging::wake_in(tx, &target, (), |_, _| Box::pin(async { Ok(()) }))
        .await?;
    Ok(())
}
