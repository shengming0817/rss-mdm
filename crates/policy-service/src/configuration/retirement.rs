//! Configuration withdrawal and unresolved effects participate in the initiating retirement transaction.
use super::*;
pub struct CleanupProgress {
    pub pending: bool,
    pub blocker: Option<(i32, Option<Uuid>)>,
}
impl Transactions {
    pub async fn retirement_cleanup_in(
        &self,
        tx: &mut PgTransaction<'_>,
        retirement: Uuid,
        device: &str,
        audit: &RequestAudit,
    ) -> Result<CleanupProgress> {
        self.runtime.validate_transaction(tx)?;
        let tenant = tx.tenant_id();
        let name = device.to_owned();
        tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_planning.configuration_devices(tenant_id,device) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(tenant.to_string()).bind(name).execute(c).await?;Ok(())})).await?;
        self.reconcile_in(tx, device, audit).await?;
        let name = device.to_owned();
        let (mut pending,mut blocker)=tx.with_connection(move|c|Box::pin(async move{
   let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_planning.configuration_claims WHERE tenant_id=$1::uuid AND device=$2)").bind(tenant.to_string()).bind(&name).fetch_one(&mut *c).await?;
   let blocker:Option<(i32,Option<Uuid>)>=sqlx::query_as("SELECT 1,c.operation FROM mdm_planning.configuration_claims c JOIN mdm_planning.configuration_objects d USING(tenant_id,device,user_key,platform,object_kind,object_key) WHERE c.tenant_id=$1::uuid AND c.device=$2 AND d.diagnosis IN('configuration_conflict','native_group_conflict','removal_blocked_by_shared_unit') ORDER BY c.operation LIMIT 1").bind(tenant.to_string()).bind(name).fetch_optional(c).await?;
   Ok((pending,blocker))
  })).await?;
        let mut after = Uuid::nil();
        loop {
            let rows:Vec<(Uuid,bool,String)>=tx.with_connection(move|c|Box::pin(async move{
    sqlx::query_as("SELECT o.id,d.terminal_at IS NULL,d.status FROM mdm_planning.configuration_operations o JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text) JOIN mdm_devices.retirement_channels r ON(r.tenant_id,r.registration)=(o.tenant_id,o.registration) WHERE o.tenant_id=$1::uuid AND r.operation=$2 AND o.id>$3 ORDER BY o.id LIMIT 64").bind(tenant.to_string()).bind(retirement).bind(after).fetch_all(c).await
   })).await?;
            let count = rows.len();
            for (id, active, status) in rows {
                after = id;
                if active {
                    pending = true;
                } else if status != "applied" && self.dispatched_in(tx, id).await? {
                    pending = true;
                    blocker = blocker
                        .into_iter()
                        .chain(Some((0, Some(id))))
                        .min_by_key(|v| (v.0, v.1));
                }
            }
            if count < 64 {
                break;
            }
        }
        Ok(CleanupProgress { pending, blocker })
    }
}
