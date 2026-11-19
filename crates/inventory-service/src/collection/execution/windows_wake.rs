//! Wake discovery and current qualification belong to collection execution.
use super::{CollectionService, model::Target};
use crate::transaction::Result;
use uuid::Uuid;
impl CollectionService {
    pub async fn windows_wake_pending_on(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        c: &mut sqlx::PgConnection,
        device: &rss_mdm_agent_wire::DeviceId,
    ) -> Result<bool> {
        let tenant = execution.tenant();
        if !rss_mdm_registration_service::lifecycle::work_allowed_on(
            rss_mdm_install_support::StorageProfile::Mdm,
            c,
            &tenant.to_string(),
            device,
        )
        .await?
        {
            return Ok(false);
        }
        let target = Target { device: *device };
        let mut after = Uuid::nil();
        loop {
            let ids:Vec<Uuid>=sqlx::query_scalar("SELECT t.id FROM mdm_inventory.collection_tasks AS t INNER JOIN mdm_access.collection_runs AS r ON (r.tenant_id, r.id) = (t.tenant_id, t.collection_run) WHERE t.tenant_id = CAST($1 AS uuid) AND t.device = $2 AND t.id > $3 AND t.native_delivery IN ('prepared', 'sent') AND t.deadline > floor(EXTRACT(EPOCH FROM clock_timestamp())) AND r.source = 'mdm.windows' AND r.sealed_at IS NULL ORDER BY t.id LIMIT 64").bind(tenant.to_string()).bind(device.into_uuid()).bind(after).fetch_all(&mut *c).await?;
            for id in &ids {
                after = *id;
                if super::native::eligible_on(&self.transactions, c, tenant, &target, *id).await? {
                    return Ok(true);
                }
            }
            if ids.len() < 64 {
                return Ok(false);
            }
        }
    }
}
