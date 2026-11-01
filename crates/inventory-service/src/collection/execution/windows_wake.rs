//! Wake discovery and current qualification belong to collection execution.
use super::{CollectionService, model::Target};
use crate::transaction::Result;
use uuid::Uuid;
impl CollectionService {
    pub async fn windows_wake_candidates_on(
        &self,
        c: &mut sqlx::PgConnection,
        after: Uuid,
    ) -> Result<Vec<Uuid>> {
        Ok(sqlx::query_scalar("SELECT DISTINCT t.registration FROM mdm_inventory.collection_tasks t JOIN mdm_access.collection_runs r ON (r.tenant_id,r.id)=(t.tenant_id,t.collection_run) JOIN mdm_access.registrations d ON(d.tenant_id,d.id,d.generation)=(t.tenant_id,t.registration,t.generation) WHERE t.tenant_id=$1::uuid AND t.registration>$2 AND d.state='active' AND t.native_delivery IN('prepared','sent') AND r.source='mdm.windows' AND r.sealed_at IS NULL AND t.deadline>floor(extract(epoch FROM clock_timestamp())) ORDER BY t.registration LIMIT 32").bind(self.transactions.tenant.to_string()).bind(after).fetch_all(c).await?)
    }
    pub async fn windows_wake_pending_on(
        &self,
        c: &mut sqlx::PgConnection,
        device: &str,
        registration: Uuid,
        generation: i64,
    ) -> Result<bool> {
        let tenant = self.transactions.tenant;
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
        let target = Target {
            device: device.into(),
            registration,
            generation,
        };
        let mut after = Uuid::nil();
        loop {
            let ids:Vec<Uuid>=sqlx::query_scalar("SELECT t.id FROM mdm_inventory.collection_tasks t JOIN mdm_access.collection_runs r ON(r.tenant_id,r.id)=(t.tenant_id,t.collection_run) WHERE t.tenant_id=$1::uuid AND t.registration=$2 AND t.generation=$3 AND t.device=$4 AND t.id>$5 AND t.native_delivery IN('prepared','sent') AND t.deadline>floor(extract(epoch FROM clock_timestamp())) AND r.source='mdm.windows' AND r.sealed_at IS NULL ORDER BY t.id LIMIT 64").bind(tenant.to_string()).bind(registration).bind(generation).bind(device).bind(after).fetch_all(&mut *c).await?;
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
