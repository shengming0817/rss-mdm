//! Group reports its own execution and queues; App composes product readiness.
use super::*;
impl Groups {
    pub fn task_state(&self) -> Option<rss_runtime::TaskState> {
        self.task_status.get().map(rss_runtime::TaskStatus::current)
    }
    pub fn input_observed(&self) -> bool {
        self.input_state.load(std::sync::atomic::Ordering::Acquire) != 0
    }
    pub fn input_failed(&self) -> bool {
        self.input_state.load(std::sync::atomic::Ordering::Acquire) == 2
    }
    pub async fn queue_health(
        &self,
        budget: std::time::Duration,
    ) -> std::result::Result<[u64; 5], Error> {
        self.runtime.local_tx(self.tenant,rss_transactional_messaging::policy::OperationDeadline::from_remaining(budget),|tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();
            tx.with_connection(move |c|Box::pin(async move {
                let row:(i64,i64,i64,i64,i64)=sqlx::query_as("SELECT
                    (SELECT count(*) FROM (SELECT 1 FROM mdm_assets.group_tasks j WHERE tenant_id=$1::uuid AND NOT completed AND cursor IS NULL AND NOT EXISTS(SELECT FROM mdm_group.member_runs r WHERE(r.tenant_id,r.id)=(j.tenant_id,j.id) AND r.processed_count>0) LIMIT 1001) q),
                    (SELECT count(*) FROM (SELECT 1 FROM mdm_assets.group_tasks j WHERE tenant_id=$1::uuid AND NOT completed AND (cursor IS NOT NULL OR EXISTS(SELECT FROM mdm_group.member_runs r WHERE(r.tenant_id,r.id)=(j.tenant_id,j.id) AND r.processed_count>0)) LIMIT 1001) q),
                    (SELECT count(*) FROM (SELECT 1 FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND completed AND failure IS NULL LIMIT 1001) q),
                    (SELECT count(*) FROM (SELECT 1 FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND failure IS NOT NULL AND failure<>'superseded' LIMIT 1001) q),
                    (SELECT count(*) FROM (SELECT 1 FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND failure='superseded' LIMIT 1001) q)")
                    .bind(tenant).fetch_one(c).await?;
                Ok([row.0 as u64,row.1 as u64,row.2 as u64,row.3 as u64,row.4 as u64])
            })).await
        })).await.fold(Ok,|_|Err(Error::Unavailable(Failure::AssetsStorage)),|_|Err(Error::Unavailable(Failure::AssetsStorage)),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|_|Err(Error::Conflict))
    }
}
