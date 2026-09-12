//! Only expired protocol sessions and cached responses are disposable; I01 and audit facts remain.
//! ref: PostgreSQL 17 SELECT FOR UPDATE SKIP LOCKED; sqlx 0.9 Transaction rollback-on-drop.
use crate::{AccessStore, Error, access_store::db};
use rss_runtime::{ManagedTask, ManagedTaskRegistration};
use sqlx::Row;
use std::{sync::Arc, time::Duration};

impl AccessStore {
    pub(crate) async fn prune_management(&self, tenant: &str) -> Result<u64, Error> {
        let mut tx = self.begin(tenant).await?;
        let expired=sqlx::query("SELECT registration::text,session_id FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND expires_at<clock_timestamp() ORDER BY expires_at,registration,session_id LIMIT 128 FOR UPDATE SKIP LOCKED")
            .bind(tenant).fetch_all(&mut *tx).await.map_err(db)?;
        let mut registrations = Vec::<String>::new();
        let mut sessions = Vec::<String>::new();
        for row in expired {
            registrations.push(row.try_get("registration").map_err(db)?);
            sessions.push(row.try_get("session_id").map_err(db)?);
        }
        if registrations.is_empty() {
            return Ok(0);
        }
        sqlx::query("DELETE FROM mdm_access.management_messages m USING unnest($2::text[],$3::text[]) k(registration,session_id) WHERE m.tenant_id=$1::uuid AND m.registration=k.registration::uuid AND m.session_id=k.session_id")
            .bind(tenant).bind(&registrations).bind(&sessions).execute(&mut *tx).await.map_err(db)?;
        let count=sqlx::query("DELETE FROM mdm_access.management_sessions s USING unnest($2::text[],$3::text[]) k(registration,session_id) WHERE s.tenant_id=$1::uuid AND s.registration=k.registration::uuid AND s.session_id=k.session_id")
            .bind(tenant).bind(&registrations).bind(&sessions).execute(&mut *tx).await.map_err(db)?.rows_affected();
        tx.commit().await.map_err(db)?;
        Ok(count)
    }
}
pub(crate) fn registration(access: Arc<AccessStore>, tenant: String) -> ManagedTaskRegistration {
    let (task, _) = ManagedTask::prepare("mdm-management-retention", Duration::from_secs(3));
    task.into_registration(move |token| async move {
        let mut tick=tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut failures=0u64;
        loop {
            tokio::select! { biased; ()=token.cancelled()=>return Ok(()), _=tick.tick()=>{} }
            let result=tokio::select! { biased; ()=token.cancelled()=>return Ok(()), result=tokio::time::timeout(Duration::from_secs(2),access.prune_management(&tenant))=>result };
            match result {
                Ok(Ok(count)) => { failures=0; if count>0 { eprintln!("{}",serde_json::json!({"event":"mdm_management_retention","sessions":count})); } }
                failed => {
                    failures=failures.saturating_add(1);
                    if failures.is_power_of_two() { eprintln!("{}",serde_json::json!({"event":"mdm_management_retention_failure","kind":if failed.is_err() { "deadline" } else { "access_store" },"count":failures})); }
                }
            }
        }
    })
}
