//! Periodic recovery uses the existing publication lifecycle, locks and original call identities.
use super::service::PublicationDirectory;
use rss_contract::Timepoint;
use rss_request_context::Deadline;
use std::{sync::Arc, time::Duration};
struct Timer;
impl rss_request_context::Clock for Timer {
    #[allow(
        clippy::disallowed_methods,
        reason = "publication lifecycle monotonic clock provider"
    )]
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}
impl PublicationDirectory {
    pub fn registration(self: Arc<Self>) -> rss_runtime::ManagedTaskRegistration {
        let (task, _) =
            rss_runtime::ManagedTask::prepare("mdm-software-publication", Duration::from_secs(8));
        task.into_registration(move|cancel|async move {
            let mut after:Option<(uuid::Uuid,i64,String)>=None;
            loop {
                if cancel.is_cancelled(){return Ok(());}
                let page=sqlx::query_as::<_,(uuid::Uuid,i64,String,String)>("SELECT tenant_id,expected_epoch,id,source FROM mdm_software_composition.work_scopes($1,$2,$3)")
                    .bind(after.as_ref().map(|v|v.0)).bind(after.as_ref().map(|v|v.1)).bind(after.as_ref().map(|v|v.2.as_str()))
                    .fetch_all(&self.discovery_pool).await;
                let page=match page {Ok(page)=>page,Err(_)=>{
                    tokio::select!{()=cancel.cancelled()=>return Ok(()),()=tokio::time::sleep(Duration::from_secs(5))=>()}
                    continue;
                }};
                if page.is_empty(){
                    after=None;
                    tokio::select!{()=cancel.cancelled()=>return Ok(()),()=tokio::time::sleep(Duration::from_secs(5))=>()}
                    continue;
                }
                for (tenant,epoch,key,source) in page {
                    if cancel.is_cancelled(){return Ok(());}
                    after=Some((tenant,epoch,key.clone()));
                    let Some(service)=self.services.get(&source) else {continue;};
                    let tenant=rss_request_context::TenantId::parse(&tenant.to_string()).map_err(rss_runtime::ShutdownError::new)?;
                    let execution=rss_transactional_messaging::fence::ExecutionBinding::new(self.storage,tenant,rss_transactional_messaging::fence::Epoch::new(epoch).map_err(rss_runtime::ShutdownError::new)?);
                    let operation=match service.operation(execution){Ok(value)=>value,Err(error)=>{eprintln!("{}",failure_event(&source,tenant,&error,None));continue;}};
                    let cutoff=Deadline::from_timeout(&Timer,Duration::from_secs(6)).map_err(rss_runtime::ShutdownError::new)?;
                    let work=match operation.reconciliation_work(&key,cutoff).await {Ok(Some(value))=>value,Ok(None)=>continue,Err(error)=>{eprintln!("{}",failure_event(&source,tenant,&error,None));continue;}};
                    let now=self.clock.unix_seconds().ok_or_else(||rss_runtime::ShutdownError::new(crate::management::Error::Unavailable(crate::management::Failure::Clock)))?;
                    let at=Timepoint::try_from(now).map_err(rss_runtime::ShutdownError::new)?;
                    // Original call settlement owns its budget; shutdown only stops between calls.
                    let outcome=if work.withdrawal {operation.reconcile_withdrawal(work.publication,work.attempt,cutoff).await.map(|_|())}else{operation.reconcile(work.publication,work.attempt,at,cutoff).await.map(|_|())};
                    if let Err(error)=outcome{eprintln!("{}",failure_event(&source,tenant,&error,Some(&work)));}
                }
            }
        })
    }
}

fn failure_event(
    source: &str,
    tenant: rss_request_context::TenantId,
    error: &crate::publication::Error,
    work: Option<&crate::publication::PublicationWork>,
) -> serde_json::Value {
    use crate::publication::Error as E;
    let mut error = error;
    let mut stage = None;
    while let E::Diagnostic {
        stage: next,
        category,
        ..
    } = error
    {
        stage.get_or_insert(*next);
        error = category;
    }
    let category = match error {
        E::PublicationNotFound => "record_not_found",
        E::Unsupported => "unsupported",
        E::Input => "input",
        E::Identity => "identity",
        E::Content => "content",
        E::Conflict => "conflict",
        E::Blocked => "blocked",
        E::ArtifactAddress => "artifact_address",
        E::ArtifactBudget => "artifact_budget",
        E::ArtifactDigest => "artifact_digest",
        E::ArtifactTransport => "artifact_transport",
        E::ArtifactTimeout => "artifact_timeout",
        E::Source => "source",
        E::NotStarted(_) => "not_started",
        E::RolledBack(_) => "rolled_back",
        E::RollbackFailed(_) => "rollback_failed",
        E::CommitUnknown(_) => "commit_unknown",
        E::Fenced(_) => "fenced",
        E::Resource(_) => "resource",
        E::Release(_) => "release",
        E::Diagnostic { .. } => unreachable!(),
    };
    let mut value = serde_json::json!({"event":"mdm_publication_recovery_failure","tenant":tenant.to_string(),"source":source,"phase":if work.is_some(){"reconcile"}else{"scan"},"category":category,"stage":stage});
    if let Some(work) = work {
        value["publication"] = serde_json::json!(
            work.publication
                .digest()
                .bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        value["attempt"] = serde_json::json!(work.attempt);
        value["withdrawal"] = serde_json::json!(work.withdrawal);
    }
    value
}
#[cfg(test)]
#[path = "../../../tests/management/publication_worker.rs"]
mod tests;
