//! Periodic recovery uses the existing publication lifecycle, locks and original call identities.
use super::service::PublicationDirectory;
use rss_contract::Timepoint;
use rss_request_context::Deadline;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
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
            let mut cursors=BTreeMap::<String,String>::new();
            loop {
                for (source,service) in &self.services {
                    if cancel.is_cancelled(){return Ok(());}
                    let cutoff=Deadline::from_timeout(&Timer,Duration::from_secs(6)).map_err(rss_runtime::ShutdownError::new)?;
                    let page=tokio::select!{()=cancel.cancelled()=>return Ok(()),page=service.reconciliation_page(cursors.get(source).map_or("",String::as_str),32,cutoff)=>page};
                    let page=match page {Ok(page)=>page,Err(error)=>{eprintln!("{}",failure_event(source,service.tenant(),&error,None));continue;}};
                    let mut completed=true;
                    for work in page.work {
                        if cancel.is_cancelled(){return Ok(());}
                        let now=self.clock.unix_seconds().map_err(rss_runtime::ShutdownError::new)?;
                        let at=Timepoint::try_from(now).map_err(rss_runtime::ShutdownError::new)?;
                        let outcome=tokio::select! {
                            ()=cancel.cancelled()=>return Ok(()),
                            outcome=async {if work.withdrawal {service.reconcile_withdrawal(work.publication,work.attempt,cutoff).await.map(|_|())}else{service.reconcile(work.publication,work.attempt,at,cutoff).await.map(|_|())}}=>outcome,
                        };
                        if let Err(error)=outcome {eprintln!("{}",failure_event(source,service.tenant(),&error,Some(&work)));}
                        cursors.insert(source.clone(),work.cursor);
                        if cutoff.is_expired(rss_request_context::Clock::now(&Timer)){completed=false;break;}
                    }
                    if completed {cursors.insert(source.clone(),page.next.unwrap_or_default());}
                }
                tokio::select!{()=cancel.cancelled()=>return Ok(()),()=tokio::time::sleep(Duration::from_secs(5))=>()}
            }
        })
    }
}

fn failure_event(
    source: &str,
    tenant: rss_request_context::TenantId,
    error: &rss_mdm_software_service::publication::Error,
    work: Option<&rss_mdm_software_service::publication::PublicationWork>,
) -> serde_json::Value {
    use rss_mdm_software_service::publication::Error as E;
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
        E::CandidateNotFound => "candidate_not_found",
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
#[path = "../../tests/software_publication_worker.rs"]
mod tests;
