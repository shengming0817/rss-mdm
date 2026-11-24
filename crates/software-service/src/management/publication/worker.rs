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
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Job {
    tenant: uuid::Uuid,
    epoch: i64,
    id: String,
    source: String,
    binding: [u8; 32],
    slot: String,
}
const IDLE: Duration = Duration::from_secs(5);
impl PublicationDirectory {
    async fn work_page(&self, after: Option<Job>) -> Result<Vec<Job>, sqlx::Error> {
        type Row = (
            uuid::Uuid,
            i64,
            String,
            String,
            sqlx::types::Json<[u8; 32]>,
            String,
        );
        let rows=sqlx::query_as::<_,Row>("SELECT tenant_id,expected_epoch,id,source,binding,slot FROM mdm_software_composition.work_scopes($1,$2,$3)")
            .bind(after.as_ref().map(|v|v.tenant)).bind(after.as_ref().map(|v|v.epoch)).bind(after.as_ref().map(|v|&v.id))
            .fetch_all(&self.discovery_pool).await?;
        Ok(rows
            .into_iter()
            .map(|(tenant, epoch, id, source, binding, slot)| Job {
                tenant,
                epoch,
                id,
                source,
                binding: binding.0,
                slot,
            })
            .collect())
    }
    pub fn registration(
        self: Arc<Self>,
        limits: rss_mdm_work_page::external::Limits,
    ) -> rss_runtime::ManagedTaskRegistration {
        let (task, _) =
            rss_runtime::ManagedTask::prepare("mdm-software-publication", Duration::from_secs(8));
        task.into_registration(move |stop| async move {
            use rss_mdm_work_page::Failure;
            rss_mdm_work_page::run_limited(
                limits.total,
                IDLE,
                &stop,
                &tokio::sync::Notify::new(),
                (
                    |job: &Job| {
                        limits.work(
                            job.tenant,
                            job.source.clone(),
                            (job.tenant, job.binding, job.slot.clone()),
                        )
                    },
                    |after| {
                        let future = self.work_page(after);
                        async move { future.await.map_err(|_| Failure::Retry) }
                    },
                ),
                |job, admission| {
                    let directory = self.clone();
                    async move {
                        let fatal = |e| Failure::Fatal(rss_runtime::ShutdownError::new(e));
                        let Some(service) = directory.services.get(&job.source) else {
                            return Ok(IDLE);
                        };
                        let tenant = rss_request_context::TenantId::parse(&job.tenant.to_string())
                            .map_err(rss_runtime::ShutdownError::new)
                            .map_err(Failure::Fatal)?;
                        let epoch = rss_transactional_messaging::fence::Epoch::new(job.epoch)
                            .map_err(rss_runtime::ShutdownError::new)
                            .map_err(Failure::Fatal)?;
                        let execution = rss_transactional_messaging::fence::ExecutionBinding::new(
                            directory.storage,
                            tenant,
                            epoch,
                        );

                        let operation = service.operation(execution).map_err(|e| {
                            eprintln!("{}", failure_event(&job.source, tenant, &e, None));
                            Failure::Retry
                        })?;
                        let cutoff = Deadline::from_timeout(&Timer, Duration::from_secs(6))
                            .map_err(rss_runtime::ShutdownError::new)
                            .map_err(Failure::Fatal)?;
                        let work = operation
                            .reconciliation_work(&job.id, job.binding, &job.slot, cutoff)
                            .await
                            .map_err(|e| {
                                eprintln!("{}", failure_event(&job.source, tenant, &e, None));
                                Failure::Retry
                            })?;
                        let Some(work) = work else { return Ok(IDLE) };
                        if admission.is_cancelled() {
                            return Ok(IDLE);
                        }
                        let now = directory.clock.unix_seconds().ok_or_else(|| {
                            fatal(crate::management::Error::Unavailable(
                                crate::management::Failure::Clock,
                            ))
                        })?;
                        let at = Timepoint::try_from(now)
                            .map_err(rss_runtime::ShutdownError::new)
                            .map_err(Failure::Fatal)?;
                        let result = if work.withdrawal {
                            operation
                                .reconcile_withdrawal(work.publication, work.attempt, cutoff)
                                .await
                                .map(|_| ())
                        } else {
                            operation
                                .reconcile(work.publication, work.attempt, at, cutoff)
                                .await
                                .map(|_| ())
                        };
                        result.map_err(|e| {
                            eprintln!("{}", failure_event(&job.source, tenant, &e, Some(&work)));
                            Failure::Retry
                        })?;
                        Ok(IDLE)
                    }
                },
                |_| {},
            )
            .await
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
