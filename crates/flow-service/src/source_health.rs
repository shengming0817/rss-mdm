use super::*;
impl SourceChanges {
    /// Read the actual product ingress checkpoint; storage failure is not a paused ingress.
    pub async fn ingress_health(
        &self,
        cutoff: std::time::Instant,
    ) -> std::result::Result<IngressHealth, HealthFailure> {
        self.runtime
            .local_tx(self.tenant, health_deadline(cutoff), |tx| {
                Box::pin(async move {
                    rss_mdm_execution_service::source_changes::health_in(tx)
                        .await
                        .map(|(consumed, watermark, suspended)| IngressHealth {
                            consumed,
                            watermark,
                            suspended,
                        })
                        .map_err(|error| match error {
                            rss_mdm_execution_service::transaction::Fault::Storage(e) => e,
                            rss_mdm_execution_service::transaction::Fault::Sql(e) => e.into(),
                            _ => sqlx::Error::Protocol("Execution ingress health".into()).into(),
                        })
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(HealthFailure::Storage),
                |_| Err(HealthFailure::Storage),
                |_| Err(HealthFailure::SettlementUnknown),
                |_| Err(HealthFailure::SettlementUnknown),
                |_| Err(HealthFailure::Deadline),
            )
    }
    pub async fn pending_count(
        &self,
        cutoff: std::time::Instant,
    ) -> std::result::Result<u64, HealthFailure> {
        self.runtime.local_tx(self.tenant,health_deadline(cutoff),|tx|Box::pin(async move {
            let tenant=tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,i64>("SELECT count(*) FROM (SELECT 1 FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT forwarded LIMIT 1001) q").bind(tenant).fetch_one(c).await})).await
        })).await.fold(|n|Ok(n as u64),|_|Err(HealthFailure::Storage),|_|Err(HealthFailure::Storage),|_|Err(HealthFailure::SettlementUnknown),|_|Err(HealthFailure::SettlementUnknown),|_|Err(HealthFailure::Deadline))
    }
}

/// Current durable input checkpoint; an absent row means no ingress has been dispatched yet.
#[derive(Clone, Copy, Debug)]
pub struct IngressHealth {
    pub consumed: u64,
    pub watermark: u64,
    pub suspended: bool,
}
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum HealthFailure {
    #[error("storage unavailable")]
    Storage,
    #[error("deadline")]
    Deadline,
    #[error("settlement unknown")]
    SettlementUnknown,
}
#[derive(Clone, Copy, Debug)]
pub enum AutomationFailure {
    StorageUnavailable,
    Deadline,
    SettlementUnknown,
    OwnershipLost,
    Cancelled,
    Rejected,
}
#[derive(Clone, Copy, Debug)]
pub struct RunObservation {
    pub failure: Option<AutomationFailure>,
    pub observed_at: Option<i64>,
}
#[derive(Clone, Copy, Debug)]
pub struct AttemptFailure {
    pub stage: rss_reconcile::Stage,
    pub failure: AutomationFailure,
    pub observed_at: Option<i64>,
}
/// Owner-local facts; no task identity or input crosses the diagnostic boundary.
#[derive(Clone, Copy, Debug)]
pub struct AutomationHealth {
    pub bridge: Option<RunObservation>,
    pub scan: Option<RunObservation>,
    pub unresolved_attempts: u64,
    pub truncated: bool,
    pub latest_failure: Option<AttemptFailure>,
}
const FAILURE_LIMIT: usize = 1000;
#[derive(Default)]
pub(crate) struct AutomationObservation {
    bridge: Option<RunObservation>,
    scans: [Option<RunObservation>; 1],
    failures: std::collections::HashMap<rss_reconcile::Target, (u64, AttemptFailure)>,
    sequence: u64,
    // Discarded identities cannot subsequently be proven recovered. A restart
    // begins a new observation window; never invent recovery after truncation.
    truncated: bool,
}
impl AutomationObservation {
    fn scanned(&mut self, scope: &rss_reconcile::Scope, observation: RunObservation) {
        let index = match scope.reconciler() {
            "mdm.assets" => 0,
            _ => return,
        };
        self.scans[index] = Some(observation);
    }
    fn failed(&mut self, target: rss_reconcile::Target, failure: AttemptFailure) {
        self.sequence = self.sequence.saturating_add(1);
        if self.failures.contains_key(&target) || self.failures.len() < FAILURE_LIMIT {
            self.failures.insert(target, (self.sequence, failure));
        } else {
            self.truncated = true;
        }
    }
    fn settled(&mut self, target: &rss_reconcile::Target, completion: rss_reconcile::Completion) {
        if matches!(
            completion,
            rss_reconcile::Completion::Converged | rss_reconcile::Completion::Reobserve(_)
        ) {
            self.failures.remove(target);
        }
    }
    fn snapshot(&self) -> AutomationHealth {
        AutomationHealth {
            bridge: self.bridge,
            // A healthy scan can clear only its own scope. Prefer an unresolved
            // failure to a newer successful observation from the other runner.
            scan: self
                .scans
                .into_iter()
                .flatten()
                .max_by_key(|o| (o.failure.is_some(), o.observed_at)),
            unresolved_attempts: self.failures.len() as u64,
            truncated: self.truncated,
            latest_failure: self
                .failures
                .values()
                .max_by_key(|(seq, _)| seq)
                .map(|(_, f)| *f),
        }
    }
}
impl SourceChanges {
    pub fn automation_health(&self) -> AutomationHealth {
        self.automation_observation
            .lock()
            .expect("automation observation")
            .snapshot()
    }
    pub(crate) fn record_bridge(&self, failure: Option<AutomationFailure>) {
        let observed_at = self.clock.unix_seconds().ok();
        self.automation_observation
            .lock()
            .expect("automation observation")
            .bridge = Some(RunObservation {
            failure,
            observed_at,
        });
    }
    pub(crate) fn record_scan(
        &self,
        scope: &rss_reconcile::Scope,
        result: std::result::Result<(), &rss_reconcile::Error>,
    ) {
        let observed_at = self.clock.unix_seconds().ok();
        self.automation_observation
            .lock()
            .expect("automation observation")
            .scanned(
                scope,
                RunObservation {
                    failure: result.err().map(reconcile_failure),
                    observed_at,
                },
            );
    }
    pub(crate) fn record_runner_failure(&self, event: rss_reconcile::Observation) {
        match event {
            rss_reconcile::Observation::ScanFailed { scope, error } => {
                self.record_scan(&scope, Err(&error))
            }
            rss_reconcile::Observation::AttemptFailed {
                target,
                stage,
                error,
            } => {
                let failure = AttemptFailure {
                    stage,
                    failure: reconcile_failure(&error),
                    observed_at: self.clock.unix_seconds().ok(),
                };
                self.automation_observation
                    .lock()
                    .expect("automation observation")
                    .failed(target, failure);
            }
        }
    }
    pub(crate) fn record_settled(
        &self,
        target: &rss_reconcile::Target,
        completion: rss_reconcile::Completion,
    ) {
        self.automation_observation
            .lock()
            .expect("automation observation")
            .settled(target, completion);
    }
}
fn reconcile_failure(error: &rss_reconcile::Error) -> AutomationFailure {
    use rss_reconcile::ErrorKind;
    match error.kind() {
        ErrorKind::Transient | ErrorKind::StorageContract => AutomationFailure::StorageUnavailable,
        ErrorKind::Deadline => AutomationFailure::Deadline,
        ErrorKind::CommitUnknown | ErrorKind::RollbackFailed => {
            AutomationFailure::SettlementUnknown
        }
        ErrorKind::Fenced => AutomationFailure::OwnershipLost,
        ErrorKind::Cancelled => AutomationFailure::Cancelled,
        ErrorKind::InvalidInput | ErrorKind::Permanent | ErrorKind::Invariant => {
            AutomationFailure::Rejected
        }
    }
}
#[allow(clippy::disallowed_methods, reason = "monotonic read budget boundary")]
fn health_deadline(
    cutoff: std::time::Instant,
) -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        cutoff.saturating_duration_since(std::time::Instant::now()),
    )
}
