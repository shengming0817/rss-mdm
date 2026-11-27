use super::*;
impl Application {
    /// A missing configuration participant has no suspended native input checkpoint.
    pub async fn configuration_input_suspended(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        cutoff: std::time::Instant,
    ) -> std::result::Result<bool, HealthFailure> {
        configuration_input_suspended(
            &self.runtime,
            binding,
            self.configuration.as_deref(),
            cutoff,
        )
        .await
    }
    /// Counts describe retained product job states, not managed task health or device effects.
    pub async fn queue_health(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        cutoff: std::time::Instant,
    ) -> std::result::Result<[u64; 5], HealthFailure> {
        queue_health(
            self.profile(),
            &self.runtime,
            binding,
            self.configuration.as_deref(),
            cutoff,
        )
        .await
    }
}
/// Read native input suspension only when the actual configuration participant exists.
pub async fn configuration_input_suspended(
    runtime: &std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    configuration: Option<&crate::configuration::Transactions>,
    cutoff: std::time::Instant,
) -> std::result::Result<bool, HealthFailure> {
    if configuration.is_none() {
        return Ok(false);
    }
    runtime
            .local_tx(binding, health_deadline(cutoff), |tx| {
                Box::pin(async move {
                    let tenant = tx.tenant_id().to_string();
                    tx.with_connection(move |c| Box::pin(async move {
                        sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_planning.configuration_source_dispatch WHERE tenant_id=$1::uuid AND failure IS NOT NULL)")
                            .bind(tenant).fetch_one(c).await
                    })).await
                })
            }).await.fold(
                Ok,
                |_| Err(HealthFailure::Storage),
                |_| Err(HealthFailure::Storage),
                |_| Err(HealthFailure::SettlementUnknown),
                |_| Err(HealthFailure::SettlementUnknown),
                |_| Err(HealthFailure::Deadline),
            )
}
/// Read common product queue counts, adding native counts only for a configured participant.
pub async fn queue_health(
    profile: rss_mdm_install_support::StorageProfile,
    runtime: &std::sync::Arc<rss_transactional_messaging_postgres::PgRuntime>,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    configuration: Option<&crate::configuration::Transactions>,
    cutoff: std::time::Instant,
) -> std::result::Result<[u64; 5], HealthFailure> {
    let configured = configuration.is_some();
    runtime
            .local_tx(binding, health_deadline(cutoff), |tx| {
                Box::pin(async move {
                    let mut counts=rss_mdm_policy_postgres::work::counts_in(profile, tx).await?;
                    if !configured { return Ok(counts); }
                    let tenant=tx.tenant_id().to_string();
                    let (pending,failed):(i64,bool)=tx.with_connection(move|c|Box::pin(async move{
                        sqlx::query_as("SELECT (SELECT count(*) FROM(SELECT FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND input_revision>observed_revision LIMIT 1001) p),EXISTS(SELECT FROM mdm_planning.configuration_source_dispatch WHERE tenant_id=$1::uuid AND failure IS NOT NULL)").bind(tenant).fetch_one(c).await
                    })).await?;
                    counts[0]=counts[0].saturating_add(pending as u64);counts[3]=counts[3].saturating_add(u64::from(failed));Ok(counts)
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
    pub blocks_readiness: bool,
    pub discovery: Option<RunObservation>,
    pub recovery: rss_mdm_recovery_observation::Phase,
    pub scan: Option<RunObservation>,
    pub unresolved_attempts: u64,
    pub truncated: bool,
    pub latest_failure: Option<AttemptFailure>,
}
impl Application {
    pub fn automation_health(&self) -> AutomationHealth {
        let snapshot = self
            .automation_observation
            .lock()
            .expect("automation observation")
            .snapshot();
        let scan = |value: rss_mdm_recovery_observation::Scan| RunObservation {
            failure: value.failure.map(reconcile_kind),
            observed_at: value.observed_at,
        };
        AutomationHealth {
            blocks_readiness: snapshot.blocks_readiness,
            discovery: snapshot.discovery.map(scan),
            recovery: snapshot.recovery,
            scan: snapshot.scan.map(scan),
            unresolved_attempts: snapshot.unresolved_attempts,
            truncated: snapshot.truncated,
            latest_failure: snapshot.latest_failure.map(|failure| AttemptFailure {
                stage: failure.stage,
                failure: reconcile_kind(failure.failure),
                observed_at: failure.observed_at,
            }),
        }
    }
    pub(crate) fn record_discovery(
        &self,
        domain: &str,
        outcome: std::result::Result<(), rss_reconcile::ErrorKind>,
    ) {
        self.automation_observation
            .lock()
            .expect("automation observation")
            .discovery(domain, outcome, self.clock.unix_seconds().ok());
    }
    pub(crate) fn record_scan(
        &self,
        scope: &rss_reconcile::Scope,
        result: std::result::Result<(), &rss_reconcile::Error>,
    ) {
        self.automation_observation
            .lock()
            .expect("automation observation")
            .scan(
                scope,
                result.map_err(|error| error.kind()),
                self.clock.unix_seconds().ok(),
            );
    }

    pub(crate) fn record_runner_failure(&self, event: rss_reconcile::Observation) {
        self.automation_observation
            .lock()
            .expect("automation observation")
            .observe(&event, self.clock.unix_seconds().ok());
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
fn reconcile_kind(kind: rss_reconcile::ErrorKind) -> AutomationFailure {
    use rss_reconcile::ErrorKind;
    match kind {
        ErrorKind::Transient | ErrorKind::StorageContract => AutomationFailure::StorageUnavailable,
        ErrorKind::Deadline => AutomationFailure::Deadline,
        ErrorKind::CommitUnknown | ErrorKind::RollbackFailed => {
            AutomationFailure::SettlementUnknown
        }
        ErrorKind::Fenced | ErrorKind::BindingChanged => AutomationFailure::OwnershipLost,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uncertain_settlement_keeps_the_product_failure_category() {
        for kind in [
            rss_reconcile::ErrorKind::CommitUnknown,
            rss_reconcile::ErrorKind::RollbackFailed,
        ] {
            assert!(matches!(
                reconcile_kind(kind),
                AutomationFailure::SettlementUnknown
            ));
        }
    }
}
