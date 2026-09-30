use super::*;
impl Planning {
    /// Read the actual product ingress checkpoint; storage failure is not a paused ingress.
    pub async fn ingress_health(
        &self,
        cutoff: std::time::Instant,
    ) -> std::result::Result<IngressHealth, HealthFailure> {
        self.runtime.local_tx(self.tenant, health_deadline(cutoff), |tx| Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move |c| Box::pin(async move {
                use sqlx::Row;
                let row = sqlx::query("SELECT consumed,watermark,failure FROM mdm_planning.asset_dispatch WHERE tenant_id=$1::uuid")
                    .bind(tenant).fetch_optional(c).await?;
                row.map_or(Ok(IngressHealth { consumed: 0, watermark: 0, suspended: false }), |r| {
                    Ok(IngressHealth { consumed: r.try_get::<i64,_>("consumed")? as u64,
                        watermark: r.try_get::<i64,_>("watermark")? as u64,
                        suspended: r.try_get::<Option<String>,_>("failure")?.is_some() })
                })
            })).await
        })).await.fold(Ok, |_| Err(HealthFailure::Storage), |_| Err(HealthFailure::Storage),
            |_| Err(HealthFailure::SettlementUnknown), |_| Err(HealthFailure::SettlementUnknown),
            |_| Err(HealthFailure::Deadline))
    }
    /// Counts describe retained product job states, not managed task health or device effects.
    pub async fn queue_health(
        &self,
        cutoff: std::time::Instant,
    ) -> std::result::Result<[u64; 6], HealthFailure> {
        self.runtime.local_tx(self.tenant, health_deadline(cutoff), |tx| Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move |c| Box::pin(async move {
                let row: (i64,i64,i64,i64,i64,i64) = sqlx::query_as(
                    "SELECT (SELECT count(*) FROM (SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND failure IS NULL AND NOT completed AND NOT forwarded LIMIT 1001) q),
                     (SELECT count(*) FROM (SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND failure IS NULL AND NOT completed AND forwarded LIMIT 1001) q),
                     (SELECT count(*) FROM (SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND failure IS NULL AND completed LIMIT 1001) q),
                     (SELECT count(*) FROM (SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND failure IS NOT NULL AND failure<>'superseded' LIMIT 1001) q),
                     (SELECT count(*) FROM (SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND failure='superseded' LIMIT 1001) q),
                     (SELECT count(*) FROM (SELECT 1 FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT forwarded LIMIT 1001) q)")
                    .bind(tenant).fetch_one(c).await?;
                Ok([row.0 as u64,row.1 as u64,row.2 as u64,row.3 as u64,row.4 as u64,row.5 as u64])
            })).await
        })).await.fold(Ok, |_| Err(HealthFailure::Storage), |_| Err(HealthFailure::Storage),
            |_| Err(HealthFailure::SettlementUnknown), |_| Err(HealthFailure::SettlementUnknown),
            |_| Err(HealthFailure::Deadline))
    }
    pub async fn clear_ingress_failure_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_planning.asset_dispatch SET failure=NULL WHERE tenant_id=$1::uuid AND failure IS NOT NULL").bind(tenant).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
    pub async fn fail_ingress_in(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        let tenant = self.tenant.to_string();
        let generation: Option<i64> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("INSERT INTO mdm_planning.asset_dispatch(tenant_id,failure,failure_generation) VALUES($1::uuid,'automation_suspended',1) ON CONFLICT(tenant_id) DO UPDATE SET failure=excluded.failure,failure_generation=asset_dispatch.failure_generation+1 WHERE asset_dispatch.failure IS NULL RETURNING failure_generation")
                .bind(tenant).fetch_optional(c).await
        })).await?;
        if let Some(generation) = generation {
            let audit = RequestAudit::new(self.tenant.to_string(), "automation_failed");
            audit.identify_service("service:asset-automation");
            audit.target("asset_ingress");
            let fact = rss_mdm_audit_integration::Fact::business(
                &audit,
                &format!("asset-ingress:{generation}:failed"),
                &generation.to_be_bytes(),
                200,
                "failed",
                None,
            )
            .map_err(Error::from)?;
            let result = self
                .audit_store
                .append_in(tx, &fact, false)
                .await
                .map_err(Error::from);
            audit.finalize(
                result
                    .as_ref()
                    .err()
                    .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
            );
            result?;
        }
        Ok(())
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
pub(in crate::planning) struct AutomationObservation {
    bridge: Option<RunObservation>,
    scan: Option<RunObservation>,
    failures: std::collections::HashMap<rss_reconcile::Target, (u64, AttemptFailure)>,
    sequence: u64,
    // Discarded identities cannot subsequently be proven recovered. A restart
    // begins a new observation window; never invent recovery after truncation.
    truncated: bool,
}
impl AutomationObservation {
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
            scan: self.scan,
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
impl Planning {
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
    pub(crate) fn record_scan(&self, result: std::result::Result<(), &rss_reconcile::Error>) {
        let observed_at = self.clock.unix_seconds().ok();
        self.automation_observation
            .lock()
            .expect("automation observation")
            .scan = Some(RunObservation {
            failure: result.err().map(reconcile_failure),
            observed_at,
        });
    }
    pub(crate) fn record_runner_failure(&self, event: rss_reconcile::Observation) {
        match event {
            rss_reconcile::Observation::ScanFailed { error, .. } => self.record_scan(Err(&error)),
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

#[cfg(test)]
mod tests {
    use super::*;
    fn target(entity: &str) -> rss_reconcile::Target {
        rss_reconcile::Target::new(
            rss_reconcile::Scope::new(
                TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
                "mdm.assets",
            )
            .unwrap(),
            entity,
        )
        .unwrap()
    }
    fn failure(stage: rss_reconcile::Stage) -> AttemptFailure {
        AttemptFailure {
            stage,
            failure: AutomationFailure::SettlementUnknown,
            observed_at: Some(9),
        }
    }
    #[test]
    fn recovery_is_per_target_and_requires_acknowledged_success() {
        use rss_reconcile::{Completion, Stage};
        let mut observations = AutomationObservation::default();
        let a = target("job:a");
        let b = target("job:b");
        observations.failed(a.clone(), failure(Stage::Apply));
        observations.failed(b.clone(), failure(Stage::Finish));
        observations.scan = Some(RunObservation {
            failure: None,
            observed_at: Some(10),
        });
        observations.bridge = observations.scan;
        observations.settled(&b, Completion::Converged);
        let snapshot = observations.snapshot();
        assert_eq!(snapshot.unresolved_attempts, 1);
        assert_eq!(snapshot.latest_failure.unwrap().stage, Stage::Apply);
        observations.settled(
            &a,
            Completion::Retry {
                after: Duration::from_secs(1),
                failures: 1,
            },
        );
        observations.settled(&a, Completion::Suspended { failures: 2 });
        assert_eq!(observations.snapshot().unresolved_attempts, 1);
        observations.settled(&a, Completion::Reobserve(Duration::from_secs(1)));
        assert_eq!(observations.snapshot().unresolved_attempts, 0);
    }
    #[test]
    fn all_runner_failure_stages_and_uncertain_settlement_remain_visible() {
        use rss_reconcile::{ErrorKind, Stage};
        let mut observations = AutomationObservation::default();
        for (i, stage) in [Stage::Observe, Stage::Apply, Stage::Renew, Stage::Finish]
            .into_iter()
            .enumerate()
        {
            observations.failed(target(&format!("job:{i}")), failure(stage));
            assert_eq!(observations.snapshot().latest_failure.unwrap().stage, stage);
        }
        assert_eq!(observations.snapshot().unresolved_attempts, 4);
        for kind in [ErrorKind::CommitUnknown, ErrorKind::RollbackFailed] {
            assert!(matches!(
                reconcile_failure(&rss_reconcile::Error::new(kind)),
                AutomationFailure::SettlementUnknown
            ));
        }
    }
    #[test]
    fn bounded_failure_retention_never_claims_unobserved_recovery() {
        let mut observations = AutomationObservation::default();
        for i in 0..=FAILURE_LIMIT {
            observations.failed(
                target(&format!("job:{i}")),
                failure(rss_reconcile::Stage::Finish),
            );
        }
        assert_eq!(observations.snapshot().unresolved_attempts, 1000);
        assert!(observations.snapshot().truncated);
        for i in 0..=FAILURE_LIMIT {
            observations.settled(
                &target(&format!("job:{i}")),
                rss_reconcile::Completion::Converged,
            );
        }
        assert_eq!(observations.snapshot().unresolved_attempts, 0);
        assert!(observations.snapshot().truncated);
    }
}
