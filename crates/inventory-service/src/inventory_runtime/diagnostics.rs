//! Read-only observations of the actual Inventory owner. No checkpoint or queue engine.
use super::*;
use rss_projection::{ObservationStatus, RunObservation};

#[derive(Clone, Copy, Debug)]
pub struct Health {
    pub initialized: bool,
    pub stopping: bool,
    pub task: Option<rss_runtime::TaskState>,
}
impl Health {
    pub fn is_ready(self) -> bool {
        self.initialized && !self.stopping && self.task == Some(rss_runtime::TaskState::Running)
    }
}
#[derive(Clone)]
pub(super) struct ProjectionObservation {
    // None records a refused empty start below the retained journal floor.
    pub run: Option<RunObservation>,
    pub started_at: Instant,
    pub last_completed_at: Option<Instant>,
}
#[derive(Clone, Copy, Debug)]
pub enum ProbeFailure {
    Storage,
    Deadline,
    Authority,
}
pub struct Diagnostics {
    pub delivery: Result<u64, ProbeFailure>,
    pub journal: Result<rss_observation_postgres::JournalBounds, ProbeFailure>,
    pub projection: Option<ObservationStatus>,
    pub baseline_required: bool,
    pub invocation_age_ms: Option<u64>,
    pub completed_age_ms: Option<u64>,
    pub head_age_ms: Option<u64>,
}
impl InventoryRuntime {
    /// Called after host authorization of this exact tenant/instance. Each query grants a fresh read.
    pub async fn diagnostics(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        cutoff: Instant,
    ) -> Diagnostics {
        let tenant = binding.tenant().to_string();
        let (delivery, head) = tokio::join!(
            tokio::time::timeout_at(cutoff.into(), self.delivery.pending_count(&tenant)),
            self.journal_bounds(binding, cutoff),
        );
        let now = self.clock.now.now();
        let local = self
            .latest_projection
            .lock()
            .expect("projection observation")
            .get(&binding.tenant())
            .cloned();
        Diagnostics {
            delivery: delivery
                .map_err(|_| ProbeFailure::Deadline)
                .and_then(|value| value.map_err(|_| ProbeFailure::Storage)),
            journal: head.map(|(bounds, _)| bounds),
            head_age_ms: head.ok().map(|(_, at)| age_ms(now, at)),
            projection: local
                .as_ref()
                .and_then(|p| p.run.as_ref())
                .map(RunObservation::read),
            baseline_required: local.as_ref().is_some_and(|p| p.run.is_none()),
            invocation_age_ms: local.as_ref().map(|p| age_ms(now, p.started_at)),
            completed_age_ms: local
                .and_then(|p| p.last_completed_at)
                .map(|at| age_ms(now, at)),
        }
    }
    async fn journal_bounds(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        cutoff: Instant,
    ) -> Result<(rss_observation_postgres::JournalBounds, Instant), ProbeFailure> {
        let cancel = CancellationToken::new();
        let scope = rss_mdm_inventory_postgres::projection_scope(binding.tenant());
        let source = PgSource::new(
            self.observation.clone(),
            JournalReadGrant::verify(
                &JournalAuthority {
                    tenant: binding.tenant(),
                    token: &cancel,
                },
                binding.tenant(),
            )
            .map_err(|_| ProbeFailure::Authority)?,
            scope.source().clone(),
            self.clock.policy.page_bytes,
        )
        .map_err(|_| ProbeFailure::Authority)?;
        let control = rss_projection::Control::new(
            &self.clock,
            cutoff.saturating_duration_since(self.clock.origin),
            &cancel,
        );
        let head = tokio::time::timeout_at(cutoff.into(), source.bounds(&control))
            .await
            .map_err(|_| ProbeFailure::Deadline)?
            .map_err(|_| ProbeFailure::Storage)?;
        Ok((head, self.clock.now.now()))
    }
}
fn age_ms(now: Instant, at: Instant) -> u64 {
    u64::try_from(now.saturating_duration_since(at).as_millis()).unwrap_or(u64::MAX)
}
