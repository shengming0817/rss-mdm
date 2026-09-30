//! Read-only observations of the actual Inventory owner. No checkpoint or queue engine.
use super::*;
use rss_projection::{ObservationStatus, RunObservation, Source};

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
    pub run: RunObservation,
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
    pub source_head: Result<Option<u64>, ProbeFailure>,
    pub projection: Option<ObservationStatus>,
    pub invocation_age_ms: Option<u64>,
    pub completed_age_ms: Option<u64>,
    pub head_age_ms: Option<u64>,
}
impl InventoryRuntime {
    /// Called after host authorization of this exact tenant/instance. Each query grants a fresh read.
    pub async fn diagnostics(&self, cutoff: Instant) -> Diagnostics {
        let tenant = self.tenant.to_string();
        let (delivery, head) = tokio::join!(
            tokio::time::timeout_at(cutoff.into(), self.delivery.pending_count(&tenant)),
            self.source_head(cutoff),
        );
        let now = self.clock.now.now();
        let local = self
            .latest_projection
            .lock()
            .expect("projection observation")
            .clone();
        Diagnostics {
            delivery: delivery
                .map_err(|_| ProbeFailure::Deadline)
                .and_then(|value| value.map_err(|_| ProbeFailure::Storage)),
            source_head: head.as_ref().map(|(position, _)| *position).map_err(|e| *e),
            head_age_ms: head.ok().map(|(_, at)| age_ms(now, at)),
            projection: local.as_ref().map(|p| p.run.read()),
            invocation_age_ms: local.as_ref().map(|p| age_ms(now, p.started_at)),
            completed_age_ms: local
                .and_then(|p| p.last_completed_at)
                .map(|at| age_ms(now, at)),
        }
    }
    async fn source_head(&self, cutoff: Instant) -> Result<(Option<u64>, Instant), ProbeFailure> {
        let cancel = CancellationToken::new();
        let scope = rss_mdm_inventory_postgres::projection_scope(self.tenant);
        let source = PgSource::new(
            self.observation.clone(),
            JournalReadGrant::verify(
                &JournalAuthority {
                    tenant: self.tenant,
                    token: &cancel,
                },
                self.tenant,
            )
            .map_err(|_| ProbeFailure::Authority)?,
            scope.source().clone(),
        )
        .map_err(|_| ProbeFailure::Authority)?;
        let head = tokio::time::timeout_at(cutoff.into(), source.high_water(scope.source()))
            .await
            .map_err(|_| ProbeFailure::Deadline)?
            .map_err(|_| ProbeFailure::Storage)?;
        Ok((head.map(|position| position.get()), self.clock.now.now()))
    }
}
fn age_ms(now: Instant, at: Instant) -> u64 {
    u64::try_from(now.saturating_duration_since(at).as_millis()).unwrap_or(u64::MAX)
}
