//! Sole host health aggregation. Component owners remain the status authorities.
use rss_mdm_flow_service::planning::automation::HealthFailure;
use rss_mdm_inventory_service::inventory_runtime::diagnostics::ProbeFailure;
use rss_mdm_management_http::runtime_diagnostics::*;
use std::{sync::Arc, time::Instant};

pub(crate) struct RuntimeDiagnostics {
    pub inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub identity_audit: Arc<crate::identity_audit::Readiness>,
    pub apple: Option<Arc<crate::apple::Apple>>,
    pub planning: Arc<rss_mdm_flow_service::planning::Planning>,
    pub execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub clock: Arc<dyn crate::clock::Clock>,
    pub tenant: rss_request_context::TenantId,
    pub instance: String,
}
impl Source for RuntimeDiagnostics {
    fn snapshot<'a>(
        &'a self,
        tenant: rss_request_context::TenantId,
        instance: &'a str,
        deadline: Instant,
    ) -> futures::future::BoxFuture<'a, Result<Snapshot, rss_mdm_management_http::Error>> {
        Box::pin(async move {
            if tenant != self.tenant || instance != self.instance {
                return Err(rss_mdm_management_http::Error(
                    rss_mdm_flow_service::Error::Forbidden,
                ));
            }
            Ok(self.collect(deadline, true).await)
        })
    }
}
impl RuntimeDiagnostics {
    pub(crate) async fn collect(&self, cutoff: Instant, detailed: bool) -> Snapshot {
        let mut inventory = self.inventory_health();
        let audit = self.audit_health();
        let apple = self.apple_health();
        let status = self.planning.automation_state();
        let mut automation = component(
            ComponentName::Automation,
            status == Some(rss_runtime::TaskState::Running),
        );
        automation.task = Some(task(status));
        if matches!(status, None | Some(rss_runtime::TaskState::Pending)) {
            automation.health = Health::Unknown;
        }
        if status != Some(rss_runtime::TaskState::Running) {
            automation.reasons.push(Reason::WorkerNotRunning);
        }
        let ingress = self.planning.ingress_health(cutoff).await;
        match ingress {
            Ok(state) => {
                if state.suspended {
                    automation.readiness = Readiness::NotReady;
                    automation.health = Health::Degraded;
                    automation.reasons.push(Reason::AutomationSuspended);
                }
                automation.dispatch = Some(Dispatch {
                    consumed: state.consumed,
                    watermark: state.watermark,
                });
                automation
                    .dependencies
                    .push(dependency(DependencyName::FlowStorage, None));
            }
            Err(failure) => {
                automation.readiness = Readiness::NotReady;
                automation.health = Health::Degraded;
                automation.reasons.push(flow_failure(failure));
                automation.dependencies.push(dependency(
                    DependencyName::FlowStorage,
                    Some(flow_failure(failure)),
                ));
            }
        }
        if detailed {
            self.enrich(cutoff, &mut inventory, &mut automation).await;
        }
        let execution = execution_component(self.execution.health());
        let components = vec![inventory, audit, apple, automation, execution];
        Snapshot {
            alive: true,
            ready: components
                .iter()
                .all(|c| c.readiness != Readiness::NotReady),
            components,
        }
    }
    async fn enrich(&self, cutoff: Instant, inventory: &mut Component, automation: &mut Component) {
        let (observations, queues) = tokio::join!(
            self.inventory.diagnostics(cutoff),
            self.planning.queue_health(cutoff)
        );
        inventory.dependencies.push(dependency(
            DependencyName::InventoryDelivery,
            observations
                .delivery
                .as_ref()
                .err()
                .map(|e| probe_failure(*e)),
        ));
        inventory.dependencies.push(dependency(
            DependencyName::ObservationJournal,
            observations
                .source_head
                .as_ref()
                .err()
                .map(|e| probe_failure(*e)),
        ));
        inventory.queues.push(queue(
            QueueName::DeliveryPending,
            observations.delivery.ok(),
        ));
        if inventory
            .dependencies
            .iter()
            .any(|d| matches!(d.state, DependencyState::Unavailable))
        {
            inventory.health = Health::Degraded;
        }
        inventory.progress = Some(projection(observations));
        if let Some(progress) = &inventory.progress {
            match progress.state {
                ProgressState::Failed => {
                    inventory.health = Health::Degraded;
                    inventory.reasons.push(Reason::ProjectionFailed);
                }
                ProgressState::Unavailable => {
                    inventory.health = Health::Degraded;
                    inventory.reasons.push(Reason::Unobserved);
                }
                ProgressState::Unobserved | ProgressState::Pending
                    if inventory.health == Health::Healthy =>
                {
                    inventory.health = Health::Unknown
                }
                _ => (),
            }
        }
        let values = queues.as_ref().ok();
        automation.queues = [
            QueueName::Pending,
            QueueName::Running,
            QueueName::Completed,
            QueueName::Failed,
            QueueName::Superseded,
            QueueName::AssetChangesPending,
        ]
        .into_iter()
        .enumerate()
        .map(|(i, name)| queue(name, values.map(|v| v[i])))
        .collect();
        if let Err(failure) = queues {
            automation.health = Health::Degraded;
            automation.dependencies.clear();
            automation.dependencies.push(dependency(
                DependencyName::FlowStorage,
                Some(flow_failure(failure)),
            ));
        }
        let health = self.planning.automation_health();
        automation.bridge = health.bridge.map(run_result);
        automation.runner = Some(Runner {
            scan: health.scan.map(run_result),
            unresolved_attempts: health.unresolved_attempts,
            truncated: health.truncated,
            latest_failure: health.latest_failure.map(|f| AttemptFailure {
                stage: match f.stage {
                    rss_reconcile::Stage::Observe => AttemptStage::Observe,
                    rss_reconcile::Stage::Apply => AttemptStage::Apply,
                    rss_reconcile::Stage::Renew => AttemptStage::Renew,
                    rss_reconcile::Stage::Finish => AttemptStage::Finish,
                },
                reason: automation_failure(f.failure),
                observed_at: f.observed_at,
            }),
        });
        if health.bridge.is_some_and(|r| r.failure.is_some())
            || health.scan.is_some_and(|r| r.failure.is_some())
            || health.unresolved_attempts > 0
        {
            automation.health = Health::Degraded;
        } else if (health.scan.is_none() || health.bridge.is_none())
            && automation.health == Health::Healthy
        {
            automation.health = Health::Unknown;
            automation.reasons.push(Reason::Unobserved);
        }
        if health.truncated {
            if automation.health != Health::Degraded {
                automation.health = Health::Unknown;
            }
            automation.reasons.push(Reason::ObservationLimit);
        }
    }
    fn inventory_health(&self) -> Component {
        let inventory_health = self.inventory.readiness.health();
        let mut inventory = component(ComponentName::Inventory, inventory_health.is_ready());
        inventory.task = Some(task(inventory_health.task));
        if !inventory_health.initialized
            && inventory_health.task == Some(rss_runtime::TaskState::Running)
        {
            inventory.health = Health::Unknown;
        }
        if matches!(
            inventory_health.task,
            None | Some(rss_runtime::TaskState::Pending)
        ) {
            inventory.health = Health::Unknown;
        }
        if !inventory_health.initialized
            && !matches!(
                inventory_health.task,
                Some(rss_runtime::TaskState::Stopped(_))
            )
        {
            inventory.reasons.push(Reason::Initializing);
        }
        if inventory_health.stopping {
            inventory.reasons.push(Reason::Stopping);
        }
        if inventory_health.task != Some(rss_runtime::TaskState::Running) {
            inventory.reasons.push(Reason::WorkerNotRunning);
        }
        inventory
    }
    fn audit_health(&self) -> Component {
        let audit_health = self.identity_audit.health();
        let mut audit = component(ComponentName::IdentityAudit, audit_health.is_ready());
        audit.task = Some(task(audit_health.task));
        if audit_health.task != Some(rss_runtime::TaskState::Running) {
            audit.reasons.push(Reason::WorkerNotRunning);
        }
        use crate::identity_audit::AuditPhase;
        match audit_health.phase {
            AuditPhase::Healthy => (),
            AuditPhase::Initializing => {
                audit.health = Health::Unknown;
                audit.reasons.push(Reason::Initializing);
            }
            AuditPhase::Retrying => audit.reasons.push(Reason::DeliveryRetrying),
            AuditPhase::DependencyUnavailable => audit.reasons.push(Reason::DependencyUnavailable),
            AuditPhase::Stopped => {
                if matches!(
                    audit_health.task,
                    Some(rss_runtime::TaskState::Stopped(
                        rss_runtime::TaskExit::Cancelled
                    ))
                ) {
                    audit.reasons.push(Reason::Stopping);
                }
            }
        }
        audit
    }
    fn apple_health(&self) -> Component {
        let Some(apple) = &self.apple else {
            let mut result = component(ComponentName::Apple, false);
            result.readiness = Readiness::NotApplicable;
            result.health = Health::NotApplicable;
            return result;
        };
        match self.clock.unix_seconds() {
            Ok(now) => {
                let state = apple.channel.health(now);
                let mut result = component(ComponentName::Apple, state.is_ready());
                if !state.push_available {
                    result.reasons.push(Reason::PushUnavailable);
                }
                if state.certificates_expired() {
                    result.reasons.push(Reason::CertificateExpired);
                }
                result
            }
            Err(_) => {
                let mut result = component(ComponentName::Apple, false);
                result.reasons.push(Reason::ClockUnavailable);
                result
            }
        }
    }
}
fn execution_component(state: rss_mdm_execution_service::health::Health) -> Component {
    use rss_mdm_execution_service::health::Phase;
    let mut result = component(ComponentName::ExecutionRecovery, state.is_ready());
    result.task = Some(task(state.task));
    if matches!(state.task, None | Some(rss_runtime::TaskState::Pending)) {
        result.health = Health::Unknown;
    }
    if state.task != Some(rss_runtime::TaskState::Running) {
        result.reasons.push(Reason::WorkerNotRunning);
    }
    if state.stopping {
        result.reasons.push(Reason::Stopping);
    }
    for phase in [state.recovery, state.relay] {
        match phase {
            Phase::Initializing => {
                if state.task == Some(rss_runtime::TaskState::Running)
                    && !state.stopping
                    && !matches!(state.recovery, Phase::Failed(_))
                    && !matches!(state.relay, Phase::Failed(_))
                {
                    result.health = Health::Unknown;
                }
                result.reasons.push(Reason::Initializing);
            }
            Phase::Failed(kind) => {
                result.health = Health::Degraded;
                result.reasons.push(execution_failure(kind));
            }
            Phase::Healthy => (),
        }
    }
    result
}
fn execution_failure(kind: rss_reconcile::ErrorKind) -> Reason {
    use rss_reconcile::ErrorKind;
    match kind {
        ErrorKind::Transient => Reason::DependencyUnavailable,
        ErrorKind::Deadline => Reason::Deadline,
        ErrorKind::CommitUnknown | ErrorKind::RollbackFailed => Reason::SettlementUnknown,
        ErrorKind::Fenced => Reason::OwnershipLost,
        ErrorKind::Cancelled => Reason::Stopping,
        ErrorKind::InvalidInput
        | ErrorKind::StorageContract
        | ErrorKind::Permanent
        | ErrorKind::Invariant => Reason::WorkRejected,
    }
}
fn component(name: ComponentName, ready: bool) -> Component {
    Component {
        name,
        readiness: if ready {
            Readiness::Ready
        } else {
            Readiness::NotReady
        },
        reasons: Vec::new(),
        health: if ready {
            Health::Healthy
        } else {
            Health::Degraded
        },
        task: None,
        dependencies: Vec::new(),
        queues: Vec::new(),
        progress: None,
        bridge: None,
        runner: None,
        dispatch: None,
    }
}
fn task(status: Option<rss_runtime::TaskState>) -> Task {
    use rss_runtime::{TaskExit, TaskState};
    match status {
        None => Task::Unknown,
        Some(TaskState::Pending) => Task::Pending,
        Some(TaskState::Running) => Task::Running,
        Some(TaskState::Stopped(TaskExit::Cancelled)) => Task::Cancelled,
        Some(TaskState::Stopped(TaskExit::Completed)) => Task::Completed,
        Some(TaskState::Stopped(TaskExit::Failed(_))) => Task::Failed,
    }
}
fn dependency(name: DependencyName, failure: Option<Reason>) -> Dependency {
    Dependency {
        name,
        state: if failure.is_some() {
            DependencyState::Unavailable
        } else {
            DependencyState::Available
        },
        reason: failure,
    }
}
fn queue(name: QueueName, count: Option<u64>) -> Queue {
    Queue {
        name,
        count: count.map(|n| n.min(1000)),
        truncated: count.map(|n| n > 1000),
    }
}
fn flow_failure(failure: HealthFailure) -> Reason {
    match failure {
        HealthFailure::Storage => Reason::DependencyUnavailable,
        HealthFailure::Deadline => Reason::Deadline,
        HealthFailure::SettlementUnknown => Reason::SettlementUnknown,
    }
}
fn probe_failure(failure: ProbeFailure) -> Reason {
    match failure {
        ProbeFailure::Storage => Reason::DependencyUnavailable,
        ProbeFailure::Deadline => Reason::Deadline,
        ProbeFailure::Authority => Reason::OwnershipLost,
    }
}
fn projection(
    value: rss_mdm_inventory_service::inventory_runtime::diagnostics::Diagnostics,
) -> Progress {
    use rss_projection::{ObservationStatus, Stop};
    let (state, position, applied) = match value.projection {
        None => (ProgressState::Unobserved, None, None),
        Some(ObservationStatus::Pending) => (ProgressState::Pending, None, None),
        Some(ObservationStatus::Running(p)) => (
            ProgressState::Running,
            p.position.map(|v| v.get()),
            Some(p.applied),
        ),
        Some(ObservationStatus::Stopped(p)) => (
            match p.stop {
                Stop::CaughtUp => ProgressState::CaughtUp,
                Stop::EventLimit => ProgressState::Limited,
                Stop::Failed(_) => ProgressState::Failed,
            },
            p.position.map(|v| v.get()),
            Some(p.applied),
        ),
        Some(ObservationStatus::Unavailable { last_confirmed }) => (
            ProgressState::Unavailable,
            last_confirmed.and_then(|p| p.position).map(|v| v.get()),
            last_confirmed.map(|p| p.applied),
        ),
    };
    let head = value.source_head.ok();
    let lagging = if matches!(state, ProgressState::Unobserved | ProgressState::Pending) {
        None
    } else {
        head.map(|h| h.is_some_and(|h| position.is_none_or(|p| h > p)))
    };
    Progress {
        state,
        confirmed_position: position,
        source_head: head.flatten(),
        lagging,
        invocation_age_ms: value.invocation_age_ms,
        completed_pass_age_ms: value.completed_age_ms,
        source_observation_age_ms: value.head_age_ms,
        applied,
    }
}

fn automation_failure(
    outcome: rss_mdm_flow_service::planning::automation::AutomationFailure,
) -> Reason {
    use rss_mdm_flow_service::planning::automation::AutomationFailure;
    match outcome {
        AutomationFailure::StorageUnavailable => Reason::DependencyUnavailable,
        AutomationFailure::Deadline => Reason::Deadline,
        AutomationFailure::SettlementUnknown => Reason::SettlementUnknown,
        AutomationFailure::OwnershipLost => Reason::OwnershipLost,
        AutomationFailure::Cancelled => Reason::Stopping,
        AutomationFailure::Rejected => Reason::WorkRejected,
    }
}
fn run_result(value: rss_mdm_flow_service::planning::automation::RunObservation) -> RunResult {
    RunResult {
        successful: value.failure.is_none(),
        reason: value.failure.map(automation_failure),
        observed_at: value.observed_at,
    }
}

#[cfg(test)]
#[path = "../tests/api/execution_health.rs"]
mod tests;
