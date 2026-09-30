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
        let status = self
            .planning
            .automation_task
            .get()
            .map(rss_runtime::TaskStatus::current);
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
        let mut execution = component(ComponentName::ExecutionRecovery, false);
        execution.readiness = Readiness::NotApplicable;
        execution.health = Health::Unknown;
        execution.task = Some(Task::Unknown);
        execution.reasons.push(Reason::Unobserved);
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
        automation.last_run = self
            .planning
            .bridge_observation
            .lock()
            .expect("bridge observation")
            .map(|o| LastRun {
                successful: matches!(
                    o.outcome,
                    rss_mdm_flow_service::planning::automation::BridgeOutcome::Succeeded
                ),
                reason: bridge_failure(o.outcome),
                observed_at: o.observed_at,
            });
        if automation.last_run.as_ref().is_some_and(|r| !r.successful) {
            automation.health = Health::Degraded;
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
        last_run: None,
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

fn bridge_failure(
    outcome: rss_mdm_flow_service::planning::automation::BridgeOutcome,
) -> Option<Reason> {
    use rss_mdm_flow_service::planning::automation::BridgeOutcome;
    match outcome {
        BridgeOutcome::Succeeded => None,
        BridgeOutcome::StorageUnavailable => Some(Reason::DependencyUnavailable),
        BridgeOutcome::Deadline => Some(Reason::Deadline),
        BridgeOutcome::SettlementUnknown => Some(Reason::SettlementUnknown),
        BridgeOutcome::Rejected => Some(Reason::WorkRejected),
    }
}
