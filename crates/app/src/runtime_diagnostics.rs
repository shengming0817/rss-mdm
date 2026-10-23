//! Sole host health aggregation. Component owners remain the status authorities.
use rss_mdm_flow_service::planning::automation::HealthFailure;
use rss_mdm_inventory_service::inventory_runtime::diagnostics::ProbeFailure;
use rss_mdm_management_http::runtime_diagnostics::*;
use std::{sync::Arc, time::Instant};

pub(crate) struct RuntimeDiagnostics {
    pub channels: Arc<crate::channel_status::Channels>,
    pub registration: Arc<dyn rss_mdm_management_http::enrollment::channels::Source>,
    pub pki: Arc<rss_mdm_pki_service::registry::Registry>,
    pub apple_store: Arc<rss_mdm_apple_channel::Store>,
    pub access: sqlx::PgPool,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
    pub inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub identity_audit: Arc<crate::audit_health::Readiness>,
    pub mdm_audit: Arc<crate::audit_health::Readiness>,
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
                return Err(rss_mdm_management_http::Error::Forbidden);
            }
            Ok(self.collect(deadline, true).await)
        })
    }
}
impl RuntimeDiagnostics {
    pub(crate) async fn collect(&self, cutoff: Instant, detailed: bool) -> Snapshot {
        let mut inventory = self.inventory_health();
        let audit = self.audit_health(ComponentName::IdentityAudit, &self.identity_audit);
        let mdm_audit = self.audit_health(ComponentName::AuditProjection, &self.mdm_audit);
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
        let source = self.source_health(cutoff).await;
        let mut components = vec![inventory, source, audit, mdm_audit, automation, execution];
        if let Some(telemetry) = self.telemetry_component(cutoff, detailed).await {
            components.push(telemetry);
        }
        if let Some(initialization) = self.initialization_component(cutoff).await {
            components.push(initialization);
        }
        Snapshot {
            channels: self.channel_health(cutoff).await,
            alive: true,
            ready: components
                .iter()
                .all(|c| c.readiness != Readiness::NotReady),
            components,
        }
    }
    async fn telemetry_component(&self, cutoff: Instant, detailed: bool) -> Option<Component> {
        let service = self.telemetry.as_ref()?;
        let mut telemetry = component(ComponentName::Telemetry, false);
        match service.diagnostics(cutoff).await {
            Ok(state) => {
                telemetry = component(ComponentName::Telemetry, state.running);
                if !state.running {
                    telemetry.reasons.push(Reason::WorkerNotRunning);
                }
                if state.unknown > 0 || state.blocked > 0 {
                    telemetry.health = Health::Degraded;
                    telemetry.reasons.push(Reason::DeliveryRetrying);
                }
                telemetry
                    .dependencies
                    .push(dependency(DependencyName::TelemetryStorage, None));
                if detailed {
                    telemetry.queues = [
                        (QueueName::DeliveryPending, state.pending),
                        (QueueName::DeliveryUnknown, state.unknown),
                        (QueueName::DeliveryBlocked, state.blocked),
                        (QueueName::MaintenancePending, state.maintenance),
                    ]
                    .into_iter()
                    .map(|(name, count)| Queue {
                        name,
                        count: Some(count.min(4096)),
                        truncated: Some(count > 4096),
                    })
                    .collect();
                }
            }
            Err(_) => {
                telemetry.health = Health::Degraded;
                telemetry.dependencies.push(dependency(
                    DependencyName::TelemetryStorage,
                    Some(Reason::DependencyUnavailable),
                ));
            }
        }
        Some(telemetry)
    }
    async fn initialization_component(&self, cutoff: Instant) -> Option<Component> {
        match tokio::time::timeout_at(
            cutoff.into(),
            crate::baseline::status(&self.access, &self.tenant.to_string()),
        )
        .await
        {
            Ok(Ok(Some((phase, blocked, assets, telemetry)))) => {
                let mut initialization =
                    component(ComponentName::Initialization, phase == "configured");
                initialization.queues = vec![
                    Queue {
                        name: QueueName::InitializationAssetsPending,
                        count: Some(assets),
                        truncated: Some(false),
                    },
                    Queue {
                        name: QueueName::InitializationTelemetryPending,
                        count: Some(telemetry),
                        truncated: Some(false),
                    },
                ];
                if phase != "configured" {
                    initialization.health = Health::Degraded;
                    initialization.reasons.push(match blocked.as_deref() {
                        Some("authorization") => Reason::InitializationAuthorization,
                        Some("content") => Reason::InitializationContent,
                        Some("conflict") => Reason::InitializationConflict,
                        Some("telemetry_backend") => Reason::InitializationTelemetryBackend,
                        Some("outcome_unknown") => Reason::SettlementUnknown,
                        Some(_) => Reason::DependencyUnavailable,
                        None => Reason::Initializing,
                    });
                }
                Some(initialization)
            }
            Ok(Ok(None)) => None,
            _ => {
                let mut initialization = component(ComponentName::Initialization, false);
                initialization.health = Health::Unknown;
                initialization.reasons.push(Reason::DependencyUnavailable);
                Some(initialization)
            }
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
    async fn source_health(&self, cutoff: Instant) -> Component {
        let mut component = component(ComponentName::AuditSource, false);
        let remaining = cutoff
            .saturating_duration_since(rss_request_context::Clock::now(
                &crate::lifecycle::RuntimeTimer,
            ))
            .min(std::time::Duration::from_secs(1));
        match self
            .audit_store
            .backlog(
                self.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(remaining),
            )
            .await
        {
            Ok(backlog) => {
                if backlog.reserve_exhausted {
                    component.reasons.push(Reason::AuditReserveExhausted);
                } else if backlog.admission_closed {
                    component.reasons.push(Reason::AuditBackpressure);
                } else {
                    component.readiness = Readiness::Ready;
                }
                if backlog.warning {
                    component.reasons.push(Reason::AuditBacklogWarning);
                }
                component.health = if component.reasons.is_empty() {
                    Health::Healthy
                } else {
                    Health::Degraded
                };
                component.audit_backlog = Some(backlog);
            }
            Err(_) => {
                component.reasons.push(Reason::DependencyUnavailable);
            }
        }
        component
    }
    fn audit_health(
        &self,
        name: ComponentName,
        health: &crate::audit_health::Readiness,
    ) -> Component {
        let audit_health = health.health();
        let mut audit = component(name, audit_health.is_ready());
        // Projection lag does not revoke reliable local source admission. Fatal faults stop the managed host.
        audit.readiness = Readiness::NotApplicable;
        audit.task = Some(task(audit_health.task));
        if audit_health.task != Some(rss_runtime::TaskState::Running) {
            audit.reasons.push(Reason::WorkerNotRunning);
        }
        use crate::audit_health::AuditPhase;
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
    fn observe_trust(&self, channel: &mut ChannelStatus) -> Option<Reason> {
        use rss_mdm_agent_wire::pki::Purpose;
        let purpose = match channel.name {
            ChannelName::Apple => Purpose::Apple,
            ChannelName::Windows => Purpose::Windows,
            ChannelName::Agent => Purpose::Agent,
            ChannelName::AgentBootstrap => Purpose::AgentBootstrap,
            ChannelName::Signing | ChannelName::WindowsPush => return None,
        };
        // Registry rotation updates this running verifier. Report that loaded fact, not desired files.
        let revision = self
            .pki
            .trust(purpose)
            .ok()
            .and_then(|trust| i64::try_from(trust.revision).ok());
        match revision {
            Some(revision) => {
                channel.loaded_materials.insert("trust".into(), revision);
                None
            }
            None => {
                channel.loaded_materials.remove("trust");
                Some(Reason::MaterialInvalid)
            }
        }
    }
    async fn channel_health(&self, cutoff: Instant) -> Vec<ChannelStatus> {
        let mut channels: Vec<_> = self
            .channels
            .snapshot()
            .into_iter()
            .map(channel_projection)
            .collect();
        project_dependents(&mut channels);
        for channel in &mut channels {
            if channel.state != ChannelState::Ready {
                continue;
            }
            if let Some(reason) = self.observe_trust(channel) {
                channel.state = ChannelState::Degraded;
                channel.reasons = vec![reason];
                continue;
            }
            let failure = match self.clock.unix_seconds() {
                Ok(now) => match channel.name {
                    ChannelName::Apple => self.apple_failure(now, cutoff).await,
                    ChannelName::Signing | ChannelName::WindowsPush => {
                        self.selected_material_failure(channel, cutoff).await
                    }
                    ChannelName::Windows | ChannelName::Agent => {
                        use rss_mdm_management_http::enrollment::channels::Availability;
                        use rss_mdm_registration_service::quotas::Channel;
                        let name = if channel.name == ChannelName::Windows {
                            Channel::WindowsMdm
                        } else {
                            Channel::Agent
                        };
                        (!matches!(
                            self.registration.status(name).availability,
                            Availability::Ready
                        ))
                        .then_some(Reason::MaterialInvalid)
                    }
                    ChannelName::AgentBootstrap => {
                        let purpose = rss_mdm_agent_wire::pki::Purpose::AgentBootstrap;
                        self.pki
                            .trust(purpose)
                            .ok()
                            .and_then(|trust| {
                                rss_mdm_device_trust::DeviceTrust::new(trust, purpose, now).ok()
                            })
                            .is_none()
                            .then_some(Reason::MaterialInvalid)
                    }
                },
                Err(_) => Some(Reason::ClockUnavailable),
            };
            if let Some(reason) = failure {
                channel.state = ChannelState::Degraded;
                channel.reasons = vec![reason];
            }
        }
        project_dependents(&mut channels);
        channels
    }
    async fn apple_failure(&self, now: i64, cutoff: Instant) -> Option<Reason> {
        let apple = self.apple.as_ref()?;
        let health = apple.channel.health(now);
        if health.certificates_expired() {
            return Some(Reason::CertificateExpired);
        }
        if !health.push_available {
            return Some(Reason::PushUnavailable);
        }
        match tokio::time::timeout_at(
            cutoff.into(),
            apple
                .channel
                .check_materials(&self.apple_store, &self.tenant.to_string(), now),
        )
        .await
        {
            Ok(Ok(())) => None,
            Ok(Err(rss_mdm_apple_channel::Error::Conflict)) => Some(Reason::MaterialInvalid),
            _ => Some(Reason::DependencyUnavailable),
        }
    }
    async fn selected_material_failure(
        &self,
        channel: &ChannelStatus,
        cutoff: Instant,
    ) -> Option<Reason> {
        let key = match channel.name {
            ChannelName::WindowsPush => "wns",
            ChannelName::Signing => "signing",
            _ => return None,
        };
        let Some(revision) = channel.loaded_materials.get(key) else {
            return Some(Reason::MaterialNotSelected);
        };
        let check = async {
            let mut tx = self.access.begin().await.map_err(|_| ())?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true)").bind(self.tenant.to_string()).execute(&mut *tx).await.map_err(|_| ())?;
            let valid = match channel.name {
                ChannelName::WindowsPush => rss_mdm_windows_channel::wns_materials::is_selected(
                    &mut tx,
                    &self.tenant.to_string(),
                    *revision,
                )
                .await
                .map_err(|_| ()),
                ChannelName::Signing => {
                    match rss_mdm_execution_service::task_signing::trust::check_revision(
                        &mut tx,
                        self.tenant,
                        *revision as u64,
                    )
                    .await
                    {
                        Ok(()) => Ok(true),
                        Err(rss_mdm_execution_service::Error::Conflict) => Ok(false),
                        Err(_) => Err(()),
                    }
                }
                _ => Err(()),
            };
            tx.rollback().await.map_err(|_| ())?;
            valid
        };
        match tokio::time::timeout_at(cutoff.into(), check).await {
            Ok(Ok(true)) => None,
            Ok(Ok(false)) => Some(Reason::MaterialRevoked),
            _ => Some(Reason::DependencyUnavailable),
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
        audit_backlog: None,
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

/// A prepared material is not an available capability when its transport owner is closed.
pub(crate) fn project_dependents(values: &mut [ChannelStatus]) {
    for (child, parent) in [
        (ChannelName::WindowsPush, ChannelName::Windows),
        (ChannelName::AgentBootstrap, ChannelName::Agent),
    ] {
        let failed = values
            .iter()
            .find(|v| v.name == parent)
            .filter(|v| v.state != ChannelState::Ready || !v.mounted)
            .map(|v| v.reasons.clone());
        if let Some(reasons) = failed
            && let Some(value) = values
                .iter_mut()
                .find(|v| v.name == child && v.state == ChannelState::Ready)
        {
            value.state = ChannelState::Degraded;
            value.reasons = if reasons.is_empty() {
                vec![Reason::IngressUnavailable]
            } else {
                reasons
            };
        }
    }
}

fn channel_projection(value: crate::channel_status::Assembly) -> ChannelStatus {
    use crate::channel_status as assembly;
    let name = match value.name {
        assembly::ChannelName::Apple => ChannelName::Apple,
        assembly::ChannelName::Windows => ChannelName::Windows,
        assembly::ChannelName::Agent => ChannelName::Agent,
        assembly::ChannelName::WindowsPush => ChannelName::WindowsPush,
        assembly::ChannelName::AgentBootstrap => ChannelName::AgentBootstrap,
        assembly::ChannelName::Signing => ChannelName::Signing,
    };
    let state = match value.state {
        assembly::ChannelState::Disabled => ChannelState::Disabled,
        assembly::ChannelState::Waiting => ChannelState::Waiting,
        assembly::ChannelState::Ready => ChannelState::Ready,
        assembly::ChannelState::Degraded => ChannelState::Degraded,
    };
    let reasons = value
        .reason
        .map(|reason| match reason {
            assembly::Reason::MaterialNotSelected => Reason::MaterialNotSelected,
            assembly::Reason::MaterialUnreadable => Reason::MaterialUnreadable,
            assembly::Reason::MaterialInvalid => Reason::MaterialInvalid,
            assembly::Reason::TrustConflict => Reason::TrustConflict,
            assembly::Reason::MaterialRevoked => Reason::MaterialRevoked,
            assembly::Reason::MaterialVersionMismatch => Reason::MaterialVersionMismatch,
            assembly::Reason::CertificateExpired => Reason::CertificateExpired,
            assembly::Reason::DependencyUnavailable => Reason::DependencyUnavailable,
        })
        .into_iter()
        .collect();
    let materials = value.materials;
    let loaded_materials = [
        ("trust", materials.trust),
        ("apns", materials.apns),
        ("profile", materials.profile),
        ("wns", materials.wns),
        ("signing", materials.signing),
    ]
    .into_iter()
    .filter_map(|(name, revision)| revision.map(|v| (name.to_owned(), v)))
    .collect();
    ChannelStatus {
        name,
        state,
        reasons,
        mounted: value.mounted,
        loaded_materials,
    }
}

#[cfg(test)]
mod channel_projection_tests {
    use super::*;
    #[test]
    fn closed_parent_prevents_ready_bootstrap_and_preserves_loaded_material_identity() {
        use crate::channel_status as assembly;
        let facts = [
            assembly::Assembly {
                name: assembly::ChannelName::Agent,
                state: assembly::ChannelState::Degraded,
                reason: Some(assembly::Reason::DependencyUnavailable),
                mounted: false,
                materials: Default::default(),
            },
            assembly::Assembly {
                name: assembly::ChannelName::AgentBootstrap,
                state: assembly::ChannelState::Ready,
                reason: None,
                mounted: false,
                materials: assembly::LoadedMaterials {
                    trust: Some(4),
                    ..Default::default()
                },
            },
        ];
        let mut values: Vec<_> = facts.iter().cloned().map(channel_projection).collect();
        project_dependents(&mut values);
        assert_eq!(values[1].state, ChannelState::Degraded);
        assert!(matches!(
            values[1].reasons.as_slice(),
            [Reason::DependencyUnavailable]
        ));
        assert_eq!(values[1].loaded_materials["trust"], 4);
        assert!(facts[1].state == assembly::ChannelState::Ready);
        assert!(facts[1].reason.is_none());
        let mut without_reason = facts;
        without_reason[0].reason = None;
        let mut values: Vec<_> = without_reason.into_iter().map(channel_projection).collect();
        project_dependents(&mut values);
        assert!(matches!(
            values[1].reasons.as_slice(),
            [Reason::IngressUnavailable]
        ));
    }
}
