//! Sole host health aggregation. Component owners remain the status authorities.
use rss_mdm_inventory_service::inventory_runtime::diagnostics::ProbeFailure;
use rss_mdm_management_http::runtime_diagnostics::*;
use rss_mdm_policy_service::worker::HealthFailure;
use std::{sync::Arc, time::Instant};

pub(crate) struct RuntimeDiagnostics {
    pub channels: Arc<crate::channel_status::Channels>,
    pub registration: Arc<dyn rss_mdm_management_http::enrollment::channels::Source>,
    pub pki: Arc<rss_mdm_pki_service::registry::Registry>,
    pub apple_store: Arc<rss_mdm_apple_channel::Store>,
    pub access: sqlx::PgPool,
    pub telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
    pub inventory: Arc<crate::inventory_runtime::InventoryRuntime>,
    pub apple: Option<Arc<crate::apple::Apple>>,
    pub devices: Arc<rss_mdm_device_service::Associations>,
    pub planning: Arc<rss_mdm_policy_service::application::Application>,
    pub scopes: Arc<rss_mdm_scope_service::Scopes>,
    pub groups: Arc<rss_mdm_inventory_service::groups::Groups>,
    pub assets: Arc<rss_mdm_inventory_service::assets::AssetService>,
    pub compliance: Arc<rss_mdm_inventory_service::compliance::Compliance>,
    pub scope_group_health: Arc<crate::scope_group_changes::Health>,
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
        let mut automation = self.automation_component(cutoff).await;
        if detailed {
            self.enrich(cutoff, &mut inventory, &mut automation).await;
        }
        let execution = execution_component(self.execution.health());
        let mut components = vec![inventory, automation, execution];
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
    async fn automation_component(&self, cutoff: Instant) -> Component {
        let status = self.planning.automation_state();
        let mut automation = component(
            ComponentName::Automation,
            status == Some(rss_runtime::TaskState::Running)
                && self.devices.worker_ready()
                && self.groups.task_state() == Some(rss_runtime::TaskState::Running)
                && self.scopes.task_state() == Some(rss_runtime::TaskState::Running)
                && self.scopes.input_observed()
                && !self.scopes.input_failed()
                && self.scope_group_health.state() == Some(rss_runtime::TaskState::Running)
                && self.groups.input_observed()
                && !self.groups.input_failed()
                && self.scope_group_health.observed()
                && !self.scope_group_health.failed(),
        );
        automation.task = Some(task(status));
        if matches!(status, None | Some(rss_runtime::TaskState::Pending)) {
            automation.health = Health::Unknown;
        }
        if status != Some(rss_runtime::TaskState::Running) {
            automation.reasons.push(Reason::WorkerNotRunning);
        }
        if self.scopes.task_state() != Some(rss_runtime::TaskState::Running)
            || self.groups.task_state() != Some(rss_runtime::TaskState::Running)
            || self.scope_group_health.state() != Some(rss_runtime::TaskState::Running)
        {
            automation.reasons.push(Reason::WorkerNotRunning);
            automation.health = Health::Unknown;
        }
        if !self.scopes.input_observed()
            || !self.groups.input_observed()
            || !self.scope_group_health.observed()
        {
            automation.reasons.push(Reason::Unobserved);
            automation.health = Health::Unknown;
        }
        if self.scopes.input_failed()
            || self.groups.input_failed()
            || self.scope_group_health.failed()
        {
            automation.reasons.push(Reason::DependencyUnavailable);
            automation.health = Health::Degraded;
        }
        for owner in [self.assets.worker_status(), self.compliance.worker_status()] {
            if owner.task != Some(rss_runtime::TaskState::Running) {
                automation.readiness = Readiness::NotReady;
                automation.health = Health::Unknown;
                automation.reasons.push(Reason::WorkerNotRunning);
            } else if !owner.observed {
                automation.readiness = Readiness::NotReady;
                automation.health = Health::Unknown;
                automation.reasons.push(Reason::Unobserved);
            }
            if owner.failed {
                automation.readiness = Readiness::NotReady;
                automation.health = Health::Degraded;
                automation.reasons.push(Reason::DependencyUnavailable);
            }
        }
        let ingress = self
            .execution
            .ingress_health(cutoff)
            .await
            .map_err(input_health_error);
        match ingress {
            Ok(state) => {
                if state.suspended {
                    automation.readiness = Readiness::NotReady;
                    automation.health = Health::Degraded;
                    automation.reasons.push(Reason::AutomationSuspended);
                }
                automation.dispatch = Some(Dispatch {
                    event_after: state.event_after,
                    window_open: state.window_open,
                });
                automation
                    .dependencies
                    .push(dependency(DependencyName::CommandStorage, None));
            }
            Err(failure) => {
                automation.readiness = Readiness::NotReady;
                automation.health = Health::Degraded;
                automation.reasons.push(health_failure(failure));
                automation.dependencies.push(dependency(
                    DependencyName::CommandStorage,
                    Some(health_failure(failure)),
                ));
            }
        }
        automation
    }
    fn automation_health(&self) -> rss_mdm_policy_service::worker::AutomationHealth {
        use rss_mdm_policy_service::worker::{AttemptFailure, RunObservation};
        let mut health = self.planning.automation_health();
        let groups = self.groups.runner_health();
        let scopes = self.scopes.runner_health();
        let project = |s: rss_mdm_inventory_service::WorkerStatus| {
            (
                s.scan.map(|v| RunObservation {
                    failure: v.failure.map(group_runner_failure),
                    observed_at: v.observed_at,
                }),
                s.unresolved_attempts,
                s.truncated,
                s.latest_failure.map(|v| AttemptFailure {
                    stage: v.stage,
                    failure: group_runner_failure(v.failure),
                    observed_at: v.observed_at,
                }),
            )
        };
        let observations = [
            (
                groups.scan.map(|v| RunObservation {
                    failure: v.failure.map(group_runner_failure),
                    observed_at: v.observed_at,
                }),
                groups.unresolved_attempts,
                groups.truncated,
                groups.latest_failure.map(|v| AttemptFailure {
                    stage: v.stage,
                    failure: group_runner_failure(v.failure),
                    observed_at: v.observed_at,
                }),
            ),
            (
                scopes.scan.map(|v| RunObservation {
                    failure: v.failure.map(group_runner_failure),
                    observed_at: v.observed_at,
                }),
                scopes.unresolved_attempts,
                scopes.truncated,
                scopes.latest_failure.map(|v| AttemptFailure {
                    stage: v.stage,
                    failure: group_runner_failure(v.failure),
                    observed_at: v.observed_at,
                }),
            ),
            project(self.assets.worker_status()),
            project(self.compliance.worker_status()),
        ];
        for (scan, unresolved, truncated, latest) in observations {
            health.scan = merge_observation(health.scan, scan);
            health.unresolved_attempts = health.unresolved_attempts.saturating_add(unresolved);
            health.truncated |= truncated;
            health.latest_failure = health
                .latest_failure
                .into_iter()
                .chain(latest)
                .max_by_key(|f| f.observed_at);
        }
        health
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
        let (observations, queues, group_queues, scope_queues) = tokio::join!(
            self.inventory.diagnostics(cutoff),
            async {
                let (policy, source) = tokio::join!(
                    self.planning.queue_health(cutoff),
                    self.execution.input_pending_count(cutoff)
                );
                let counts = policy?;
                let pending = source.map_err(input_health_error)?;
                Ok::<_, HealthFailure>([
                    counts[0], counts[1], counts[2], counts[3], counts[4], pending,
                ])
            },
            self.groups.queue_health(cutoff.saturating_duration_since(
                rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
            )),
            self.scopes.queue_health(cutoff.saturating_duration_since(
                rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
            ))
        );
        let group_queues = match (group_queues, scope_queues) {
            (Ok(mut g), Ok(s)) => {
                for (n, v) in g.iter_mut().zip(s) {
                    *n = n.saturating_add(v);
                }
                Ok(g)
            }
            _ => Err(rss_mdm_inventory_service::Error::Unavailable(
                rss_mdm_inventory_service::Failure::AssetsStorage,
            )),
        };
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
        let mut queues = merge_owner_queues(queues, group_queues);
        let remaining = || {
            cutoff.saturating_duration_since(rss_request_context::Clock::now(
                &crate::lifecycle::RuntimeTimer,
            ))
        };
        let (query_counts, compliance_counts) = tokio::join!(
            self.assets.queue_health(remaining()),
            self.compliance.queue_health(remaining())
        );
        queues = merge_owner_queues(merge_owner_queues(queues, query_counts), compliance_counts);
        let values = queues.as_ref().ok();
        automation.queues = [
            QueueName::Pending,
            QueueName::Running,
            QueueName::Completed,
            QueueName::Failed,
            QueueName::Superseded,
            QueueName::ExecutionInputsPending,
        ]
        .into_iter()
        .enumerate()
        .map(|(i, name)| queue(name, values.map(|v| v[i])))
        .collect();
        automation.dependencies.push(dependency(
            DependencyName::BusinessQueues,
            queues
                .as_ref()
                .err()
                .map(|failure| health_failure(*failure)),
        ));
        if queues.is_err() {
            automation.health = Health::Degraded;
        }
        let health = self.automation_health();
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
        if health.scan.is_some_and(|r| r.failure.is_some()) || health.unresolved_attempts > 0 {
            automation.health = Health::Degraded;
        } else if health.scan.is_none() && automation.health == Health::Healthy {
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
    for phase in [state.recovery, state.relay, state.inputs] {
        match phase {
            Phase::Initializing => {
                if state.task == Some(rss_runtime::TaskState::Running)
                    && !state.stopping
                    && !matches!(state.recovery, Phase::Failed(_))
                    && !matches!(state.relay, Phase::Failed(_))
                    && !matches!(state.inputs, Phase::Failed(_))
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
        ErrorKind::Fenced | ErrorKind::BindingChanged => Reason::OwnershipLost,
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
fn health_failure(failure: HealthFailure) -> Reason {
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

fn group_runner_failure(
    kind: rss_reconcile::ErrorKind,
) -> rss_mdm_policy_service::worker::AutomationFailure {
    use rss_mdm_policy_service::worker::AutomationFailure as Failure;
    use rss_reconcile::ErrorKind;
    match kind {
        ErrorKind::Transient | ErrorKind::StorageContract => Failure::StorageUnavailable,
        ErrorKind::Deadline => Failure::Deadline,
        ErrorKind::CommitUnknown | ErrorKind::RollbackFailed => Failure::SettlementUnknown,
        ErrorKind::Fenced | ErrorKind::BindingChanged => Failure::OwnershipLost,
        ErrorKind::Cancelled => Failure::Cancelled,
        ErrorKind::InvalidInput | ErrorKind::Permanent | ErrorKind::Invariant => Failure::Rejected,
    }
}
fn automation_failure(outcome: rss_mdm_policy_service::worker::AutomationFailure) -> Reason {
    use rss_mdm_policy_service::worker::AutomationFailure;
    match outcome {
        AutomationFailure::StorageUnavailable => Reason::DependencyUnavailable,
        AutomationFailure::Deadline => Reason::Deadline,
        AutomationFailure::SettlementUnknown => Reason::SettlementUnknown,
        AutomationFailure::OwnershipLost => Reason::OwnershipLost,
        AutomationFailure::Cancelled => Reason::Stopping,
        AutomationFailure::Rejected => Reason::WorkRejected,
    }
}
fn run_result(value: rss_mdm_policy_service::worker::RunObservation) -> RunResult {
    RunResult {
        successful: value.failure.is_none(),
        reason: value.failure.map(automation_failure),
        observed_at: value.observed_at,
    }
}

fn merge_owner_queues(
    totals: Result<[u64; 6], HealthFailure>,
    counts: Result<[u64; 5], rss_mdm_inventory_service::Error>,
) -> Result<[u64; 6], HealthFailure> {
    let mut totals = totals?;
    let counts = counts.map_err(|error| match error {
        rss_mdm_inventory_service::Error::CommitUnknown
        | rss_mdm_inventory_service::Error::RollbackFailed => HealthFailure::SettlementUnknown,
        _ => HealthFailure::Storage,
    })?;
    for (total, count) in totals.iter_mut().zip(counts) {
        *total = total.saturating_add(count).min(1001);
    }
    Ok(totals)
}

// A healthy observation clears only its owner's failure; every owner must have observed success.
fn merge_observation(
    a: Option<rss_mdm_policy_service::worker::RunObservation>,
    b: Option<rss_mdm_policy_service::worker::RunObservation>,
) -> Option<rss_mdm_policy_service::worker::RunObservation> {
    match (a, b) {
        (Some(a), Some(b)) => Some(
            [a, b]
                .into_iter()
                .max_by_key(|o| (o.failure.is_some(), o.observed_at))
                .expect("two observations"),
        ),
        (a, b) => a.or(b).filter(|o| o.failure.is_some()),
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

fn input_health_error(e: rss_mdm_execution_service::Error) -> HealthFailure {
    match e {
        rss_mdm_execution_service::Error::CommitUnknown
        | rss_mdm_execution_service::Error::RollbackFailed => HealthFailure::SettlementUnknown,
        _ => HealthFailure::Storage,
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
