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
    pub groups: Arc<rss_mdm_group_service::Groups>,
    pub assets: Arc<rss_mdm_inventory_service::assets::AssetService>,
    pub compliance: Arc<rss_mdm_compliance_service::Compliance>,
    pub scope_group_health: Arc<crate::local_delivery::Health>,
    pub(crate) asset_input_health: Arc<crate::local_delivery::Health>,
    pub execution: Arc<rss_mdm_device_service::control::Service>,
    pub software: Arc<rss_mdm_software_service::deployment::SoftwareService>,
    pub recovery: Option<Arc<rss_mdm_recovery_credentials::native::Service>>,
    pub installation: Arc<rss_mdm_registration_service::installation::Service>,
    pub scripts: Arc<rss_mdm_script_service::worker::Worker>,
    pub collections: Arc<rss_mdm_inventory_service::collection::execution::worker::Worker>,
    pub enrollment: Arc<rss_mdm_registration_service::enrollment::tasks::worker::Worker>,
    pub access_tasks: Arc<rss_mdm_device_access_postgres::device_access::execution::worker::Worker>,
    pub credential_tasks: Vec<(
        ComponentName,
        Arc<rss_mdm_recovery_credentials::tasks::worker::Worker>,
    )>,
    pub first_use: Arc<crate::administration::first_use::FirstUse>,
    pub authorization: Arc<rss_mdm_authorization_service::Store>,
    pub clock: Arc<dyn crate::clock::Clock>,
    pub tenant: rss_request_context::TenantId,
    pub instance: String,
}
// A retained input failure participates in lightweight readiness independently
// of detailed job queue counts or the managed task's running state.
fn apply_configuration_input(automation: &mut Component, suspended: Result<bool, HealthFailure>) {
    match suspended {
        Ok(false) => {}
        Ok(true) => {
            automation.readiness = Readiness::NotReady;
            automation.health = Health::Degraded;
            automation.reasons.push(Reason::AutomationSuspended);
        }
        Err(failure) => {
            automation.readiness = Readiness::NotReady;
            automation.health = Health::Degraded;
            automation.reasons.push(health_failure(failure));
        }
    }
}
impl Source for RuntimeDiagnostics {
    fn snapshot<'a>(
        &'a self,
        auth: &'a rss_mdm_authorization_service::context::RequestAuth,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
        continuation: &'a rss_mdm_authorization_service::credential::RequestCredential,
    ) -> futures::future::BoxFuture<'a, Result<Snapshot, rss_mdm_management_http::Error>> {
        Box::pin(async move {
            use rss_mdm_authorization_service::{Error as AuthorizationError, Permission};
            use rss_mdm_management_http::Error;
            tokio::time::timeout_at(auth.deadline.into(), async {
                if auth.proof.tenant_id() != self.tenant.to_string()
                    || auth.proof.instance_id() != self.instance
                {
                    return Err(Error::Forbidden);
                }
                let before = rss_mdm_authorization_service::store::authorization_snapshot(
                    &self.authorization,
                    &auth.proof,
                )
                .await?;
                before
                    .require(&auth.proof, Permission::RuntimeDiagnosticsRead, None)
                    .map_err(AuthorizationError::from)?;
                let binding = before.query_binding(&auth.proof)?;
                let mut result = self.collect(auth.deadline, true).await;
                result.first_use = Some(
                    match before
                        .require(&auth.proof, Permission::RegistrationConfigurationRead, None)
                        .map_err(AuthorizationError::from)
                    {
                        Ok(()) => self.first_use.summary(auth, audit, continuation).await,
                        Err(AuthorizationError::Forbidden) => FirstUse::Forbidden,
                        Err(error) => return Err(error.into()),
                    },
                );
                let fresh = auth.revalidate().await?;
                let current = rss_mdm_authorization_service::store::authorization_snapshot(
                    &self.authorization,
                    &auth.proof,
                )
                .await?;
                if auth.current_binding(&current, fresh.as_ref())? != binding {
                    return Err(Error::QueryReadConflict);
                }
                current
                    .require(&auth.proof, Permission::RuntimeDiagnosticsRead, None)
                    .map_err(AuthorizationError::from)?;
                Ok(result)
            })
            .await
            .map_err(|_| Error::Unavailable(rss_mdm_management_http::Failure::RequestDeadline))?
        })
    }
}
impl RuntimeDiagnostics {
    pub(crate) fn collect(
        &self,
        cutoff: Instant,
        detailed: bool,
    ) -> futures::future::BoxFuture<'_, Snapshot> {
        Box::pin(async move {
            let mut inventory = self.inventory_health();
            if detailed {
                self.enrich_inventory(cutoff, &mut inventory).await;
            }
            let mut policy = worker_component(
                ComponentName::Policy,
                self.planning.automation_state(),
                true,
                false,
            );
            let health = self.planning.automation_health();
            apply_runner(
                &mut policy,
                Runner {
                    scan: health.scan.map(run_result),
                    unresolved_attempts: health.unresolved_attempts,
                    truncated: health.truncated,
                    latest_failure: health.latest_failure.map(|f| AttemptFailure {
                        stage: attempt_stage(f.stage),
                        reason: automation_failure(f.failure),
                        observed_at: f.observed_at,
                    }),
                },
            );
            let health = self.groups.runner_health();
            let mut group = worker_component(
                ComponentName::Group,
                self.groups.task_state(),
                health.scan.is_some(),
                false,
            );
            apply_runner(
                &mut group,
                Runner {
                    scan: health.scan.map(|v| RunResult {
                        successful: v.failure.is_none(),
                        reason: v.failure.map(execution_failure),
                        observed_at: v.observed_at,
                    }),
                    unresolved_attempts: health.unresolved_attempts,
                    truncated: health.truncated,
                    latest_failure: health.latest_failure.map(|f| AttemptFailure {
                        stage: attempt_stage(f.stage),
                        reason: execution_failure(f.failure),
                        observed_at: f.observed_at,
                    }),
                },
            );
            let health = self.scopes.runner_health();
            let mut scope = worker_component(
                ComponentName::Scope,
                self.scopes.task_state(),
                health.scan.is_some(),
                false,
            );
            apply_runner(
                &mut scope,
                Runner {
                    scan: health.scan.map(|v| RunResult {
                        successful: v.failure.is_none(),
                        reason: v.failure.map(execution_failure),
                        observed_at: v.observed_at,
                    }),
                    unresolved_attempts: health.unresolved_attempts,
                    truncated: health.truncated,
                    latest_failure: health.latest_failure.map(|f| AttemptFailure {
                        stage: attempt_stage(f.stage),
                        reason: execution_failure(f.failure),
                        observed_at: f.observed_at,
                    }),
                },
            );
            let health = self.assets.worker_status();
            let mut assets = worker_component(
                ComponentName::AssetQuery,
                health.task,
                health.scan.is_some(),
                false,
            );
            apply_runner(
                &mut assets,
                Runner {
                    scan: health.scan.map(|v| RunResult {
                        successful: v.failure.is_none(),
                        reason: v.failure.map(execution_failure),
                        observed_at: v.observed_at,
                    }),
                    unresolved_attempts: health.unresolved_attempts,
                    truncated: health.truncated,
                    latest_failure: health.latest_failure.map(|f| AttemptFailure {
                        stage: attempt_stage(f.stage),
                        reason: execution_failure(f.failure),
                        observed_at: f.observed_at,
                    }),
                },
            );
            let health = self.compliance.worker_status();
            let mut compliance = worker_component(
                ComponentName::Compliance,
                health.task,
                health.scan.is_some(),
                false,
            );
            apply_runner(
                &mut compliance,
                Runner {
                    scan: health.scan.map(|v| RunResult {
                        successful: v.failure.is_none(),
                        reason: v.failure.map(execution_failure),
                        observed_at: v.observed_at,
                    }),
                    unresolved_attempts: health.unresolved_attempts,
                    truncated: health.truncated,
                    latest_failure: health.latest_failure.map(|f| AttemptFailure {
                        stage: attempt_stage(f.stage),
                        reason: execution_failure(f.failure),
                        observed_at: f.observed_at,
                    }),
                },
            );
            let health = self.devices.worker_health();
            let mut associations = worker_component(
                ComponentName::DeviceAssociations,
                health.task,
                health.observed,
                health.failure.is_some(),
            );
            if let Some(failure) = health.failure {
                associations.reasons.push(execution_failure(failure));
            }
            associations.runner = Some(Runner {
                scan: None,
                unresolved_attempts: health.unresolved_attempts,
                truncated: health.truncated,
                latest_failure: None,
            });
            let mut control =
                recovery_component(ComponentName::DeviceControl, &self.execution.health());
            let mut software =
                recovery_component(ComponentName::SoftwareDeployment, &self.software.health());
            let remaining = || {
                cutoff.saturating_duration_since(rss_request_context::Clock::now(
                    &crate::lifecycle::RuntimeTimer,
                ))
            };
            let (
                group_input,
                scope_input,
                compliance_input,
                policy_input,
                control_input,
                software_input,
            ) = tokio::join!(
                self.groups.input_failed(remaining()),
                self.scopes.input_failed(remaining()),
                self.compliance.input_failed(remaining()),
                self.planning.configuration_input_suspended(cutoff),
                self.execution.ingress_health(cutoff),
                self.software.ingress_health(cutoff)
            );
            apply_configuration_input(&mut group, group_input.map_err(|e| queue_failure(e.into())));
            apply_configuration_input(&mut scope, scope_input.map_err(|e| queue_failure(e.into())));
            apply_configuration_input(
                &mut compliance,
                compliance_input.map_err(|e| queue_failure(e.into())),
            );
            apply_configuration_input(&mut policy, policy_input);
            match control_input.map_err(input_health_error) {
                Ok(state) => {
                    apply_configuration_input(&mut control, Ok(state.suspended));
                    control.dispatch = Some(Dispatch {
                        event_after: state.event_after,
                        window_open: state.window_open,
                    });
                    control
                        .dependencies
                        .push(dependency(DependencyName::CommandStorage, None));
                }
                Err(error) => {
                    apply_configuration_input(&mut control, Err(error));
                    control.dependencies.push(dependency(
                        DependencyName::CommandStorage,
                        Some(health_failure(error)),
                    ));
                }
            }
            match software_input.map_err(software_health_error) {
                Ok(state) => {
                    apply_configuration_input(&mut software, Ok(state.suspended));
                    software.dispatch = Some(Dispatch {
                        event_after: state.event_after,
                        window_open: state.window_open,
                    });
                    software
                        .dependencies
                        .push(dependency(DependencyName::CommandStorage, None));
                }
                Err(error) => {
                    apply_configuration_input(&mut software, Err(error));
                    software.dependencies.push(dependency(
                        DependencyName::CommandStorage,
                        Some(health_failure(error)),
                    ));
                }
            }
            if detailed {
                let (p, g, s, a, c, control_inputs, software_inputs) = tokio::join!(
                    self.planning.queue_health(cutoff),
                    self.groups.queue_health(remaining()),
                    self.scopes.queue_health(remaining()),
                    self.assets.queue_health(remaining()),
                    self.compliance.queue_health(remaining()),
                    self.execution.input_pending_count(cutoff),
                    self.software.input_pending_count(cutoff)
                );
                apply_queues(&mut policy, p);
                apply_queues(&mut group, g.map_err(|e| queue_failure(e.into())));
                apply_queues(&mut scope, s.map_err(|e| queue_failure(e.into())));
                apply_queues(&mut assets, a.map_err(|e| queue_failure(e.into())));
                apply_queues(&mut compliance, c.map_err(|e| queue_failure(e.into())));
                apply_input_queue(&mut control, control_inputs.map_err(input_health_error));
                apply_input_queue(
                    &mut software,
                    software_inputs.map_err(software_health_error),
                );
            }
            let mut components = vec![
                self.baseline_component(cutoff).await.unwrap_or_else(|| {
                    let mut value = unmounted(ComponentName::Baseline);
                    value.mounted = true;
                    value
                }),
                self.telemetry_component(cutoff, detailed)
                    .await
                    .unwrap_or_else(|| unmounted(ComponentName::Telemetry)),
                inventory,
                policy,
                group,
                scope,
                assets,
                compliance,
                associations,
                delivery_component(ComponentName::ScopeGroupDelivery, &self.scope_group_health),
                delivery_component(ComponentName::AssetInputDelivery, &self.asset_input_health),
                control,
                software,
                recovery_component(
                    ComponentName::NativeInstallation,
                    &self.installation.health(),
                ),
                recovery_component(ComponentName::ScriptExecution, &self.scripts.health()),
                recovery_component(
                    ComponentName::CollectionExecution,
                    &self.collections.health(),
                ),
                recovery_component(ComponentName::EnrollmentTasks, &self.enrollment.health()),
                recovery_component(
                    ComponentName::DeviceAccessExecution,
                    &self.access_tasks.health(),
                ),
                self.recovery
                    .as_ref()
                    .map(|owner| {
                        recovery_component(
                            ComponentName::NativeRecoveryCredentials,
                            &owner.health(),
                        )
                    })
                    .unwrap_or_else(|| unmounted(ComponentName::NativeRecoveryCredentials)),
            ];
            for name in [
                ComponentName::MdmCredentialTasks,
                ComponentName::DaCredentialTasks,
            ] {
                components.push(
                    self.credential_tasks
                        .iter()
                        .find(|(owner, _)| *owner == name)
                        .map(|(_, owner)| recovery_component(name, &owner.health()))
                        .unwrap_or_else(|| unmounted(name)),
                );
            }
            Snapshot {
                channels: self.channel_health(cutoff).await,
                alive: true,
                ready: components
                    .iter()
                    .all(|c| c.readiness != Readiness::NotReady),
                components,
                first_use: None,
            }
        })
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
    async fn baseline_component(&self, cutoff: Instant) -> Option<Component> {
        match tokio::time::timeout_at(
            cutoff.into(),
            crate::administration::baseline::status(&self.access, &self.tenant.to_string()),
        )
        .await
        {
            Ok(Ok(Some((phase, blocked, assets, telemetry)))) => {
                let mut initialization = component(ComponentName::Baseline, phase == "configured");
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
                let mut initialization = component(ComponentName::Baseline, false);
                initialization.health = Health::Unknown;
                initialization.reasons.push(Reason::DependencyUnavailable);
                Some(initialization)
            }
        }
    }
    async fn enrich_inventory(&self, cutoff: Instant, inventory: &mut Component) {
        let observations = self.inventory.diagnostics(cutoff).await;
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
                    match rss_mdm_task_trust::trust::check_revision(
                        rss_mdm_install_support::StorageProfile::Mdm,
                        rss_mdm_task_trust::Use::AgentTask,
                        &mut tx,
                        self.tenant,
                        *revision as u64,
                    )
                    .await
                    {
                        Ok(()) => Ok(true),
                        Err(rss_mdm_task_trust::Error::Conflict) => Ok(false),
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
// Only phases actually owned by each worker participate in readiness.
fn recovery_component(
    name: ComponentName,
    state: &rss_mdm_recovery_observation::Health,
) -> Component {
    use rss_mdm_recovery_observation::Phase;
    let mut result = worker_component(name, state.task, true, false);
    result.readiness = if state.is_ready() {
        Readiness::Ready
    } else {
        Readiness::NotReady
    };
    if state.stopping {
        result.reasons.push(Reason::Stopping);
    }
    for (name, phase) in std::iter::once((PhaseName::Recovery, state.recovery))
        .chain(state.relay.map(|phase| (PhaseName::Relay, phase)))
        .chain(state.inputs.map(|phase| (PhaseName::Inputs, phase)))
    {
        let (state, reason) = match phase {
            Phase::Initializing => (PhaseState::Unobserved, Some(Reason::Initializing)),
            Phase::Healthy => (PhaseState::Healthy, None),
            Phase::Failed(kind) => (PhaseState::Failed, Some(execution_failure(kind))),
        };
        if let Some(reason) = reason {
            result.reasons.push(reason);
        }
        result.phases.push(PhaseObservation {
            name,
            state,
            reason,
        });
    }
    if state
        .phases()
        .any(|phase| matches!(phase, Phase::Failed(_)))
    {
        result.health = Health::Degraded;
    } else if state.phases().any(|phase| phase == Phase::Initializing) {
        result.health = Health::Unknown;
    }
    result.runner = Some(Runner {
        scan: match state.scan {
            Phase::Initializing => None,
            Phase::Healthy => Some(RunResult {
                successful: true,
                reason: None,
                observed_at: None,
            }),
            Phase::Failed(kind) => Some(RunResult {
                successful: false,
                reason: Some(execution_failure(kind)),
                observed_at: None,
            }),
        },
        unresolved_attempts: state.unresolved_attempts,
        truncated: state.truncated,
        latest_failure: None,
    });
    result
}
fn worker_component(
    name: ComponentName,
    status: Option<rss_runtime::TaskState>,
    observed: bool,
    failed: bool,
) -> Component {
    let mut value = component(
        name,
        status == Some(rss_runtime::TaskState::Running) && observed && !failed,
    );
    value.task = Some(task(status));
    if status != Some(rss_runtime::TaskState::Running) {
        value.reasons.push(Reason::WorkerNotRunning);
    }
    if !observed {
        value.reasons.push(Reason::Unobserved);
    }
    if failed {
        value.reasons.push(Reason::DependencyUnavailable);
    } else if !observed || matches!(status, None | Some(rss_runtime::TaskState::Pending)) {
        value.health = Health::Unknown;
    }
    value
}
fn delivery_component(name: ComponentName, owner: &crate::local_delivery::Health) -> Component {
    worker_component(name, owner.state(), owner.observed(), owner.failed())
}
fn unmounted(name: ComponentName) -> Component {
    let mut value = component(name, true);
    value.mounted = false;
    value.readiness = Readiness::NotApplicable;
    value.health = Health::NotApplicable;
    value
}
fn attempt_stage(stage: rss_reconcile::Stage) -> AttemptStage {
    match stage {
        rss_reconcile::Stage::Observe => AttemptStage::Observe,
        rss_reconcile::Stage::Apply => AttemptStage::Apply,
        rss_reconcile::Stage::Renew => AttemptStage::Renew,
        rss_reconcile::Stage::Finish => AttemptStage::Finish,
    }
}
fn apply_runner(value: &mut Component, runner: Runner) {
    if runner.scan.as_ref().is_some_and(|scan| !scan.successful) || runner.unresolved_attempts > 0 {
        value.health = Health::Degraded;
        value.readiness = Readiness::NotReady;
        value.reasons.push(
            runner
                .latest_failure
                .as_ref()
                .map(|f| f.reason)
                .or_else(|| runner.scan.as_ref().and_then(|s| s.reason))
                .unwrap_or(Reason::DependencyUnavailable),
        );
    } else if runner.scan.is_none() {
        value.health = Health::Unknown;
        value.readiness = Readiness::NotReady;
        value.reasons.push(Reason::Unobserved);
    }
    if runner.truncated {
        value.health = Health::Degraded;
        value.readiness = Readiness::NotReady;
        value.reasons.push(Reason::ObservationLimit);
    }
    value.runner = Some(runner);
}
fn apply_queues(value: &mut Component, counts: Result<[u64; 5], HealthFailure>) {
    value.queues = [
        QueueName::Pending,
        QueueName::Running,
        QueueName::Completed,
        QueueName::Failed,
        QueueName::Superseded,
    ]
    .into_iter()
    .enumerate()
    .map(|(i, name)| queue(name, counts.as_ref().ok().map(|v| v[i])))
    .collect();
    value.dependencies.push(dependency(
        DependencyName::BusinessQueues,
        counts.err().map(health_failure),
    ));
    if value
        .dependencies
        .last()
        .is_some_and(|d| matches!(d.state, DependencyState::Unavailable))
    {
        value.health = Health::Degraded;
    }
}
fn apply_input_queue(value: &mut Component, count: Result<u64, HealthFailure>) {
    value.queues.push(queue(
        QueueName::ExecutionInputsPending,
        count.as_ref().ok().copied(),
    ));
    if let Err(failure) = count {
        value.health = Health::Degraded;
        value.dependencies.push(dependency(
            DependencyName::BusinessQueues,
            Some(health_failure(failure)),
        ));
    }
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
        mounted: true,
        phases: Vec::new(),
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

fn queue_failure(error: crate::Error) -> HealthFailure {
    use crate::Error as E;
    match error {
        E::CommitUnknown
        | E::RollbackFailed
        | E::Inventory(
            rss_mdm_inventory_service::Error::CommitUnknown
            | rss_mdm_inventory_service::Error::RollbackFailed,
        )
        | E::Group(
            rss_mdm_group_service::Error::CommitUnknown
            | rss_mdm_group_service::Error::RollbackFailed,
        )
        | E::Compliance(
            rss_mdm_compliance_service::Error::CommitUnknown
            | rss_mdm_compliance_service::Error::RollbackFailed,
        )
        | E::Scope(
            rss_mdm_scope_service::Error::CommitUnknown
            | rss_mdm_scope_service::Error::RollbackFailed,
        ) => HealthFailure::SettlementUnknown,
        _ => HealthFailure::Storage,
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

fn software_health_error(e: rss_mdm_software_service::deployment::Error) -> HealthFailure {
    use rss_mdm_software_service::deployment::Error;
    match e {
        Error::CommitUnknown | Error::RollbackFailed => HealthFailure::SettlementUnknown,
        _ => HealthFailure::Storage,
    }
}

fn input_health_error(e: rss_mdm_device_service::control::Error) -> HealthFailure {
    match e {
        rss_mdm_device_service::control::Error::CommitUnknown
        | rss_mdm_device_service::control::Error::RollbackFailed => {
            HealthFailure::SettlementUnknown
        }
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
