//! Startup-only resource arithmetic. RSS owns task admission, claims and execution.
use crate::{ConfigIssue, Error, config::Config};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub(crate) const ACCESS_CONNECTIONS: u32 = 4;
pub(crate) const IDENTITY_CONNECTIONS: u32 = 10;
pub(crate) const AUXILIARY_CONNECTIONS: u32 = 10;
pub(crate) const SCHEDULER_CONNECTIONS: u32 = 2;
pub(crate) const PROVISIONING_SLOTS: u32 = 2;
pub(crate) const PROVISIONING_CONNECTIONS: u32 = 1;
pub(crate) const CONTENT_CONNECTIONS: u32 = 4;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackgroundConfig {
    pub device_concurrency: usize,
    pub planning_concurrency: usize,
    pub scheduling: SchedulingConfig,
    pub command_recovery_batch_size: u16,
    pub command_supersede_batch_size: u16,
    pub database_connection_budget: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerPolicy {
    pub claim_batch_size: usize,
    pub scan_budget: u32,
    pub lease_ms: u64,
    pub drain_ms: u64,
    pub attempt_ms: u64,
    pub scan_interval_ms: u64,
    pub idle_scan_ms: u64,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub max_attempts: u32,
}
impl WorkerPolicy {
    fn compile(&self, concurrency: usize) -> Result<rss_reconcile::Policy, Error> {
        let bad = || Error::Configuration(ConfigIssue::Budget);
        for ms in [
            self.drain_ms,
            self.lease_ms,
            self.attempt_ms,
            self.scan_interval_ms,
            self.idle_scan_ms,
            self.initial_backoff_ms,
            self.max_backoff_ms,
        ] {
            if ms == 0
                || i64::try_from(ms).is_err()
                || rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
                    .checked_add(Duration::from_millis(ms))
                    .is_none()
            {
                return Err(bad());
            }
        }
        if self.drain_ms < self.attempt_ms {
            return Err(bad());
        }
        i32::try_from(self.scan_budget).map_err(|_| bad())?;
        rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
            concurrency,
            claim_batch_size: self.claim_batch_size,
            scan_budget: self.scan_budget,
            lease_ttl: Duration::from_millis(self.lease_ms),
            attempt_timeout: Duration::from_millis(self.attempt_ms),
            scan_interval: Duration::from_millis(self.scan_interval_ms),
            idle_scan_interval: Duration::from_millis(self.idle_scan_ms),
            initial_backoff: Duration::from_millis(self.initial_backoff_ms),
            max_backoff: Duration::from_millis(self.max_backoff_ms),
            max_attempts: self.max_attempts,
        })
        .map_err(|_| bad())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulingConfig {
    pub device: WorkerPolicy,
    pub commands: WorkerPolicy,
    pub tasks: WorkerPolicy,
    pub planning: WorkerPolicy,
    pub policy: WorkerPolicy,
}
impl SchedulingConfig {
    pub(crate) fn installation() -> Self {
        let planning = WorkerPolicy {
            claim_batch_size: 64,
            scan_budget: 64,
            lease_ms: 30000,
            drain_ms: 20000,
            attempt_ms: 6000,
            scan_interval_ms: 20,
            idle_scan_ms: 5000,
            initial_backoff_ms: 1000,
            max_backoff_ms: 30000,
            max_attempts: 1000,
        };
        let tasks = WorkerPolicy {
            initial_backoff_ms: 5000,
            max_backoff_ms: 60000,
            ..planning.clone()
        };
        Self {
            device: WorkerPolicy {
                drain_ms: 30000,
                attempt_ms: 8000,
                idle_scan_ms: 60000,
                ..planning.clone()
            },
            commands: WorkerPolicy {
                idle_scan_ms: 60000,
                ..tasks.clone()
            },
            tasks,
            policy: WorkerPolicy {
                idle_scan_ms: 60000,
                ..planning.clone()
            },
            planning,
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Compiled {
    pub device_drain: Duration,
    pub commands_drain: Duration,
    pub tasks_drain: Duration,
    pub planning_drain: Duration,
    pub policy_drain: Duration,
    pub command_recovery_batch: rss_device_command::BatchLimit,
    pub command_supersede_batch: rss_device_command::BatchLimit,
    pub access_connections: u32,
    pub command_connections: u32,
    pub inventory_connections: u32,
    pub scope_connections: u32,
    pub policy_connections: u32,
    pub telemetry_control_connections: u32,
    pub device: rss_reconcile::Policy,
    pub commands: rss_reconcile::Policy,
    pub tasks: rss_reconcile::Policy,
    pub inventory: rss_reconcile::Policy,
    pub group: rss_reconcile::Policy,
    pub scope: rss_reconcile::Policy,
    pub compliance: rss_reconcile::Policy,
    pub policy: rss_reconcile::Policy,
    pub policy_events: rss_reconcile::Policy,
}
impl BackgroundConfig {
    pub(crate) fn compile(&self, config: &Config) -> Result<Compiled, Error> {
        let bad = || Error::Configuration(ConfigIssue::Budget);
        if [self.device_concurrency, self.planning_concurrency]
            .into_iter()
            .any(|value| value == 0 || value > tokio::sync::Semaphore::MAX_PERMITS)
        {
            return Err(bad());
        }
        let device = self.scheduling.device.compile(self.device_concurrency)?;
        let commands = self.scheduling.commands.compile(self.device_concurrency)?;
        let tasks = self.scheduling.tasks.compile(self.device_concurrency)?;
        let planning = self
            .scheduling
            .planning
            .compile(self.planning_concurrency)?;
        let policy = self.scheduling.policy.compile(self.device_concurrency)?;
        let policy_events = self.scheduling.policy.compile(self.planning_concurrency)?;
        let sum = |values: &[usize], extra: u32| -> Result<u32, Error> {
            values
                .iter()
                .try_fold(extra, |n, value| n.checked_add(u32::try_from(*value).ok()?))
                .ok_or_else(bad)
        };
        let (command_slots, policy_slots) = crate::delivery_capacity::Capacity::command_limits(
            std::num::NonZeroUsize::new(commands.concurrency()).ok_or_else(bad)?,
        );
        let compiled = Compiled {
            device_drain: Duration::from_millis(self.scheduling.device.drain_ms),
            commands_drain: Duration::from_millis(self.scheduling.commands.drain_ms),
            tasks_drain: Duration::from_millis(self.scheduling.tasks.drain_ms),
            planning_drain: Duration::from_millis(self.scheduling.planning.drain_ms),
            policy_drain: Duration::from_millis(self.scheduling.policy.drain_ms),
            command_recovery_batch: rss_device_command::BatchLimit::new(
                self.command_recovery_batch_size,
            )
            .map_err(|_| bad())?,
            command_supersede_batch: rss_device_command::BatchLimit::new(
                self.command_supersede_batch_size,
            )
            .map_err(|_| bad())?,
            access_connections: sum(&[device.concurrency()], 8)?,
            command_connections: sum(
                &[commands.concurrency(), command_slots.saturating_sub(2)],
                8,
            )?,
            inventory_connections: sum(
                &[
                    planning.concurrency(),
                    planning.concurrency(),
                    planning.concurrency(),
                ],
                2,
            )?,
            scope_connections: sum(&[planning.concurrency()], 2)?,
            policy_connections: sum(
                &[
                    policy.concurrency(),
                    policy_events.concurrency(),
                    policy_slots.saturating_sub(2),
                ],
                2,
            )?,
            telemetry_control_connections: rss_mdm_telemetry_service::CONTROL_WORKERS
                .checked_add(2)
                .ok_or_else(bad)?,
            device,
            commands,
            tasks,
            inventory: planning,
            group: planning,
            scope: planning,
            compliance: planning,
            policy,
            policy_events,
        };
        // One entry per physical pool. Audit and domain adapters borrow these pools.
        let mut pools = vec![
            ("access", ACCESS_CONNECTIONS),
            ("da-access", 4),
            ("da-transactions", 4),
            ("observation", 4),
            ("projection", 4),
            ("identity", IDENTITY_CONNECTIONS),
            ("access-source", compiled.access_connections),
            ("inventory-owner", compiled.inventory_connections),
            ("scope-owner", compiled.scope_connections),
            ("policy-owner", compiled.policy_connections),
            ("resource-owner", 2),
            ("software-owner", 2),
            ("command", compiled.command_connections),
            ("execution-scheduler", SCHEDULER_CONNECTIONS),
            ("business-scheduler", SCHEDULER_CONNECTIONS),
            ("notifications", 1),
            ("scope-group-delivery", crate::local_delivery::CONNECTIONS),
            ("asset-input-delivery", crate::local_delivery::CONNECTIONS),
            ("webhook-recovery", AUXILIARY_CONNECTIONS),
            // Direct startup/maintenance probes do not borrow a long-lived pool.
            ("direct-probes", 2),
        ];
        if config.content.is_some() {
            pools.extend([
                ("content", CONTENT_CONNECTIONS),
                ("content-owner", 2),
                (
                    "content-admission",
                    rss_mdm_content_service::ADMISSION_CONNECTIONS,
                ),
            ]);
        }
        if !config.publication.sources.is_empty() {
            pools.push(("publication", AUXILIARY_CONNECTIONS));
        }
        if config.tenant_administration.is_some() {
            pools.extend([
                ("tenant-registry", 8),
                ("tenant-registry-source", IDENTITY_CONNECTIONS),
                (
                    "tenant-provisioning",
                    PROVISIONING_SLOTS
                        .checked_mul(PROVISIONING_CONNECTIONS)
                        .ok_or_else(bad)?,
                ),
            ]);
        }
        if !config.telemetry.is_empty() {
            pools.push(("telemetry-control", compiled.telemetry_control_connections));
        }
        for telemetry in &config.telemetry {
            pools.push(("telemetry", telemetry.connections.get()));
            if matches!(
                telemetry.backend,
                crate::telemetry::Storage::TimescaleDedicated { .. }
            ) {
                pools.push(("telemetry-maintenance", telemetry.connections.get()));
            }
        }
        let total = pools
            .iter()
            .try_fold(0u32, |total, (_, max)| total.checked_add(*max))
            .ok_or_else(bad)?;
        if total > self.database_connection_budget {
            return Err(bad());
        }
        Ok(compiled)
    }
}
