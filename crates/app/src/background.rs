//! Startup-only resource arithmetic. RSS owns task admission, claims and execution.
use crate::{ConfigIssue, Error, config::Config};
use serde::Deserialize;

pub(crate) const IDENTITY_CONNECTIONS: u32 = 10;
pub(crate) const AUXILIARY_CONNECTIONS: u32 = 10;
pub(crate) const SCHEDULER_CONNECTIONS: u32 = 2;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackgroundConfig {
    pub device_concurrency: usize,
    pub database_connection_budget: u32,
    /// Maximum tenant host processes sharing this deployment's database allocation.
    pub database_host_instances: u32,
}
impl BackgroundConfig {
    /// Device tasks share the access source runtime with foreground and fixed workers.
    pub(crate) fn access_connections(&self) -> u32 {
        self.device_concurrency as u32 + 8
    }
    /// Execution shares its runtime with Policy events, relay and foreground requests.
    pub(crate) fn execution_connections(&self) -> u32 {
        self.device_concurrency as u32 + 8
    }
    pub(crate) fn business_connections(&self) -> u32 {
        self.device_concurrency as u32 + 14
    }
    pub(crate) fn validate(&self, config: &Config) -> Result<(), Error> {
        let bad = || Error::Configuration(ConfigIssue::Budget);
        if !(1..=64).contains(&self.device_concurrency) || self.database_host_instances == 0 {
            return Err(bad());
        }
        // One entry per physical pool. Audit and domain adapters borrow these pools.
        let mut pools = vec![
            ("access", 4),
            ("observation", 4),
            ("projection", 4),
            ("identity", IDENTITY_CONNECTIONS),
            ("access-source", self.access_connections()),
            ("business", self.business_connections()),
            ("execution", self.execution_connections()),
            ("execution-scheduler", SCHEDULER_CONNECTIONS),
            ("business-scheduler", SCHEDULER_CONNECTIONS),
            ("notifications", 1),
            ("scope-group-delivery", 2),
            ("webhook-recovery", AUXILIARY_CONNECTIONS),
            // Direct startup/maintenance probes do not borrow a long-lived pool.
            ("direct-probes", 2),
        ];
        if config.content.is_some() {
            pools.push(("content", 4));
        }
        if !config.flow.publication.sources.is_empty() {
            pools.push(("publication", AUXILIARY_CONNECTIONS));
        }
        if config.tenant_administration.is_some() {
            pools.extend([
                ("tenant-registry", 8),
                ("tenant-registry-source", IDENTITY_CONNECTIONS),
            ]);
        }
        if let Some(telemetry) = &config.telemetry {
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
            .and_then(|per_host| per_host.checked_mul(self.database_host_instances))
            .ok_or_else(bad)?;
        if total > self.database_connection_budget {
            return Err(bad());
        }
        Ok(())
    }
}
