//! Startup-only resource arithmetic. RSS owns task admission, claims and execution.
use crate::{ConfigIssue, Error, config::Config};
use serde::Deserialize;

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
    pub database_connection_budget: u32,
    /// Maximum tenant host processes sharing this deployment's database allocation.
    pub database_host_instances: u32,
}
impl BackgroundConfig {
    /// Device tasks share the access source runtime with foreground and fixed workers.
    pub(crate) fn access_connections(&self) -> u32 {
        self.device_concurrency as u32 + 8
    }
    /// Execution shares its runtime with Command workers, relay and foreground requests.
    pub(crate) fn execution_connections(&self) -> u32 {
        self.device_concurrency as u32 + 8
    }
    pub(crate) fn inventory_connections(&self) -> u32 {
        (rss_mdm_inventory_service::groups::runtime::CONCURRENCY
            + rss_mdm_inventory_service::assets::runtime::CONCURRENCY
            + rss_mdm_inventory_service::compliance::runtime::CONCURRENCY) as u32
            + 2
    }
    pub(crate) fn scope_connections(&self) -> u32 {
        rss_mdm_scope_service::runtime::CONCURRENCY as u32 + 2
    }
    pub(crate) fn policy_connections(&self) -> u32 {
        self.device_concurrency as u32
            + rss_mdm_policy_service::worker::EVENT_CONCURRENCY as u32
            + 2
    }
    pub(crate) fn telemetry_control_connections(&self) -> u32 {
        rss_mdm_telemetry_service::CONTROL_WORKERS + 2
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
            ("inventory-owner", self.inventory_connections()),
            ("scope-owner", self.scope_connections()),
            ("policy-owner", self.policy_connections()),
            ("resource-owner", 2),
            ("software-owner", 2),
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
                    PROVISIONING_SLOTS * PROVISIONING_CONNECTIONS,
                ),
            ]);
        }
        if let Some(telemetry) = &config.telemetry {
            pools.push(("telemetry", telemetry.connections.get()));
            pools.push(("telemetry-control", self.telemetry_control_connections()));
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
