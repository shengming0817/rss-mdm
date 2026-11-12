//! A task-scoped grant remembers authentic admission evidence, never browser secrets.
use crate::deployment::authorization::Permission;
use crate::deployment::{Error, database::db};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authority {
    Software {
        origin: rss_mdm_audit_integration::activity::ActivityOrigin,
        retirement: Option<uuid::Uuid>,
        target: rss_mdm_policy::SoftwareTarget,
        tenant: String,
        version: uuid::Uuid,
        device: rss_mdm_agent_wire::DeviceId,
        operation: uuid::Uuid,
        required: Vec<Permission>,
    },

    AgentInstall {
        origin: rss_mdm_audit_integration::activity::ActivityOrigin,
        source_objects: Vec<crate::deployment::scope::DeviceObject>,
        required: Vec<Permission>,
        package: Box<crate::installation::package::Package>,
        download_origin: String,
        tenant: String,
        policy: uuid::Uuid,
        version: uuid::Uuid,
        device: rss_mdm_agent_wire::DeviceId,
        operation: uuid::Uuid,
    },
}
mod validity;
impl Authority {
    pub async fn dispatch_ready(
        &self,
        inventory: &dyn crate::deployment::inventory::Inventory,
        source: &dyn crate::deployment::scope::Sources,
        _lifecycle: &dyn crate::deployment::retirement::Lifecycle,
        c: &mut PgConnection,
        mdm_software_enabled: bool,
    ) -> Result<bool, Error> {
        match self {
            Self::Software {
                tenant, operation, ..
            } => Ok((mdm_software_enabled
                || crate::deployment::agent_install::dispatched_on(c, tenant, *operation).await?)
                && crate::deployment::native_software::dispatch_authority_on(source, c, self)
                    .await?),

            Self::AgentInstall {
                tenant,
                version,
                device,
                operation,
                source_objects,
                ..
            } => {
                if !source
                    .evidence_valid_on(
                        c,
                        rss_request_context::TenantId::parse(tenant)
                            .map_err(|_| Error::Malformed)?,
                        rss_mdm_inventory::Channel::Mdm,
                        device,
                        source_objects,
                    )
                    .await?
                {
                    return Ok(false);
                }
                crate::deployment::agent_install::dispatch_ready_on(
                    inventory, c, tenant, *version, device, *operation,
                )
                .await
            }
        }
    }

    pub fn apple_owner(&self, operation: uuid::Uuid) -> Result<String, Error> {
        Ok(match self {
            Self::Software { .. } | Self::AgentInstall { .. } => {
                format!("operation:{operation}")
            }
        })
    }
    pub fn required(&self) -> &[Permission] {
        match self {
            Self::Software { required, .. } | Self::AgentInstall { required, .. } => required,
        }
    }
    pub fn bind_required(&mut self, permissions: Vec<Permission>) {
        match self {
            Self::Software { required, .. } | Self::AgentInstall { required, .. } => {
                *required = permissions
            }
        }
    }
    pub fn agent_package(&self) -> Option<&crate::installation::package::Package> {
        match self {
            Self::AgentInstall { package, .. } => Some(package),
            _ => None,
        }
    }

    pub async fn valid(
        &self,
        source: &dyn crate::deployment::scope::Sources,
        lifecycle: &dyn crate::deployment::retirement::Lifecycle,
        conn: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        permissions: &[Permission],
        now: i64,
    ) -> Result<bool, Error> {
        Ok(validity::many(
            source,
            lifecycle,
            conn,
            key,
            &[(self.clone(), permissions.to_vec())],
            now,
            true,
        )
        .await?
        .pop()
        .unwrap_or(false))
    }
    pub(crate) async fn valid_many(
        source: &dyn crate::deployment::scope::Sources,
        lifecycle: &dyn crate::deployment::retirement::Lifecycle,
        conn: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        requests: &[(Self, Vec<Permission>)],
        now: i64,
    ) -> Result<Vec<bool>, Error> {
        validity::many(source, lifecycle, conn, key, requests, now, false).await
    }
    /// A correlated receipt settles the original task, independently of later Scope membership.
    pub(crate) async fn receipt_valid(
        &self,
        _source: &dyn crate::deployment::scope::Sources,
        _lifecycle: &dyn crate::deployment::retirement::Lifecycle,
        conn: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        permissions: &[Permission],
        _now: i64,
    ) -> Result<bool, Error> {
        let _ = (conn, key);
        Ok(!permissions.is_empty() && permissions.iter().all(|p| self.required().contains(p)))
    }
}
