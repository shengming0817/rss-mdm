//! A task-scoped grant remembers authentic admission evidence, never browser secrets.
use crate::authorization::{Actor, Permission, Snapshot};
use crate::{Error, authorization::context::AuthorizedPrincipal, database::db};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentInstallStage {
    Install,
    Bootstrap,
    Cleanup { bootstrap: uuid::Uuid },
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionAuthority {
    Software {
        target: rss_mdm_policy::SoftwareTarget,
        tenant: String,
        version: uuid::Uuid,
        device: String,
        operation: uuid::Uuid,
        required: Vec<Permission>,
    },
    Retirement {
        tenant: String,
        retirement: uuid::Uuid,
        version: uuid::Uuid,
        device: String,
        registration: uuid::Uuid,
        execution: uuid::Uuid,
        required: Vec<Permission>,
    },
    AgentInstall {
        stage: AgentInstallStage,
        source_objects: Vec<crate::source_authority::DeviceObject>,
        required: Vec<Permission>,
        package: Box<crate::agent_install::Package>,
        download_origin: String,
        tenant: String,
        policy: uuid::Uuid,
        version: uuid::Uuid,
        device: String,
        operation: uuid::Uuid,
    },
    Credential {
        required: Vec<Permission>,
        actor: Actor,
        registration: uuid::Uuid,
        generation: i64,
        operation: uuid::Uuid,
    },
    DeviceControl {
        action: crate::device_control::Kind,
        confirmation: Option<crate::device_control::RegistrationConfirmation>,
        required: Vec<Permission>,
        actor: Actor,
    },
    Policy {
        source_objects: Vec<crate::source_authority::DeviceObject>,
        unit: String,
        required: Vec<Permission>,
        tenant: String,
        policy: uuid::Uuid,
        version: uuid::Uuid,
        device: String,
        remove: bool,
    },
}
mod validity;
impl ExecutionAuthority {
    pub async fn dispatch_ready(
        &self,
        source: &dyn crate::source_authority::SourceAuthority,
        c: &mut PgConnection,
    ) -> Result<bool, Error> {
        match self {
            Self::Software {
                tenant, operation, ..
            } => Ok((source.mdm_software_enabled()
                || crate::agent_install::dispatched_on(c, tenant, *operation).await?)
                && crate::native_software::dispatch_authority_on(source, c, self).await?),
            Self::Retirement {
                tenant,
                device,
                execution,
                ..
            } => rss_mdm_device_service::lifecycle::execution_allowed_in(
                c, tenant, device, *execution,
            )
            .await
            .map_err(Error::from),
            Self::AgentInstall {
                stage: AgentInstallStage::Cleanup { .. },
                ..
            } => crate::agent_install::cleanup_authorized_on(c, self).await,
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
                crate::agent_install::dispatch_ready_on(c, tenant, *version, device, *operation)
                    .await
            }
            Self::DeviceControl { .. } | Self::Credential { .. } => Ok(true),
            Self::Policy {
                tenant,
                device,
                source_objects,
                remove,
                ..
            } => {
                if *remove {
                    return Ok(true);
                }
                Ok(source
                    .evidence_valid_on(
                        c,
                        rss_request_context::TenantId::parse(tenant)
                            .map_err(|_| Error::Malformed)?,
                        rss_mdm_inventory::Channel::Mdm,
                        device,
                        source_objects,
                    )
                    .await?)
            }
        }
    }
    pub(crate) fn for_control(
        snapshot: &Snapshot,
        proof: &AuthorizedPrincipal,
        device: &str,
        action: crate::device_control::Kind,
        confirmation: Option<crate::device_control::RegistrationConfirmation>,
    ) -> Result<Self, Error> {
        let permissions = [action.permission()];
        for &permission in &permissions {
            crate::permissions::authorize(snapshot, proof, Some(device), permission)?;
        }
        Ok(Self::DeviceControl {
            action,
            confirmation,
            required: permissions.to_vec(),
            actor: proof.actor(),
        })
    }
    pub fn apple_owner(&self, operation: uuid::Uuid) -> Result<String, Error> {
        Ok(match self {
            Self::Retirement { retirement, .. } => format!("retirement:{retirement}"),
            Self::DeviceControl { actor, .. } | Self::Credential { actor, .. } => {
                format!("actor:{}:{}", actor.instance_id(), actor.subject())
            }
            Self::Policy { unit, .. } => format!("configuration:{unit}"),
            Self::Software { .. } | Self::AgentInstall { .. } => {
                format!("operation:{operation}")
            }
        })
    }
    pub fn required(&self) -> &[Permission] {
        match self {
            Self::Retirement { required, .. }
            | Self::Credential { required, .. }
            | Self::DeviceControl { required, .. }
            | Self::Software { required, .. }
            | Self::AgentInstall { required, .. }
            | Self::Policy { required, .. } => required,
        }
    }
    pub fn bind_required(&mut self, permissions: Vec<Permission>) {
        match self {
            Self::Retirement { required, .. }
            | Self::Credential { required, .. }
            | Self::DeviceControl { required, .. }
            | Self::Software { required, .. }
            | Self::AgentInstall { required, .. }
            | Self::Policy { required, .. } => *required = permissions,
        }
    }
    pub fn agent_package(&self) -> Option<&crate::agent_install::Package> {
        match self {
            Self::AgentInstall {
                stage: AgentInstallStage::Install,
                package,
                ..
            } => Some(package),
            _ => None,
        }
    }
    pub(crate) fn control_matches(
        &self,
        input: &crate::Create,
        registration: uuid::Uuid,
        generation: i64,
    ) -> Result<bool, Error> {
        let Self::DeviceControl {
            action,
            confirmation,
            required,
            ..
        } = self
        else {
            return Ok(false);
        };
        if required != &[action.permission()] || action.dangerous() != confirmation.is_some() {
            return Ok(false);
        }
        if let Some(confirmation) = confirmation {
            confirmation.check(registration, generation)?;
        }
        crate::device_control::matches(*action, input)
    }

    pub async fn valid(
        &self,
        source: &dyn crate::source_authority::SourceAuthority,
        conn: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        permissions: &[Permission],
        now: i64,
    ) -> Result<bool, Error> {
        if let Self::Retirement {
            tenant,
            device,
            execution,
            ..
        } = self
        {
            if !rss_mdm_device_service::lifecycle::execution_allowed_in(
                conn, tenant, device, *execution,
            )
            .await
            .map_err(Error::from)?
            {
                return Ok(false);
            }
        }
        if let Self::Policy {
            tenant,
            device,
            remove: true,
            ..
        } = self
        {
            let tenant =
                rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?;
            let mut after = uuid::Uuid::nil();
            loop {
                let page = source
                    .candidates_on(
                        conn,
                        tenant,
                        device,
                        crate::source_authority::CandidateKind::Configuration,
                        after,
                    )
                    .await?;
                if !page.has_more {
                    break;
                }
                after = page.scanned_after;
            }
        }
        Ok(validity::many(
            source,
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
        source: &dyn crate::source_authority::SourceAuthority,
        conn: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        requests: &[(Self, Vec<Permission>)],
        now: i64,
    ) -> Result<Vec<bool>, Error> {
        validity::many(source, conn, key, requests, now, false).await
    }
    /// A correlated receipt settles the original task, independently of later Scope membership.
    pub(crate) async fn receipt_valid(
        &self,
        _source: &dyn crate::source_authority::SourceAuthority,
        conn: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        permissions: &[Permission],
        _now: i64,
    ) -> Result<bool, Error> {
        let Self::Policy {
            tenant,
            policy,
            version,
            ..
        } = self
        else {
            return Ok(
                !permissions.is_empty() && permissions.iter().all(|p| self.required().contains(p))
            );
        };
        if permissions.is_empty() {
            return Ok(false);
        }
        let frozen=sqlx::query_scalar::<_,serde_json::Value>("SELECT frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2 AND policy=$3").bind(tenant).bind(version).bind(policy).fetch_optional(&mut *conn).await.map_err(db)?;
        let Some(frozen) = frozen else {
            return Ok(false);
        };
        let frozen: crate::frozen::Frozen =
            serde_json::from_value(frozen).map_err(|_| Error::Malformed)?;
        let crate::frozen::Frozen::Configuration { native, .. } = frozen else {
            return Ok(false);
        };
        let tenant_id =
            rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?;
        let native = native.open(
            key,
            tenant_id,
            crate::configuration::Owner::Policy {
                policy: *policy,
                version: *version,
            },
        )?;
        let mut accepted = native.apply.permissions()?;
        if let Some(remove) = native.remove {
            accepted.extend(remove.permissions()?);
        }
        if permissions
            .iter()
            .chain(self.required())
            .any(|p| !accepted.contains(p))
        {
            return Ok(false);
        }
        Ok(true)
    }
}
