//! A task-scoped grant remembers authentic admission evidence, never browser secrets.
use crate::authorization::{Actor, Permission, Snapshot};
use crate::{Error, authorization::context::AuthorizedPrincipal, database::db};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionAuthority {
    Retirement {
        origin: rss_mdm_audit_integration::activity::ActivityOrigin,
        tenant: String,
        retirement: uuid::Uuid,
        version: uuid::Uuid,
        device: String,
        registration: uuid::Uuid,
        execution: uuid::Uuid,
        required: Vec<Permission>,
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
}
mod validity;
impl ExecutionAuthority {
    pub async fn dispatch_ready(&self, c: &mut PgConnection) -> Result<bool, Error> {
        match self {
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

            Self::DeviceControl { .. } | Self::Credential { .. } => Ok(true),
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
    pub fn apple_owner(&self, _operation: uuid::Uuid) -> Result<String, Error> {
        Ok(match self {
            Self::Retirement { retirement, .. } => format!("retirement:{retirement}"),
            Self::DeviceControl { actor, .. } | Self::Credential { actor, .. } => {
                format!("actor:{}:{}", actor.instance_id(), actor.subject())
            }
        })
    }
    pub fn required(&self) -> &[Permission] {
        match self {
            Self::Retirement { required, .. }
            | Self::Credential { required, .. }
            | Self::DeviceControl { required, .. } => required,
        }
    }
    pub fn bind_required(&mut self, permissions: Vec<Permission>) {
        match self {
            Self::Retirement { required, .. }
            | Self::Credential { required, .. }
            | Self::DeviceControl { required, .. } => *required = permissions,
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
            && !rss_mdm_device_service::lifecycle::execution_allowed_in(
                conn, tenant, device, *execution,
            )
            .await
            .map_err(Error::from)?
        {
            return Ok(false);
        }
        Ok(validity::many(
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
        conn: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        requests: &[(Self, Vec<Permission>)],
        now: i64,
    ) -> Result<Vec<bool>, Error> {
        validity::many(conn, key, requests, now, false).await
    }
    /// A correlated receipt settles the original task, independently of later Scope membership.
    pub(crate) async fn receipt_valid(
        &self,
        _source: &rss_mdm_scope_service::channels::ChannelTargets,
        conn: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        permissions: &[Permission],
        _now: i64,
    ) -> Result<bool, Error> {
        let _ = (conn, key);
        Ok(!permissions.is_empty() && permissions.iter().all(|p| self.required().contains(p)))
    }
}
