//! A task-scoped grant remembers authentic admission evidence, never browser secrets.
use crate::control::authorization::{Actor, Permission, Snapshot};
use crate::control::{Error, authorization::context::AuthorizedPrincipal, database::db};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authority {
    Retirement {
        origin: rss_mdm_audit_integration::activity::ActivityOrigin,
        tenant: String,
        retirement: uuid::Uuid,
        version: uuid::Uuid,
        device: String,
        execution: uuid::Uuid,
        required: Vec<Permission>,
    },

    DeviceControl {
        action: crate::control::device_control::Kind,
        confirmation: bool,
        required: Vec<Permission>,
        actor: Actor,
    },
}
mod validity;
impl Authority {
    pub async fn dispatch_ready(&self, c: &mut PgConnection) -> Result<bool, Error> {
        match self {
            Self::Retirement {
                tenant,
                device,
                execution,
                ..
            } => crate::lifecycle::execution_allowed_in(c, tenant, device, *execution)
                .await
                .map_err(Error::from),

            Self::DeviceControl { .. } => Ok(true),
        }
    }
    pub(crate) fn for_control(
        snapshot: &Snapshot,
        proof: &AuthorizedPrincipal,
        device: &str,
        action: crate::control::device_control::Kind,
        confirmation: bool,
    ) -> Result<Self, Error> {
        let permissions = [action.permission()];
        for &permission in &permissions {
            crate::control::permissions::authorize(snapshot, proof, Some(device), permission)?;
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
            Self::DeviceControl { actor, .. } => {
                format!("actor:{}:{}", actor.instance_id(), actor.subject())
            }
        })
    }
    pub fn required(&self) -> &[Permission] {
        match self {
            Self::Retirement { required, .. } | Self::DeviceControl { required, .. } => required,
        }
    }
    pub fn bind_required(&mut self, permissions: Vec<Permission>) {
        match self {
            Self::Retirement { required, .. } | Self::DeviceControl { required, .. } => {
                *required = permissions
            }
        }
    }

    pub(crate) fn control_matches(&self, input: &crate::control::Create) -> Result<bool, Error> {
        let Self::DeviceControl {
            action,
            confirmation,
            required,
            ..
        } = self
        else {
            return Ok(false);
        };
        if required != &[action.permission()] || action.dangerous() != *confirmation {
            return Ok(false);
        }
        crate::control::device_control::matches(*action, input)
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
            && !crate::lifecycle::execution_allowed_in(conn, tenant, device, *execution)
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
        conn: &mut PgConnection,
        key: &rss_mdm_native_protection::Protector,
        permissions: &[Permission],
        _now: i64,
    ) -> Result<bool, Error> {
        let _ = (conn, key);
        Ok(!permissions.is_empty() && permissions.iter().all(|p| self.required().contains(p)))
    }
}
