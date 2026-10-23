//! Device Access association authority. Registration and local-account generations are distinct.
//! ref: kanidm server/lib/src/idm/credupdatesession.rs (explicit credential ceremony state).
mod service;
pub mod storage;
use crate::Error;
use rss_mdm_agent_wire::runtime::{
    AccessAccount, AccessConfiguration, AccessEffect, AccessLocalSession, TaskPlatform,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const INSTALL_SQL: &str = include_str!("../schema/device-access.sql");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Person {
    pub instance: Uuid,
    pub principal: Uuid,
}
impl Person {
    pub fn validate(&self) -> Result<(), Error> {
        if self.instance.is_nil() || self.principal.is_nil() {
            Err(Error::Malformed)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AccountIntent {
    Existing {
        account: AccessAccount,
    },
    Create {
        platform: TaskPlatform,
        name: String,
    },
}
impl AccountIntent {
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Existing { account } => account.validate().map_err(|_| Error::Malformed),
            Self::Create { name, .. } => {
                if name.is_empty()
                    || name.len() > 20
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    || !name.as_bytes()[0].is_ascii_alphabetic()
                {
                    Err(Error::Malformed)
                } else {
                    Ok(())
                }
            }
        }
    }
    pub fn platform(&self) -> TaskPlatform {
        match self {
            Self::Existing { account } => account.platform(),
            Self::Create { platform, .. } => *platform,
        }
    }
    pub fn account(&self) -> Option<&AccessAccount> {
        match self {
            Self::Existing { account } => Some(account),
            Self::Create { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pending,
    Active,
    Revoked,
}

/// The initiator of a binding generation, distinct from the policy publisher.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Origin {
    SelfEnrollment,
    Administrator {
        authority: rss_mdm_authorization_service::OperationAuthority,
    },
}

/// A configured business target. It does not authenticate an HTTP request or issue a session.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub id: Uuid,
    pub tenant: Uuid,
    pub device: String,
    pub registration: Uuid,
    pub registration_generation: i64,
    pub person: Person,
    pub origin: Origin,
    pub generation: i64,
    pub revision: i64,
    pub state: State,
    pub intent: AccountIntent,
    pub account: Option<AccessAccount>,
    pub policy: Uuid,
    pub policy_version: Uuid,
    pub configuration: AccessConfiguration,
    pub received_revision: Option<i64>,
    pub applied_revision: Option<i64>,
    pub effect: Option<AccessEffect>,
    pub created_by_rss: bool,
}
impl Binding {
    pub fn validate(&self) -> Result<(), Error> {
        self.person.validate()?;
        self.intent.validate()?;
        if self.id.is_nil()
            || self.tenant.is_nil()
            || self.registration.is_nil()
            || self.policy.is_nil()
            || self.policy_version.is_nil()
            || self.device.is_empty()
            || self.device.len() > 256
            || self.generation < 1
            || self.revision < 1
            || self.registration_generation < 1
            || self
                .received_revision
                .is_some_and(|r| r < 1 || r > self.revision)
            || self
                .applied_revision
                .is_some_and(|r| r < 1 || r > self.revision)
        {
            return Err(Error::Malformed);
        }
        if let Some(account) = &self.account {
            account.validate().map_err(|_| Error::Malformed)?;
            if account.platform() != self.intent.platform()
                || self.intent.account().is_some_and(|a| a != account)
            {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
    /// Desired effect identity, independent of delivery state and observations.
    pub fn definition_digest(&self) -> Result<[u8; 32], Error> {
        use sha2::{Digest, Sha256};
        Ok(Sha256::digest(
            serde_json::to_vec(&(
                "rss-mdm-device-access.v1",
                self.tenant,
                &self.device,
                self.registration,
                self.registration_generation,
                self.id,
                self.generation,
                self.revision,
                &self.person,
                &self.origin,
                &self.intent,
                self.policy,
                self.policy_version,
                &self.configuration,
                self.state == State::Revoked,
            ))
            .map_err(|_| Error::Malformed)?,
        )
        .into())
    }
    pub fn accepts_login(&self) -> bool {
        self.state == State::Active
            && self.configuration.enabled
            && self.account.is_some()
            && self.applied_revision == Some(self.revision)
            && self.effect.as_ref().is_some_and(AccessEffect::complete)
    }
}

/// A policy selection produced by the trusted Policy/Scope owner on the borrowed connection.
/// This is composition data, never an HTTP input.
pub struct PolicySelection {
    pub policy: Uuid,
    pub version: Uuid,
    pub configuration: AccessConfiguration,
}

/// Product composition checks the current policy and live native interactive context.
pub trait Admission: Send + Sync {
    fn policy<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: Uuid,
        device: &'a str,
        policy: Uuid,
    ) -> crate::agent::Pending<'a, PolicySelection>;
    fn local_session<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        device: &'a crate::DevicePrincipal,
    ) -> crate::agent::Pending<'a, AccessLocalSession>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub action: Action,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Action {
    Put {
        person: Person,
        intent: AccountIntent,
        policy: Uuid,
    },
    Unbind,
}
