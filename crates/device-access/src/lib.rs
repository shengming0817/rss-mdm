//! Device Access business values and pure qualification rules.
#![forbid(unsafe_code)]
use rss_mdm_agent_wire::runtime::{AccessAccount, AccessConfiguration, TaskPlatform};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("invalid device access value")]
pub struct Error;
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Person {
    pub instance: Uuid,
    pub principal: Uuid,
}
impl Person {
    pub fn validate(&self) -> Result<(), Error> {
        if self.instance.is_nil() || self.principal.is_nil() {
            Err(Error)
        } else {
            Ok(())
        }
    }
}

#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
            Self::Existing { account } => account.validate().map_err(|_| Error),
            Self::Create { name, .. } => {
                if name.is_empty()
                    || name.len() > 20
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    || !name.as_bytes()[0].is_ascii_alphabetic()
                {
                    Err(Error)
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

#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pending,
    Active,
    Revoked,
}

/// A policy selection produced by the trusted Policy/Scope owner on the borrowed connection.
/// This is composition data, never an HTTP input.
pub struct PolicySelection {
    pub policy: Uuid,
    pub version: Uuid,
    pub configuration: AccessConfiguration,
}

pub mod deployment;
