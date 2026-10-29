//! Scope definitions, calculation, publication and independent recovery.
//! Participants borrow the initiating transaction; no service owns a second commit.
use rss_mdm_scope::ScopeDefinition;
use serde::{Deserialize, Serialize};

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ScopeChange {
    Put { definition: ScopeDefinition },
    Delete,
}

pub mod results;
pub mod sources;

pub mod group_changes;

pub mod clock;
mod diagnostic;
mod error;
mod error_projection;
pub mod operation;
pub mod transaction;
pub use diagnostic::Failure;
pub use error::Error;
mod service;
use rss_mdm_authorization_service as authorization;
pub use service::{Command, Dependencies, Scopes};
mod action_admission;
mod calculation;
pub mod directory;
mod mutations;
pub mod pages;
mod receipts;
pub mod runtime;
pub mod tasks;
pub mod wire;
use rss_mdm_audit_integration::RequestAudit;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde_json::Value;
use transaction::*;
use uuid::Uuid;
fn query_error(e: rss_mdm_query::Error) -> Error {
    if matches!(e, rss_mdm_query::Error::CursorInvalidated) {
        Error::Conflict
    } else {
        Error::Malformed
    }
}
fn identity(
    command: &Command,
    audit: &RequestAudit,
) -> transaction::Result<(Option<Uuid>, Vec<u8>)> {
    use sha2::{Digest, Sha256};
    let id = match command {
        Command::Scope { change, .. } => Some(change.operation_id),
        _ => None,
    };
    if id.is_some_and(|id| id.is_nil()) {
        return Err(Error::Malformed.into());
    }
    let who = audit.snapshot();
    Ok((
        id,
        Sha256::digest(checked_input(serde_json::to_vec(&(
            audit.tenant(),
            who.actor,
            who.instance,
            command,
        )))?)
        .to_vec(),
    ))
}
fn group_checked<T>(
    r: std::result::Result<T, rss_mdm_group_postgres::Rejection>,
) -> transaction::Result<T> {
    r.map_err(|e| match e {
        rss_mdm_group_postgres::Rejection::NotFound
        | rss_mdm_group_postgres::Rejection::Deleted => Error::NotFound.into(),
        rss_mdm_group_postgres::Rejection::CapacityExceeded
        | rss_mdm_group_postgres::Rejection::PageBudgetExceeded => {
            Error::Unavailable(Failure::Capacity).into()
        }
        rss_mdm_group_postgres::Rejection::InvalidInput => Error::Malformed.into(),
        _ => Error::Conflict.into(),
    })
}

pub mod health;
