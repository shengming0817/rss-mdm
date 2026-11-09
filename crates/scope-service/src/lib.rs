//! Scope definitions, calculation, publication and independent recovery.
//! Participants borrow the initiating transaction; no service owns a second commit.
use rss_mdm_scope::ScopeDefinition;
use serde::{Deserialize, Serialize};

pub mod results;
pub mod sources;

pub mod group_changes;

pub mod clock;
mod diagnostic;
mod error;
mod error_projection;
pub mod transaction;
pub use diagnostic::Failure;
pub use error::Error;
mod service;
use rss_mdm_authorization_service as authorization;
pub use service::{Dependencies, Scopes};
mod action_admission;
mod calculation;
mod mutations;
pub mod pages;
pub mod preview;
pub mod runtime;
pub mod tasks;
pub mod wire;
use rss_mdm_audit_integration::RequestAudit;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde_json::Value;
use transaction::*;
use uuid::Uuid;
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

pub mod channels;
mod projection;

pub mod window;

mod storage_profile;

pub mod registration;
