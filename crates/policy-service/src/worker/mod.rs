//! Policy-owned durable work; RSS provides claims, leases and recovery.
use crate::application::Application;
use crate::transaction::*;
use crate::{Error, Failure};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
pub mod jobs;
mod runtime;
use crate::clock::Timer;
pub(crate) use rss_mdm_policy_postgres::work::Work;
pub use runtime::{Automation, PolicyWork};
pub(crate) mod health;
pub use health::{
    AttemptFailure, AutomationFailure, AutomationHealth, HealthFailure, RunObservation,
};

use rss_mdm_audit_integration::RequestAudit;
