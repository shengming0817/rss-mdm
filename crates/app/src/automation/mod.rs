//! Host dispatch for the existing durable automation queue; RSS owns claims and recovery.
use crate::mutation::*;
use crate::planning::Planning;
use crate::{Error, Failure, assets};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
pub(crate) mod jobs;
mod model;
mod runtime;
use crate::planning::automation::{Timer, asset_target};
pub(crate) use model::{JobInput, TaskKind};
pub(crate) use runtime::{Automation, Resource};

use rss_mdm_audit_integration::RequestAudit;
