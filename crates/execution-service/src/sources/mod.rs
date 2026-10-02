//! Execution consumes published Policy inputs and narrow Scope authority facts.
use crate::{Error, action_contract::*, frozen::Frozen, transaction::*};
use rss_mdm_authorization_service::Permission;
use rss_mdm_policy::{Action, Frequency, Policy};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;
pub mod admission;
pub mod enrollment;
pub mod onboarding;
pub mod software;
pub mod storage;

use rss_mdm_resource as resource;
