//! Execution consumes published Policy inputs and narrow Scope authority facts.
use crate::deployment::{Error, action_contract::*, frozen::Published, transaction::*};
use rss_mdm_policy::{Action, Policy};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;

pub mod onboarding;
pub mod software;
pub mod storage;

use rss_mdm_resource as resource;

pub mod candidates;

pub mod admission;
