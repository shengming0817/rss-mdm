//! Execution consumes published Policy inputs and narrow Scope authority facts.
use crate::{Error, frozen::Frozen, transaction::*};
use rss_mdm_policy::{Frequency, Policy};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;
pub mod admission;

pub mod storage;

pub mod candidates;
