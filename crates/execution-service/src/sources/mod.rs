//! Execution consumes published Policy inputs and narrow Scope authority facts.
use crate::{Error, frozen::Frozen, transaction::*};
use rss_mdm_policy::Policy;
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub mod storage;

pub mod candidates;
