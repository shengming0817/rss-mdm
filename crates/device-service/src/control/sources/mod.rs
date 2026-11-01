//! Device consumes published unmanage inputs and current device authority facts.
use crate::control::{Error, frozen::Frozen, transaction::*};
use rss_mdm_policy::Policy;
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub mod storage;

pub mod candidates;
