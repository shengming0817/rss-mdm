//! Software asset interpretation belongs to Inventory; original observations remain immutable.
//! ref: Apache DataFusion 50.2.0 datafusion/functions-aggregate/src/count.rs (distinct set semantics).
use super::{AssetService, ReadScope, digest};
use crate::{Error, Failure, transaction::*};
use rss_transactional_messaging_postgres::PgTransaction;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
pub struct Sources {
    pub objects: std::sync::Arc<dyn crate::objects::ObjectReader>,
    pub groups: rss_mdm_group_postgres::GroupSources,
}

mod model;
pub use model::*;
mod evidence;
mod filter;
mod projection;
mod query;
mod read;
mod store;
pub mod windows;

#[cfg(test)]
mod tests;
