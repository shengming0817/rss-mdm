pub(crate) use rss_mdm_inventory_service::assets::*;
pub mod http;
pub use http::routes;
pub mod collection {
    pub(crate) use rss_mdm_inventory_service::collection_service::*;
}
use crate::{Error, Failure};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_inventory_service::operation::Operation;
use std::sync::Arc;
use uuid::Uuid;
