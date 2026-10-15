pub(crate) use rss_mdm_inventory_service::assets::*;
pub mod http;
use crate::{Error, Failure};
pub use http::routes;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_inventory_service::operation::Operation;
use std::sync::Arc;
use uuid::Uuid;
