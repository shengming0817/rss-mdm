pub(crate) use crate::authorization_bootstrap::{bounded as bounded_initialization, initialize};
pub(crate) use rss_mdm_authorization_service::*;
pub(crate) use rss_mdm_management_http::authorization::http;
#[path = "../authorization/mod.rs"]
pub(crate) mod t2;
