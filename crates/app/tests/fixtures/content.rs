//! Content management ingress; storage is owned by content-service.
pub(crate) use rss_mdm_management_http::content::http;
#[cfg(all(test, feature = "integration"))]
#[path = "../content/mod.rs"]
mod t2;
