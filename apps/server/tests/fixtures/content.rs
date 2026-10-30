//! Content management ingress; storage is owned by content-service.
#[cfg(all(test, feature = "integration"))]
#[path = "../content/mod.rs"]
pub(crate) mod t2;
