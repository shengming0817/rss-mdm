pub(crate) use rss_mdm_management_http::enrollment::http;
pub(crate) use rss_mdm_registration_service::enrollment::*;
#[path = "../enrollment/mod.rs"]
pub(crate) mod t2;
#[path = "../enrollment/support.rs"]
pub(crate) mod test_support;
