use crate::Error;
pub(crate) use rss_mdm_policy_service::application::Application;
pub(crate) use rss_mdm_scope_service::{Command, pages};
#[cfg(test)]
#[path = "../planning/mod.rs"]
pub(crate) mod t2;
#[cfg(test)]
#[path = "../planning/support.rs"]
pub(crate) mod test_support;

pub(crate) use rss_mdm_policy_service::clock as automation;
