//! Application-owned routes composed before the shared authentication and audit boundary.
use super::{first_use, settings, user_profiles};
use rss_mdm_http_contract::Router;
use std::sync::Arc;
pub(crate) struct Services<'a> {
    pub profiles: &'a Arc<user_profiles::Backend>,
    pub first_use: &'a Arc<first_use::FirstUse>,
    pub settings: &'a Arc<settings::Directory>,
}
pub(crate) fn mount(
    runtime: Option<Services<'_>>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! { struct Administration for [Browser] { profiles, first_use, settings } }
    Administration {
        profiles: user_profiles::http::register()
            .bind_with(runtime.as_ref(), |s| s.profiles.clone()),
        first_use: first_use::http::register().bind_with(runtime.as_ref(), |s| s.first_use.clone()),
        settings: settings::http::register().bind_with(runtime.as_ref(), |s| s.settings.clone()),
    }
    .assemble()
}
