//! Native transports share ingress limits and TLS ownership, never protocol state.
pub(crate) mod admission;
pub(crate) mod gateway;
pub(crate) mod origins;
use axum::Router;
use serde::Deserialize;
use std::sync::Arc;
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEndpoint {
    pub origin: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChannelKind {
    Agent,
    WindowsEnrollment,
    WindowsManagement,
    AppleManagement,
    #[cfg(test)]
    AppleWebhookFixture,
}
impl ChannelKind {
    pub(crate) const fn windows_retention(self) -> bool {
        match self {
            Self::WindowsManagement => true,
            Self::Agent | Self::WindowsEnrollment | Self::AppleManagement => false,
            #[cfg(test)]
            Self::AppleWebhookFixture => false,
        }
    }
}
pub(crate) struct ChannelRouter {
    pub origins: Vec<String>,
    pub router: Router,
    pub(crate) admission: Arc<admission::Admission>,
}
pub(crate) struct Routers {
    pub(crate) baseline: rss_runtime::ManagedTaskRegistration,
    pub telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
    pub webhooks: Arc<crate::webhooks::Backend>,
    pub apple_control: Arc<rss_mdm_apple_channel::HttpState>,
    pub pki: Arc<rss_mdm_pki_service::registry::Registry>,
    pub agent_pki: Option<Arc<crate::agent_pki::AgentPki>>,
    pub windows: Option<Arc<crate::windows::Windows>>,
    pub apple: Option<Arc<crate::apple::Apple>>,
    pub browser: Router,
    pub agent_enrollment: Option<Arc<rss_mdm_registration_service::agent::Service>>,
    pub listeners: Vec<(ChannelKind, ChannelRouter)>,
}
