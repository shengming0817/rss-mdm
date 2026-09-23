//! Native transports share ingress limits and TLS ownership, never protocol state.
pub(crate) mod admission;
pub(crate) mod tls;
use axum::Router;
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsEndpoint {
    pub listen: SocketAddr,
    pub origin: String,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeListenerKind {
    WindowsEnrollment,
    WindowsManagement,
    AppleManagement,
    #[cfg(test)]
    AppleWebhookFixture,
}
impl NativeListenerKind {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::WindowsEnrollment => "mdm-enrollment-tls",
            Self::WindowsManagement => "mdm-management-tls",
            Self::AppleManagement => "apple-management-tls",
            #[cfg(test)]
            Self::AppleWebhookFixture => "apple-webhook-fixture",
        }
    }
    pub(crate) const fn audit_action(self) -> &'static str {
        match self {
            Self::WindowsEnrollment => "protected_request",
            Self::WindowsManagement => "windows_management",
            Self::AppleManagement => "apple_management",
            #[cfg(test)]
            Self::AppleWebhookFixture => "apple_scep",
        }
    }
    pub(crate) const fn windows_retention(self) -> bool {
        match self {
            Self::WindowsManagement => true,
            Self::WindowsEnrollment | Self::AppleManagement => false,
            #[cfg(test)]
            Self::AppleWebhookFixture => false,
        }
    }
}
pub(crate) struct TlsRouter {
    pub(crate) admission: Arc<admission::Admission>,
    pub listen: SocketAddr,
    pub tls: Arc<tokio_rustls::rustls::ServerConfig>,
    pub router: Router,
}
pub(crate) struct Routers {
    pub apple: Option<Arc<crate::apple::Apple>>,
    pub browser: Router,
    pub listeners: Vec<(NativeListenerKind, TlsRouter)>,
}
