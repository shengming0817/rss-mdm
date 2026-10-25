//! Browser management HTTP. Every mounted router closes over services supplied by App.
mod api;
pub mod api_access;
pub mod assets;
pub mod authorization;
mod body_policy;
pub mod compliance;
pub mod content;
pub mod enrollment;
mod error;
mod error_projection;
pub mod execution;
pub mod http_operation;
pub mod identity;
pub mod planning;
pub mod resource_catalog;
mod response;
pub mod settings;
pub mod software_catalog;
pub mod software_publication;
pub mod tenant_administration;
pub use error::Error;
use rss_mdm_flow_service::automation;
mod diagnostic;
pub use diagnostic::{ConfigIssue, Failure};
use rss_mdm_registration_service::device;

mod router;
pub mod runtime_diagnostics;
pub use router::{
    Services, device_action_routes, identity_context_routes, router, workspace_routes,
};

pub mod boundary;

/// Apply the browser request boundary to the closed Identity SDK router.
pub fn authentication_routes(
    router: rss_mdm_http_contract::Router,
    envelope: boundary::Envelope,
) -> rss_mdm_http_contract::Router {
    router.layer(axum::middleware::from_fn_with_state(
        envelope,
        boundary::authentication,
    ))
}

pub mod certificate_archive;
pub mod device_views;
pub mod timeline;

pub mod software_native;

pub mod agent_enrollment;

pub mod pki;

pub mod windows_entra;

pub mod recovery_credentials;

pub mod software_content;
pub mod webhooks;

pub mod mail;

pub mod first_use;

pub mod telemetry;

pub mod device_access;
pub mod user_profiles;

pub mod enterprise_broker;
