//! Browser management HTTP. Every mounted router closes over services supplied by App.
mod api;
pub mod assets;
pub mod authorization;
pub mod collection;
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
pub mod software_catalog;
pub mod software_publication;
pub use error::Error;
use rss_mdm_flow_service::{Failure, automation};
use rss_mdm_registration_service::device;

mod router;
pub mod runtime_diagnostics;
pub use router::{Services, router};

pub mod boundary;

/// Apply the browser request boundary to the closed Identity SDK router.
pub fn authentication_routes(router: axum::Router, envelope: boundary::Envelope) -> axum::Router {
    router.layer(axum::middleware::from_fn_with_state(
        envelope,
        boundary::authentication,
    ))
}
