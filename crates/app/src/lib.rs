#![deny(clippy::cognitive_complexity)]
//! Embedded authentication assembly and product-owned device/resource authorization.
#[cfg(test)]
extern crate self as rss_mdm_app;
#[cfg(not(test))]
use rss_mdm_inventory_service::assets;
#[cfg(test)]
#[path = "../tests/fixtures/assets.rs"]
mod assets;
#[cfg(test)]
#[path = "../tests/audit/mod.rs"]
mod audit_integration_tests;
#[cfg(not(test))]
use rss_mdm_authorization_service as authorization;
#[cfg(test)]
#[path = "../tests/fixtures/authorization.rs"]
mod authorization;
use rss_mdm_flow_service::automation;
#[cfg(not(test))]
use rss_mdm_inventory_service::collection;
#[cfg(test)]
#[path = "../tests/fixtures/collection.rs"]
mod collection;
#[cfg(test)]
#[path = "../tests/fixtures/compliance.rs"]
mod compliance;
mod database;
#[cfg(not(test))]
use rss_mdm_registration_service::device;
#[cfg(test)]
#[path = "../tests/fixtures/device.rs"]
mod device;
#[cfg(not(test))]
use rss_mdm_registration_service::enrollment;
#[cfg(test)]
#[path = "../tests/fixtures/enrollment.rs"]
mod enrollment;
#[cfg(test)]
#[path = "../tests/fixtures/execution.rs"]
mod execution;

#[cfg(test)]
#[path = "../tests/fixtures/content.rs"]
mod content;
mod execution_assembly;
mod flow;
#[cfg(not(test))]
use rss_mdm_inventory_service::inventory_runtime;
#[cfg(test)]
#[path = "../tests/fixtures/inventory_runtime.rs"]
mod inventory_runtime;
#[cfg(not(test))]
use rss_mdm_flow_service::planning;
#[cfg(test)]
#[path = "../tests/fixtures/planning.rs"]
mod planning;
#[cfg(test)]
#[path = "../../../tests/support/software/mod.rs"]
mod publication_support;
mod registration_lifecycle;
#[cfg(not(test))]
use rss_mdm_flow_service::resource_catalog;
mod publication_config;
#[cfg(test)]
#[path = "../tests/fixtures/resource_catalog.rs"]
mod resource_catalog;
#[cfg(test)]
#[path = "../tests/fixtures/software_catalog.rs"]
mod software_catalog;
mod task_signing;
use database::Database;

mod diagnostic;
mod error_projection;
mod runtime_diagnostics;
pub use diagnostic::{ConfigIssue, Failure, Monotonic, ProcessError, install_diagnostics};
#[cfg(not(test))]
use rss_mdm_agent_channel as agent;
#[cfg(test)]
#[path = "../tests/fixtures/agent.rs"]
mod agent;
mod api;
#[path = "assembly/apple/mod.rs"]
mod apple;
mod clock;
pub mod config;
mod identity;
mod identity_audit;
mod lifecycle;
pub mod maintenance;
pub mod migration;
mod native;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;
#[path = "assembly/windows/mod.rs"]
mod windows;
pub use lifecycle::{serve, signal};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid product configuration")]
    Configuration(ConfigIssue),
    #[error("host dependency unavailable")]
    Unavailable(Failure),
    #[error("invalid host input")]
    Malformed,
    #[error("host operation unavailable")]
    Unsupported,
    #[error("host identity rejected")]
    Unauthorized,
    #[error("host permission denied")]
    Forbidden,
    #[error("host operation conflict")]
    Conflict,
    #[error("commit outcome unknown")]
    CommitUnknown,
    #[error("rollback unconfirmed")]
    RollbackFailed,
    #[error("certificate request rejected")]
    CertificateRequest,
    #[error(transparent)]
    Apple(#[from] rss_mdm_apple_channel::Error),
    #[error(transparent)]
    Windows(#[from] rss_mdm_windows_channel::Error),
    #[error(transparent)]
    Flow(#[from] rss_mdm_flow_service::Error),
    #[error(transparent)]
    Execution(#[from] rss_mdm_execution_service::Error),
    #[error(transparent)]
    Authorization(#[from] rss_mdm_authorization_service::Error),
    #[error(transparent)]
    Registration(#[from] rss_mdm_registration_service::Error),
    #[error(transparent)]
    Inventory(#[from] rss_mdm_inventory_service::Error),
    #[error(transparent)]
    Software(#[from] rss_mdm_software_service::management::Error),
    #[error(transparent)]
    Content(#[from] rss_mdm_content_service::Error),
    #[error(transparent)]
    ContentRequest(#[from] rss_mdm_content_service::service::Error),
    #[error(transparent)]
    Http(#[from] rss_mdm_management_http::Error),
}

#[cfg(test)]
#[path = "../tests/fixtures/error.rs"]
mod fixture_error;

#[cfg(test)]
#[path = "../tests/support/audit.rs"]
mod audit_test_support;

mod worker_wake;

impl From<rss_mdm_certificate::Error> for Error {
    fn from(error: rss_mdm_certificate::Error) -> Self {
        use rss_mdm_certificate::Error as Certificate;
        match error {
            Certificate::Malformed => Self::Malformed,
            Certificate::CertificateRequest => Self::CertificateRequest,
            Certificate::Unauthorized => Self::Unauthorized,
            Certificate::Conflict => Self::Conflict,
            Certificate::Expired | Certificate::Signing => Self::Unavailable(Failure::Certificate),
        }
    }
}
impl From<rss_mdm_apple_mdm::Error> for Error {
    fn from(error: rss_mdm_apple_mdm::Error) -> Self {
        match error {
            rss_mdm_apple_mdm::Error::Malformed => Self::Malformed,
            rss_mdm_apple_mdm::Error::Unsupported => Self::Unsupported,
            rss_mdm_apple_mdm::Error::Conflict => Self::Conflict,
        }
    }
}

mod http_host;

mod authorization_bootstrap;
mod source_credentials;
pub use authorization_bootstrap::{
    Initialize as AuthorizationInitialization, initialize as initialize_authorization,
};

#[cfg(test)]
#[path = "../tests/timeline/mod.rs"]
mod timeline_tests;

mod certificate_archive;

#[cfg(test)]
#[path = "../tests/certificate_archive/mod.rs"]
mod certificate_archive_tests;

pub mod agent_pki;

#[cfg(all(test, feature = "integration"))]
#[path = "../tests/agent_pki/mod.rs"]
mod agent_pki_tests;
