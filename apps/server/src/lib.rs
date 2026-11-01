#![deny(clippy::cognitive_complexity)]
//! Embedded authentication assembly and product-owned device/resource authorization.

use rss_mdm_authorization_service as authorization;

use rss_mdm_inventory_service::collection;
use rss_mdm_policy_service::worker as automation;

mod database;
use rss_mdm_registration_service::device;

use rss_mdm_registration_service::enrollment;

mod background;

mod cursor_keys;
mod enrollment_progress;
mod owner_storage;
mod resource_usage;
mod scheduler;
use rss_mdm_inventory_service::inventory_runtime;

mod registration_lifecycle;

mod publication_config;

mod task_signing;
use database::Database;

mod channel_status;
mod diagnostic;
mod error_projection;
mod registration_channels;
mod runtime_diagnostics;
pub use diagnostic::{ConfigIssue, Failure, Monotonic, ProcessError, install_diagnostics};
use rss_mdm_agent_channel as agent;
mod adapters;

mod assembly;
pub use assembly::http::http_contract_document;
pub mod administration;
#[path = "assembly/apple/mod.rs"]
mod apple;
mod clock;
pub mod commands;
pub mod config;
mod identity;
pub mod installation;
mod lifecycle;
pub mod maintenance;
pub mod migration;
mod native;

#[path = "assembly/windows/mod.rs"]
mod windows;
pub use lifecycle::{serve, signal};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Webhook(#[from] rss_mdm_webhook_service::Error),
    #[error("resource not found")]
    NotFound,
    #[error("selected first-use requirements are not ready")]
    FirstUseNotReady,
    #[error("first-use operation not observed")]
    FirstUseOperationMissing,
    #[error(transparent)]
    Resource(#[from] rss_mdm_resource_service::Error),
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
    Policy(#[from] rss_mdm_policy_service::Error),
    #[error(transparent)]
    Scope(#[from] rss_mdm_scope_service::Error),
    #[error(transparent)]
    Execution(#[from] rss_mdm_device_service::control::Error),
    #[error(transparent)]
    Authorization(#[from] rss_mdm_authorization_service::Error),
    #[error(transparent)]
    Registration(#[from] rss_mdm_registration_service::Error),
    #[error(transparent)]
    Inventory(#[from] rss_mdm_inventory_service::Error),
    #[error(transparent)]
    Compliance(#[from] rss_mdm_compliance_service::Error),
    #[error(transparent)]
    Group(#[from] rss_mdm_group_service::Error),
    #[error(transparent)]
    Software(#[from] rss_mdm_software_service::management::Error),
    #[error(transparent)]
    Content(#[from] rss_mdm_content_service::Error),
    #[error(transparent)]
    ContentRequest(#[from] rss_mdm_content_service::service::Error),
    #[error(transparent)]
    Http(#[from] rss_mdm_management_http::Error),
}

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

mod certificate_archive;

pub mod agent_pki;
mod ca_webhooks;

mod device_pki;

mod agent_configurations;

mod recovery_credentials;

pub mod telemetry;

mod scope_group_changes;
mod scopes;

#[cfg(test)]
#[path = "../tests/foundation/mod.rs"]
mod foundation_t2;

#[cfg(test)]
#[path = "../tests/support/authority.rs"]
mod authority_t2_support;
#[cfg(test)]
#[path = "../tests/task_trust/mod.rs"]
mod task_trust_t2;

#[cfg(test)]
#[path = "../tests/agent/mod.rs"]
mod agent_t2;
#[cfg(test)]
#[path = "../tests/support/command_runtime.rs"]
mod command_runtime_t2_support;
#[cfg(test)]
#[path = "../tests/task_trust/support.rs"]
mod device_material_support;

#[cfg(test)]
#[path = "../tests/support/native_identity.rs"]
mod native_identity_t2_support;

#[cfg(test)]
#[path = "../tests/windows/protocol.rs"]
mod windows_t2;

#[cfg(test)]
#[path = "../tests/apple/mod.rs"]
mod apple_t2;

#[cfg(test)]
#[path = "../tests/support/planning.rs"]
mod planning_t2_support;
#[cfg(test)]
#[path = "../tests/policy/configuration.rs"]
mod policy_configuration_t2;
#[cfg(test)]
#[path = "../tests/scope/publication.rs"]
mod scope_t2;
