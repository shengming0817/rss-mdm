//! App composes bounded reads; preparation and result interpretation stay with each owner.
use super::owner_errors::{
    access_fault, configuration_fault, credential_fault, device_control_fault, enrollment_fault,
    script, script_fault, software_fault,
};
use rss_mdm_authorization_service::Permission;
use rss_mdm_management_http::{Error, Failure};
use std::sync::Arc;
mod preview;
use super::query_snapshot::{QuerySnapshot, sql};
pub(crate) struct Reads {
    pub configuration: Arc<rss_mdm_policy_service::configuration::Transactions>,
    pub software: Arc<rss_mdm_software_service::deployment::queries::Queries>,
    pub enrollment: Arc<rss_mdm_registration_service::enrollment::tasks::Materials>,
    pub entries: rss_mdm_registration_service::enrollment::task::Entries,
    pub recovery_enabled: bool,
    pub snapshot: QuerySnapshot,
    pub policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    pub scripts: rss_mdm_script_service::inputs::Inputs,
    pub collections: rss_mdm_inventory_service::collection::execution::inputs::Inputs,
    pub device_control: Arc<rss_mdm_device_service::control::queries::Queries>,
}

mod history;

mod assignments;

fn source(error: rss_mdm_scope_service::channels::SourceError) -> Error {
    use rss_mdm_scope_service::channels::SourceError as S;
    match error {
        S::Unsupported => Error::Unsupported,
        S::Capacity => Error::Unavailable(Failure::Capacity),
        S::Missing => Error::ScopeNotFound,
        S::Conflict => Error::QueryReadConflict,
        S::Invariant => Error::Unavailable(Failure::PlanningStorage),
        S::Storage(e) => sql(e),
    }
}
fn window(error: rss_mdm_scope_service::window::Error) -> Error {
    use rss_mdm_scope_service::window::Error as W;
    match error {
        W::Malformed => Error::Malformed,
        W::Conflict => Error::QueryCursorInvalidated,
        W::Source(e) => source(e),
    }
}

mod projections;

mod retirement;

#[expect(
    clippy::too_many_arguments,
    reason = "HTTP reads compose explicit owner query ports"
)]
pub(crate) fn assemble(
    snapshot: QuerySnapshot,
    config: &crate::config::Config,
    storage: &super::host_storage::Storage,
    protection: std::sync::Arc<rss_mdm_native_protection::Protector>,
    content: Option<std::sync::Arc<rss_mdm_content_service::Store>>,
    recovery_enabled: bool,
    source: std::sync::Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    configuration: std::sync::Arc<rss_mdm_policy_service::configuration::Transactions>,
    software: std::sync::Arc<rss_mdm_software_service::deployment::queries::Queries>,
    enrollment: std::sync::Arc<rss_mdm_registration_service::enrollment::tasks::Materials>,
    queries: std::sync::Arc<rss_mdm_device_service::control::queries::Queries>,
) -> std::sync::Arc<Reads> {
    Arc::new(Reads {
        configuration,
        software,
        enrollment,
        entries: config.enrollment_entries.clone(),
        recovery_enabled,
        snapshot,
        policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(
            rss_mdm_install_support::StorageProfile::Mdm,
            storage.runtime.clone(),
        ),
        source,
        scripts: rss_mdm_script_service::inputs::Inputs::bind(
            storage.runtime.clone(),
            content.clone(),
        ),
        collections: rss_mdm_inventory_service::collection::execution::inputs::Inputs::bind(
            storage.runtime.clone(),
            content.clone(),
            Arc::new(super::collection_ports::Delivery {
                protection: protection.clone(),
            }),
        ),
        device_control: queries,
    })
}
