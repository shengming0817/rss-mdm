//! Apple facts required by business use cases; protocol transactions belong to the channel.
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, crate::native::Error>> + Send + 'a>>;
pub struct AppleRegistration {
    pub tenant: String,
    pub device: String,
    pub registration: uuid::Uuid,
    pub generation: i64,
}
pub trait AppleProfiles: Send + Sync {
    fn operation_permissions<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
        operations: Vec<Uuid>,
    ) -> Pending<'a, Vec<crate::native::authorization::Permission>>;

    fn bind_command<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
        binding: rss_mdm_registration_service::command_authority::CommandBinding,
    ) -> Pending<'a, ()>;

    fn reserve_profile<'a>(
        &'a self,
        c: &'a mut PgConnection,
        target: AppleRegistration,
        command: AppleCommand,
    ) -> Pending<'a, ()>;
    fn previous_profiles<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
        user_key: String,
        identifier: String,
    ) -> Pending<'a, Vec<Uuid>>;
}
pub enum AppleEvidence {
    Declarations(Option<Box<rss_mdm_apple_mdm::native::evidence::DeclarationEvidence>>),
    Observations(Vec<rss_mdm_apple_mdm::native::evidence::Observation>),
}
pub trait AppleResults: Send + Sync {
    /// Bounded evidence for one authorized page; all native decoding stays with Apple.
    fn evidence_page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        requests: Vec<(Uuid, rss_mdm_apple_mdm::native::request::Request)>,
        native_values: bool,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, AppleEvidence>>;

    fn declarations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
        native_values: bool,
    ) -> Pending<'a, Option<rss_mdm_apple_mdm::native::evidence::DeclarationEvidence>>;

    fn observations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
        request: rss_mdm_apple_mdm::native::request::Request,
        native_values: bool,
    ) -> Pending<'a, Vec<rss_mdm_apple_mdm::native::evidence::Observation>>;
}
pub struct AppleCommand {
    pub operation: Uuid,
    pub owner: String,
    pub authorized_declarations: Vec<Uuid>,
    pub assets: Vec<rss_mdm_apple_mdm::native::ddm::AssetBinding>,
    pub deadline: i64,
    pub input_version: String,
    pub target: super::NativeTarget,
    pub request: rss_mdm_apple_mdm::native::request::Request,
}
