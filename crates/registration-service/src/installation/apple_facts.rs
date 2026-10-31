//! Apple facts required by business use cases; protocol transactions belong to the channel.
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, crate::installation::Error>> + Send + 'a>>;
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
    ) -> Pending<'a, Vec<crate::installation::authorization::Permission>>;

    fn bind_command<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
        binding: crate::command_authority::CommandBinding,
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
    /// Correlate native PSSO readback before projecting a Password completion.
    /// Registration qualification deliberately does not require an already-Applied binding.

    /// Bounded evidence for one authorized page; all native decoding stays with Apple.
    fn evidence_page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        requests: Vec<(Uuid, rss_mdm_apple_mdm::native::request::Request)>,
        native_values: bool,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, AppleEvidence>>;
    /// Purge input copies only after execution delivery settles and the material owner permits expiry.

    /// Current-generation declaration keys from the caller's consistent evidence snapshot.

    /// Check current-registration platform evidence without issuing a command.

    /// Server publication withdrawal is distinct from native object absence.

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
