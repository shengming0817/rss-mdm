//! Configuration consumes immutable channel facts and reservations on the initiating connection.
use super::{Create, model::NativeTarget};
use crate::{Error, authorization::Permission};
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
pub struct Reservation {
    pub device: String,
    pub binding: rss_mdm_registration_service::command_authority::CommandBinding,
    pub target: NativeTarget,
    pub request: rss_mdm_apple_mdm::native::request::Request,
    pub deadline: i64,
    pub input_version: String,
}
pub trait Channels: WindowsEvidence + Send + Sync {
    fn observations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        reads: Vec<ObservationRead>,
        values: bool,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, super::queries::records::NativeObservation>>;

    fn bind_command<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        binding: rss_mdm_registration_service::command_authority::CommandBinding,
        windows: bool,
    ) -> Pending<'a, ()>;
    /// Includes every previous owner's permissions before replacing a shared native object.
    fn previous_permissions<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
        input: &'a Create,
        owner: String,
    ) -> Pending<'a, Vec<Permission>>;
    fn reserve_profile<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        reservation: Reservation,
    ) -> Pending<'a, ()>;
    fn execute_was_sent<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        operation: Uuid,
    ) -> Pending<'a, bool>;
    fn withdrawal_published<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
    ) -> Pending<'a, bool>;
}

/// Evidence needed to reduce a configuration command; protocol parsing remains in the channel.
pub trait WindowsEvidence: Send + Sync {
    fn settlement<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        id: Uuid,
        complete: bool,
    ) -> Pending<'a, rss_mdm_windows_mdm::native::receipt::Settlement>;
    fn assessment<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        id: Uuid,
        registration: String,
        request: rss_mdm_windows_mdm::native::Execution,
    ) -> Pending<'a, rss_mdm_windows_mdm::native::verification::EffectAssessment>;
}

pub struct ObservationRead {
    pub id: Uuid,
    pub device: String,
    pub task: super::Task,
    pub profile: bool,
    pub status: rss_device_command::Status,
}
