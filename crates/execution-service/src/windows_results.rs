//! Windows evidence consumed by business reducers and authorized query projections.
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::{collections::BTreeMap, future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, crate::Error>> + Send + 'a>>;
pub struct Read {
    pub id: Uuid,
    pub registration: Uuid,
    pub registration_generation: i64,
    pub request: rss_mdm_windows_mdm::native::Execution,
    pub values: bool,
}
pub struct Evidence {
    pub receipts: Vec<crate::queries::records::WindowsReceipt>,
    pub assessment: rss_mdm_windows_mdm::native::verification::EffectAssessment,
}
pub struct InstallationRead {
    pub id: Uuid,
    pub registration: Uuid,
    pub generation: i64,
    pub snapshot: Option<Uuid>,
}
#[derive(Debug, Default, PartialEq, Eq)]
pub enum InstallationDelivery {
    #[default]
    Unknown,
    Acknowledged,
    Rejected,
}
#[derive(Default)]
pub struct Installation {
    pub channel_state: Option<serde_json::Value>,
    pub delivery: InstallationDelivery,
}
pub trait Store: Send + Sync {
    fn bind_command<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
        binding: rss_mdm_registration_service::command_authority::CommandBinding,
    ) -> Pending<'a, ()>;

    fn installations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        reads: Vec<InstallationRead>,
    ) -> Pending<'a, BTreeMap<Uuid, Installation>>;

    fn observations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        reads: Vec<Read>,
    ) -> Pending<'a, BTreeMap<Uuid, Evidence>>;
    fn received<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a rss_mdm_registration_service::DevicePrincipal,
        session: u32,
        after: Option<Uuid>,
    ) -> Pending<'a, Vec<Uuid>>;
    fn settlement<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        id: Uuid,
        complete: bool,
    ) -> Pending<'a, rss_mdm_windows_mdm::native::receipt::Settlement>;
}
