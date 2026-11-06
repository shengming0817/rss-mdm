//! Windows evidence consumed by business reducers and authorized query projections.
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::{collections::BTreeMap, future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, crate::control::Error>> + Send + 'a>>;
pub struct Read {
    pub id: Uuid,
    pub registration: Uuid,
    pub registration_generation: i64,
    pub request: rss_mdm_windows_mdm::native::Execution,
    pub values: bool,
}
pub struct Evidence {
    pub receipts: Vec<crate::control::queries::records::WindowsReceipt>,
    pub assessment: rss_mdm_windows_mdm::native::verification::EffectAssessment,
}
pub trait Store: Send + Sync {
    fn control_applicability<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        checks: Vec<(usize, Uuid, i64, rss_mdm_windows_mdm::native::Request)>,
    ) -> Pending<'a, BTreeMap<usize, crate::control::device_control::Applicability>>;

    fn sent<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
        ids: Vec<Uuid>,
    ) -> Pending<'a, std::collections::BTreeSet<Uuid>>;

    fn bind_command<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
        binding: rss_mdm_registration_service::command_authority::CommandBinding,
    ) -> Pending<'a, ()>;

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
