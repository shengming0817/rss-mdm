//! Windows-owned session and delivery coordinates.
use crate::participants::Pending;
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_registration_service::DevicePrincipal;
use sqlx::PgConnection;
pub struct Reply {
    pub bytes: Vec<u8>,
    pub facts: Vec<Fact>,
}
/// Packet completeness is independent of command receipts and effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageState {
    Partial,
    Complete,
    Aborted,
}
/// Host ingress lease; only the protocol owner can complete authenticated admission.
pub trait ManagementIngress: Send + Sync {
    fn authenticated(&self, principal: &DevicePrincipal) -> Result<(), std::time::Duration>;
}
/// A settled protocol response or admission refusal before business writes.
pub enum ManagementReply {
    Response(Vec<u8>),
    Limited(std::time::Duration),
}
pub enum WindowsReception {
    Limited(std::time::Duration),
    Replay { reply: Reply, package: PackageState },
    Challenge(PreparedWindows),
    Authenticated(PreparedWindows),
}
/// Protocol preparation retains adapter-private session state without transferring its owner.
pub struct PreparedWindows {
    /// Authenticated and correlated peer request to end further dispatch.
    pub stopped: bool,
    pub declared_summaries: Vec<rss_mdm_windows_mdm::native::declared::Summary>,
    pub provider_id: String,
    pub management_urls: Vec<String>,
    pub user_available: bool,
    pub input: rss_mdm_windows_mdm::syncml::Message,
    pub history: Option<rss_mdm_windows_mdm::syncml::Expected>,
    pub response: rss_mdm_windows_mdm::syncml::Message,
    pub controls: Vec<rss_mdm_windows_mdm::syncml::Command>,
    pub continuing: Vec<rss_mdm_windows_mdm::syncml::Reference>,
    pub limits: rss_mdm_windows_mdm::CodecLimits,
    pub package: PackageState,
    pub session: Box<dyn WindowsSession>,
}
/// Native runs processed by this request, returned by the protocol correlation owner.
pub struct WindowsCollections {
    pub pending: bool,
    pub runs: Vec<uuid::Uuid>,
}
/// One request's channel participant. Every method borrows the original transaction.
pub trait WindowsSession: Send {
    /// Channel-owned prerequisite reads can authorize a further bounded data fragment.
    fn result_eligible<'a>(
        &'a self,
        c: &'a mut PgConnection,
        key: &'a rss_mdm_native_protection::Protector,
        p: &'a DevicePrincipal,
        session: u32,
        reference: &'a rss_mdm_windows_mdm::syncml::Reference,
    ) -> Pending<'a, Option<bool>> {
        let _ = (c, key, p, session, reference);
        Box::pin(async { Ok(None) })
    }
    #[allow(clippy::too_many_arguments)]
    fn receive<'a>(
        &'a mut self,
        source: &'a dyn crate::participants::Business,
        c: &'a mut PgConnection,
        key: &'a rss_mdm_native_protection::Protector,
        p: &'a DevicePrincipal,
        input: &'a rss_mdm_windows_mdm::syncml::Message,
        history: Option<&'a rss_mdm_windows_mdm::syncml::Expected>,
    ) -> Pending<'a, WindowsCollections>;
    fn send<'a>(
        &'a mut self,
        source: &'a dyn crate::participants::Business,
        c: &'a mut PgConnection,
        key: &'a rss_mdm_native_protection::Protector,
        p: &'a DevicePrincipal,
        response: &'a mut rss_mdm_windows_mdm::syncml::Message,
    ) -> Pending<'a, bool>;
    fn finish<'a>(
        self: Box<Self>,
        c: &'a mut PgConnection,
        key: &'a rss_mdm_native_protection::Protector,
        p: &'a DevicePrincipal,
        response: Vec<u8>,
        package: PackageState,
        pending: bool,
    ) -> Pending<'a, Reply>;
}
/// Authenticated transport identity and the exact bytes decoded as this message.
#[derive(Clone, Copy)]
pub struct WindowsInput<'a> {
    pub principal: &'a DevicePrincipal,
    pub message: &'a rss_mdm_windows_mdm::syncml::Message,
    pub bytes: &'a [u8],
}
pub trait Windows: Send + Sync {
    /// The configured provider belongs to the Windows channel owner.
    fn retirement_request(
        &self,
        purpose: rss_mdm_registration_service::Purpose,
    ) -> Result<rss_mdm_windows_mdm::native::Request, crate::Error>;
    fn prepare<'a>(
        self: std::sync::Arc<Self>,
        connection: &'a mut PgConnection,
        protection: &'a rss_mdm_native_protection::Protector,
        input: WindowsInput<'a>,
        audit: &'a RequestAudit,
        ingress: &'a dyn ManagementIngress,
    ) -> Pending<'a, WindowsReception>;
}
