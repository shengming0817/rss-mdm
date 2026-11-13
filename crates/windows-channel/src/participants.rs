//! Business capabilities borrowed by the Windows protocol owner.
use crate::Error;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_registration_service::DevicePrincipal;
use rss_transactional_messaging_postgres::PgTransaction;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
pub struct Operation {
    pub id: Uuid,
    pub request: rss_mdm_windows_mdm::native::Execution,
    pub user: bool,
    pub matches: bool,
    pub dispatch: bool,
    pub receipt: bool,
    pub observe: bool,
    pub replay: bool,
    pub software: bool,
    pub agent_minimum_os: Option<[u16; 4]>,
    pub minimum_os: Option<[u16; 4]>,
    pub observation: Option<rss_mdm_windows_mdm::native::Request>,
}
/// Native exchange phases; database values are decoded fail-closed.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptPhase {
    Prepare,
    Execute,
    Observe,
}
impl AttemptPhase {
    pub(crate) fn receipt_role(self) -> rss_mdm_windows_mdm::native::receipt::ReceiptRole {
        use rss_mdm_windows_mdm::native::receipt::ReceiptRole;
        match self {
            Self::Prepare => ReceiptRole::Prepare,
            Self::Execute => ReceiptRole::Execute,
            Self::Observe => ReceiptRole::Observe,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Execute => "execute",
            Self::Observe => "observe",
        }
    }
    pub fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "prepare" => Ok(Self::Prepare),
            "execute" => Ok(Self::Execute),
            "observe" => Ok(Self::Observe),
            _ => Err(Error::Unavailable(crate::Failure::Protocol)),
        }
    }
}
pub trait Business: Send + Sync {
    fn software_enabled(&self) -> bool;
    fn detection<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
    ) -> Pending<'a, DetectionCatalog>;
    fn prepare<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()>;
    #[allow(
        clippy::too_many_arguments,
        reason = "the protocol transaction borrows identity, audit and distinct settlement facts"
    )]
    fn finish<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        session: u32,
        complete: bool,
        authenticated: bool,
        retirement: rss_mdm_windows_mdm::native::Request,
        runs: Vec<Uuid>,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()>;
    fn candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, Vec<Operation>>;
    fn operation<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        id: Uuid,
    ) -> Pending<'a, Operation>;
    fn rejected<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        id: Uuid,
        reason: String,
        phase: Option<AttemptPhase>,
        context: Option<rss_mdm_windows_mdm::native::Context>,
    ) -> Pending<'a, ()>;
    fn wake_configuration<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, ()>;
    fn collection_eligible<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        id: Uuid,
        delivery: bool,
    ) -> Pending<'a, bool>;
    fn collection_plan<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        id: Uuid,
    ) -> Pending<'a, rss_mdm_windows_mdm::native::collection::Plan>;
    fn collection_sent<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        id: Uuid,
    ) -> Pending<'a, ()>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DetectionCatalog {
    pub identities: Vec<Identity>,
    pub win32: Vec<Win32Identity>,
    pub complete: bool,
    pub digest: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum Identity {
    WindowsMsi {
        product: Uuid,
        publisher: Option<String>,
    },
    WindowsMsix {
        family: String,
        identity: rss_mdm_resource::MsixIdentity,
        minimum_os: [u16; 4],
    },
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Win32Identity {
    pub key: String,
    pub publisher: Option<String>,
}
pub trait Departure: Send + Sync {
    fn departed<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        registration: rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, ()>;
}
pub trait WakeDemand: Send + Sync {
    fn candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        after: Option<rss_mdm_agent_wire::DeviceId>,
    ) -> Pending<'a, Vec<rss_mdm_agent_wire::DeviceId>>;
    fn pending<'a>(
        &'a self,
        c: &'a mut PgConnection,
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, bool>;
}
