//! Channel-owned protocol participants borrow the Execution-owned connection and cannot commit it.
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_registration_service::DevicePrincipal;
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Rejection>> + Send + 'a>>;
#[derive(Clone, Debug, thiserror::Error)]
pub enum Rejection {
    #[error("commit outcome unknown")]
    CommitUnknown,
    #[error("rollback unconfirmed")]
    RollbackFailed,
    #[error("audit isolation invalid")]
    AuditIsolation,
    #[error("audit admission rejected")]
    AuditAdmission,
    #[error("invalid protocol input")]
    Malformed,
    #[error("protocol identity rejected")]
    Unauthorized,
    #[error("protocol permission denied")]
    Forbidden,
    #[error("protocol state conflict")]
    Conflict,
    #[error("protocol storage unavailable")]
    Storage,
    #[error("protocol state invalid")]
    Protocol,
    #[error("protocol deadline exceeded")]
    Deadline,
    #[error("protocol audit integrity failure")]
    AuditIntegrity,
    #[error("protocol audit contract failure")]
    AuditContract,
    #[error("protocol audit unavailable")]
    Audit,
}
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
pub enum WindowsReception {
    Replay { reply: Reply, package: PackageState },
    Challenge(PreparedWindows),
    Authenticated(PreparedWindows),
}
/// Protocol preparation retains adapter-private session state without transferring its owner.
pub struct PreparedWindows {
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
    fn collect<'a>(
        &'a mut self,
        source: &'a dyn crate::source_authority::SourceAuthority,
        c: &'a mut PgConnection,
        key: &'a rss_mdm_native_protection::Protector,
        p: &'a DevicePrincipal,
        input: &'a rss_mdm_windows_mdm::syncml::Message,
        history: Option<&'a rss_mdm_windows_mdm::syncml::Expected>,
        response: &'a mut rss_mdm_windows_mdm::syncml::Message,
        dispatch: bool,
    ) -> Pending<'a, bool>;
    fn finish<'a>(
        self: Box<Self>,
        c: &'a mut PgConnection,
        key: &'a rss_mdm_native_protection::Protector,
        p: &'a DevicePrincipal,
        response: rss_mdm_windows_mdm::syncml::Message,
        package: PackageState,
        pending: bool,
    ) -> Pending<'a, Reply>;
}
pub trait Windows: Send + Sync {
    fn prepare<'a>(
        self: std::sync::Arc<Self>,
        connection: &'a mut PgConnection,
        protection: &'a rss_mdm_native_protection::Protector,
        principal: &'a DevicePrincipal,
        message: &'a rss_mdm_windows_mdm::syncml::Message,
        bytes: &'a [u8],
        audit: &'a RequestAudit,
    ) -> Pending<'a, WindowsReception>;
}

use uuid::Uuid;
pub struct Observation {
    pub phase: rss_mdm_apple_mdm::native::evidence::Phase,
    pub state: rss_mdm_apple_mdm::native::evidence::ReceiptState,
    pub fields: Option<rss_mdm_apple_mdm::native::input::Fields>,
    pub error: Option<rss_mdm_apple_mdm::native::input::Fields>,
    pub profile: Option<rss_mdm_apple_mdm::native::profiles::Verification>,
    pub application: Option<rss_mdm_apple_mdm::software::Presence>,
    pub received_at: Option<i64>,
    pub accepted: bool,
    pub native_outcome: Option<rss_mdm_apple_mdm::native::outcome::Outcome>,
}
pub struct AppleRegistration {
    pub tenant: String,
    pub device: String,
    pub registration: uuid::Uuid,
    pub generation: i64,
}
pub trait AppleProfiles: Send + Sync {
    fn declaration_candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        user: &'a str,
    ) -> Pending<'a, Vec<Uuid>>;

    fn previous_declarations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
        user: String,
        owner: String,
    ) -> Pending<'a, Vec<Uuid>>;

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
pub trait AppleCollections: Send + Sync {
    fn prepare_native_collection<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        id: Uuid,
    ) -> Pending<'a, Vec<Fact>>;
    fn pending_collections<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        limit: usize,
    ) -> Pending<'a, Vec<PendingCollection>>;
}
pub trait ApplePush: Send + Sync {
    fn needs_prerequisites<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
    ) -> Pending<'a, bool>;
    fn push_due<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        configuration: [u8; 32],
    ) -> Pending<'a, bool>;
    fn push_candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        configuration: [u8; 32],
    ) -> Pending<'a, Vec<PushCandidate>>;
    fn defer_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        user_key: String,
    ) -> Pending<'a, ()>;
    fn lease_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        wake: Uuid,
        registration: Uuid,
        user_key: String,
        configuration: [u8; 32],
    ) -> Pending<'a, ()>;
    fn settle_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        wake: Wake,
        status: Option<u16>,
        outcome: PushOutcome,
    ) -> Pending<'a, Option<u64>>;
    fn renewal_due<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
    ) -> Pending<'a, bool>;
}
pub trait AppleResults: Send + Sync {
    /// Server publication withdrawal is distinct from native object absence.
    fn withdrawal_published<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
    ) -> Pending<'a, bool>;

    fn declarations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
        native_values: bool,
    ) -> Pending<'a, Option<serde_json::Value>>;

    fn observations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
        request: rss_mdm_apple_mdm::native::request::Request,
        native_values: bool,
    ) -> Pending<'a, Vec<Observation>>;
}
pub trait AppleAttempt: Send {
    fn operation(&self) -> Option<Uuid>;
    fn settle<'a>(
        self: Box<Self>,
        c: &'a mut PgConnection,
        accepted: bool,
        command: AppleCommand,
        target: AppleRegistration,
    ) -> Pending<'a, rss_mdm_apple_mdm::native::evidence::Settlement>;
}
/// An already decoded protocol request; only the channel can inspect its native content.
pub trait AppleExchange: Send {
    fn user_key(&self) -> &str;
    fn current<'a>(&'a self, c: &'a mut PgConnection, p: &'a DevicePrincipal) -> Pending<'a, ()>;
    fn reception<'a>(
        self: Box<Self>,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, AppleReception>;
}
pub enum AppleReception {
    Idle,
    Replay,
    Collection(Vec<Fact>),
    Command(Box<dyn AppleAttempt>),
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
/// Native applicability failures are operation evidence, not a failed device connection.
pub enum AppleDispatch {
    Ready(Vec<u8>),
    Waiting,
    Rejected(rss_mdm_apple_mdm::native::Error),
}
impl From<Option<Vec<u8>>> for AppleDispatch {
    fn from(value: Option<Vec<u8>>) -> Self {
        match value {
            Some(bytes) => Self::Ready(bytes),
            None => Self::Waiting,
        }
    }
}
pub trait Apple: Send + Sync {
    fn current<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        udid: &'a str,
        user_key: &'a str,
    ) -> Pending<'a, ()>;
    fn command<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        command: &'a AppleCommand,
    ) -> Pending<'a, AppleDispatch>;
    fn prerequisites<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        command: &'a AppleCommand,
    ) -> Pending<'a, AppleDispatch>;
    fn collection<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, Reply>;
}

#[derive(Clone)]
pub struct Wake {
    pub id: Uuid,
    pub registration: Uuid,
    pub revision: i64,
    pub user_key: String,
    pub token: Vec<u8>,
    pub magic: String,
}
pub struct PushCandidate {
    pub registration: Uuid,
    pub revision: i64,
    pub user_key: String,
    pub token: Vec<u8>,
    pub magic: String,
}
pub struct PendingCollection {
    pub id: Uuid,
}
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PushOutcome {
    Accepted,
    Retryable,
    Unregistered,
    Rejected,
}
impl PushOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Retryable => "retryable",
            Self::Unregistered => "unregistered",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone)]
pub struct AgentBinding {
    pub execution_context: rss_mdm_agent_wire::SoftwareExecutionContext,
    pub platform: String,
    pub architecture: String,
    pub capabilities: Vec<rss_mdm_agent_wire::Capability>,
}
impl AgentBinding {
    pub fn inventory(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::Capability::InventoryCollectionV6)
    }
    pub fn script(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::Capability::TaskExecuteV6)
    }
    pub fn software(&self) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability.is_software())
    }
    pub fn enrollment(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::Capability::MdmEnrollmentV6)
    }
    pub fn task(&self) -> bool {
        self.script() || self.software() || self.enrollment()
    }
}
pub trait Agent: Send + Sync {
    fn update_context<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        context: &'a rss_mdm_agent_wire::SoftwareExecutionContext,
    ) -> Pending<'a, ()>;
    fn managed_replay<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        input: &'a rss_mdm_agent_wire::ManagedRegistrationRequest,
        audit: &'a RequestAudit,
    ) -> Pending<'a, Option<rss_mdm_agent_wire::RegistrationReceipt>>;
    fn managed_register<'a>(
        &'a self,
        c: &'a mut PgConnection,
        authority: rss_mdm_registration_service::enrollment::managed::Authority,
        input: &'a rss_mdm_agent_wire::ManagedRegistrationRequest,
        audit: &'a RequestAudit,
    ) -> Pending<'a, rss_mdm_agent_wire::RegistrationReceipt>;

    fn bindings<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registrations: Vec<Uuid>,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, AgentBinding>>;
    fn binding<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
    ) -> Pending<'a, Option<AgentBinding>> {
        Box::pin(async move {
            Ok(self
                .bindings(c, tenant, vec![registration])
                .await?
                .remove(&registration))
        })
    }
}
pub async fn agent_binding_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    store: std::sync::Arc<dyn Agent>,
    registration: Uuid,
) -> crate::transaction::Result<Option<AgentBinding>> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(store.binding(c, tenant, registration).await) })
        })
        .await?
        .map_err(crate::Error::from)?)
}

pub async fn agent_context_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    store: std::sync::Arc<dyn Agent>,
    registration: Uuid,
    context: &rss_mdm_agent_wire::SoftwareExecutionContext,
) -> crate::transaction::Result<()> {
    let tenant = tx.tenant_id().to_string();
    let context = context.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(store
                .update_context(c, tenant, registration, &context)
                .await)
        })
    })
    .await?
    .map_err(crate::Error::from)?;
    Ok(())
}

pub struct RegisteredAgent {
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
    pub binding: AgentBinding,
}
pub async fn agent_targets_in(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    store: std::sync::Arc<dyn Agent>,
    devices: Vec<String>,
) -> crate::transaction::Result<Vec<RegisteredAgent>> {
    let tenant = tx.tenant_id().to_string();
    let registrations = tx
        .with_connection(move |c| {
            Box::pin(async move {
                rss_mdm_registration_service::device::read::active_channel_in(
                    c,
                    tenant,
                    devices,
                    rss_mdm_inventory::Channel::Agent,
                    rss_mdm_registration_service::Purpose::Primary,
                )
                .await
            })
        })
        .await?;
    let ids = registrations.iter().map(|(_, id, _)| *id).collect();
    let tenant = tx.tenant_id().to_string();
    let bindings = tx
        .with_connection(move |c| Box::pin(async move { Ok(store.bindings(c, tenant, ids).await) }))
        .await?
        .map_err(crate::Error::from)?;
    Ok(registrations
        .into_iter()
        .filter_map(|(device, registration, generation)| {
            bindings
                .get(&registration)
                .cloned()
                .map(|binding| RegisteredAgent {
                    device,
                    registration,
                    generation,
                    binding,
                })
        })
        .collect())
}

impl Rejection {
    /// The native registration endpoint speaks the same closed Agent V6 errors.
    pub fn agent_error(self) -> (u16, rss_mdm_agent_wire::ErrorBody) {
        use rss_mdm_agent_wire::ErrorCode as C;
        let (status, code) = match self {
            Self::Malformed => (400, C::MalformedRequest),
            Self::Unauthorized => (401, C::InvalidIdentity),
            Self::Forbidden => (403, C::PermissionDenied),
            Self::Conflict => (409, C::OperationConflict),
            Self::CommitUnknown | Self::RollbackFailed => (503, C::OperationUnknown),
            _ => (503, C::ServiceUnavailable),
        };
        (status, rss_mdm_agent_wire::ErrorBody { code })
    }
}

/// A native check-in participant retains protocol bytes at the channel owner.
pub trait AppleDdmExchange: Send {
    fn user_key(&self) -> &str;
    fn current<'a>(&'a self, c: &'a mut PgConnection, p: &'a DevicePrincipal) -> Pending<'a, ()>;
    fn candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, Vec<Uuid>>;
    fn respond<'a>(
        self: Box<Self>,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        authorized: Vec<Uuid>,
    ) -> Pending<'a, AppleDdmReply>;
}
pub struct AppleDdmReply {
    pub status: u16,
    pub bytes: Vec<u8>,
    pub synchronized: Vec<Uuid>,
}

pub trait AppleAssetRead: Send + Sync {
    fn binding<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, Option<rss_mdm_apple_mdm::native::ddm::AssetBinding>>;
}
