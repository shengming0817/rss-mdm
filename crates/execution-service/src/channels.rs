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
    #[error("enrollment admission paused")]
    EnrollmentPaused,
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
    ) -> Pending<'a, WindowsCollections>;
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
    /// The configured provider belongs to the Windows channel owner.
    fn retirement_request(
        &self,
        purpose: rss_mdm_registration_service::Purpose,
    ) -> rss_mdm_windows_mdm::native::Request;
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
        user_key: String,
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
    fn reject_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        user_key: String,
        revision: i64,
        scope: String,
    ) -> Pending<'a, ()>;
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
    fn maintenance_due<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
    ) -> Pending<'a, bool>;
}
pub enum AppleEvidence {
    Declarations(Option<Box<rss_mdm_apple_mdm::native::evidence::DeclarationEvidence>>),
    Observations(Vec<rss_mdm_apple_mdm::native::evidence::Observation>),
}
pub trait AppleResults: Send + Sync {
    /// Correlate native PSSO readback before projecting a Password completion.
    /// Registration qualification deliberately does not require an already-Applied binding.
    fn platform_sso_observation<'a>(
        &'a self,
        c: &'a mut PgConnection,
        binding: &'a rss_mdm_registration_service::device_access::Binding,
        facts: &'a rss_mdm_agent_wire::runtime::AccessMacPlatformSsoFacts,
    ) -> Pending<'a, bool>;

    /// Bounded evidence for one authorized page; all native decoding stays with Apple.
    fn evidence_page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        requests: Vec<(Uuid, rss_mdm_apple_mdm::native::request::Request)>,
        native_values: bool,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, AppleEvidence>>;
    /// Purge input copies only after execution delivery settles and the material owner permits expiry.
    fn purge_credential_inputs<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
        terminal: bool,
    ) -> Pending<'a, bool>;
    /// Current-generation declaration keys, locked through the caller's evidence read.
    fn declaration_page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        generation: i64,
        after: Option<Uuid>,
        limit: usize,
    ) -> Pending<'a, Vec<(Uuid, String)>>;

    /// Check current-registration platform evidence without issuing a command.
    fn device_control_supported<'a>(
        &'a self,
        c: &'a mut PgConnection,
        target: AppleRegistration,
        action: crate::device_control::Kind,
        command: rss_mdm_apple_mdm::native::input::CommandInput,
    ) -> Pending<'a, bool>;
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
        source: &'a dyn crate::source_authority::SourceAuthority,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
    ) -> Pending<'a, AppleReception>;
}
pub enum AppleReception {
    Idle,
    Replay,
    Collection { facts: Vec<Fact>, run: Option<Uuid> },
    Command(Box<dyn AppleAttempt>),
}
pub struct AppleCommand {
    pub recovery: Option<std::sync::Arc<rss_mdm_recovery_credentials::Protection>>,
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
    /// Deliver device trust maintenance before business commands.
    fn trust<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
    ) -> Pending<'a, Reply>;
    fn collection<'a>(
        &'a self,
        source: &'a dyn crate::source_authority::SourceAuthority,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        user_key: &'a str,
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
    pub device: String,
    pub revision: i64,
    pub user_key: String,
    pub disposition: PushDisposition,
}
pub enum PushDisposition {
    Ready { token: Vec<u8>, magic: String },
    Inactive,
    Invalid { scope: String },
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
    pub execution_context: rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    pub platform: String,
    pub architecture: String,
    pub capabilities: Vec<rss_mdm_agent_wire::runtime::Capability>,
}
impl AgentBinding {
    pub fn inventory(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::InventoryCollectionV1)
    }
    pub fn script(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::TaskExecuteV1)
    }
    pub fn software(&self) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability.is_software())
    }
    pub fn enrollment(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::MdmEnrollmentV1)
    }
    pub fn native_collection(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::InventoryNativeV1)
    }
    pub fn task(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::runtime::Capability::DeviceUnmanageV1)
            || self
                .capabilities
                .contains(&rss_mdm_agent_wire::runtime::Capability::DeviceAccessV1)
            || self.script()
            || self.software()
            || self.enrollment()
            || self.native_collection()
            || self
                .capabilities
                .contains(&rss_mdm_agent_wire::runtime::Capability::CredentialsWindowsV1)
    }
}
pub trait Agent: Send + Sync {
    fn update_context<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        context: &'a rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    ) -> Pending<'a, ()>;
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
    context: &rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
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
    /// The native registration endpoint speaks the same closed Agent V1 errors.
    pub fn agent_error(self) -> (u16, rss_mdm_agent_wire::runtime::ErrorBody) {
        use rss_mdm_agent_wire::runtime::ErrorCode as C;
        let (status, code) = match self {
            Self::Malformed => (400, C::MalformedRequest),
            Self::Unauthorized => (401, C::InvalidIdentity),
            Self::Forbidden => (403, C::PermissionDenied),
            Self::Conflict => (409, C::OperationConflict),
            Self::CommitUnknown | Self::RollbackFailed => (503, C::OperationUnknown),
            _ => (503, C::ServiceUnavailable),
        };
        (status, rss_mdm_agent_wire::runtime::ErrorBody { code })
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
    pub facts: Vec<Fact>,
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
