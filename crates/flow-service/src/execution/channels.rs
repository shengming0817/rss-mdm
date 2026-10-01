//! Channel-owned protocol participants borrow the Flow-owned connection and cannot commit it.
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
pub trait Windows: Send + Sync {
    fn exchange<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        principal: &'a DevicePrincipal,
        message: &'a rss_mdm_windows_mdm::syncml::Message,
        bytes: &'a [u8],
        audit: &'a RequestAudit,
    ) -> Pending<'a, Reply>;
}

use rss_mdm_apple_mdm::protocol::Status;
use uuid::Uuid;
pub struct Observation {
    pub phase: String,
    pub state: String,
    pub response: Option<Vec<u8>>,
    pub received_at: Option<i64>,
}
pub trait AppleStore: Send + Sync {
    fn prepare_native_collection<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        id: Uuid,
    ) -> Pending<'a, Vec<Fact>>;
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
    ) -> Pending<'a, ()>;
    fn lease_push<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        wake: Uuid,
        registration: Uuid,
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
    fn pending_collections<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        limit: usize,
    ) -> Pending<'a, Vec<PendingCollection>>;
    fn defer_collection<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        collection: Uuid,
    ) -> Pending<'a, ()>;
    fn observations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
    ) -> Pending<'a, Vec<Observation>>;
}
pub enum Reception {
    Replay,
    Ready(Box<dyn AppleAttempt>),
}
pub trait AppleAttempt: Send {
    fn operation(&self) -> Option<Uuid>;
    fn phase(&self) -> &str;
    fn settle<'a>(self: Box<Self>, c: &'a mut PgConnection, status: Status) -> Pending<'a, ()>;
}
#[derive(Clone)]
pub enum NativeTask {
    Install {
        enabled: bool,
    },
    AgentInstall {
        bundle: String,
        version: String,
        url: String,
        sha256: [u8; 32],
    },
    Remove,
}
pub struct AppleCommand {
    pub operation: Uuid,
    pub deadline: i64,
    pub task: NativeTask,
}
pub trait Apple: Send + Sync {
    fn current<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        udid: &'a str,
    ) -> Pending<'a, ()>;
    fn collect<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        id: Uuid,
        status: Status,
        dictionary: &'a plist::Dictionary,
        bytes: &'a [u8],
    ) -> Pending<'a, (bool, Vec<Fact>)>;
    fn lock_attempt<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        id: Uuid,
        bytes: &'a [u8],
    ) -> Pending<'a, Option<Reception>>;
    fn command<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        command: &'a AppleCommand,
    ) -> Pending<'a, Option<Vec<u8>>>;
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
    pub token: Vec<u8>,
    pub magic: String,
}
pub struct PushCandidate {
    pub registration: Uuid,
    pub revision: i64,
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
    pub platform: String,
    pub architecture: String,
    pub capabilities: Vec<rss_mdm_agent_wire::Capability>,
}
impl AgentBinding {
    pub fn inventory(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::Capability::InventoryCollectionV5)
    }
    pub fn script(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::Capability::TaskExecuteV5)
    }
    pub fn software(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::Capability::SoftwareExecuteV5)
    }
    pub fn enrollment(&self) -> bool {
        self.capabilities
            .contains(&rss_mdm_agent_wire::Capability::MdmEnrollmentV5)
    }
    pub fn task(&self) -> bool {
        self.script() || self.software() || self.enrollment()
    }
}
pub trait Agent: Send + Sync {
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
    /// The native registration endpoint speaks the same closed Agent V4 errors.
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
