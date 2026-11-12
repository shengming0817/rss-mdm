//! Product-owned receipt namespaces. Locators are evidence, never authority.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Each variant identifies an actual product owner's persistent namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationOwner {
    DeviceManagement,
    DeviceControl,
    DeviceAction,
    DeviceControlRequest,
    Retirement,
    Registration,
    AgentConfiguration,
    RegistrationRecovery,
    Installation,
    EnrollmentTask,
    Policy,
    PolicyEvent,
    PolicyEventMember,
    PolicyWork,
    Configuration,
    Group,
    GroupTask,
    Scope,
    ScopeTask,
    Compliance,
    ComplianceTask,
    Asset,
    AssetQuery,
    Collection,
    CollectionExecution,
    Script,
    ScriptInvocation,
    SoftwareInvocation,
    EnrollmentInvocation,
    Resource,
    Content,
    StorageConnection,
    StorageMigration,
    SoftwareCatalog,
    SoftwarePublication,
    SoftwareSourceSnapshot,
    SoftwareDeployment,
    SoftwareAction,
    Filevault,
    RecoveryCommand,
    CredentialTask,
    DeviceAccess,
    EnterpriseConfiguration,
    DaPublication,
    DaConfigurationExport,
    AgentDelivery,
    DeviceAccessTask,
    CertificateArchive,
    Pki,
    PkiSigning,
    PkiRevocation,
    Authorization,
    TaskTrust,
    Smtp,
    Webhook,
    Telemetry,
    FirstUse,
    UserProfile,
    TenantAdministration,
    Initialization,
    AppleAde,
    AppleRuntimeMaterial,
    AppleAccountEnrollment,
    WindowsWns,
}
impl OperationOwner {
    pub const fn invocation(self) -> bool {
        matches!(
            self,
            Self::ScriptInvocation | Self::SoftwareInvocation | Self::EnrollmentInvocation
        )
    }

    /// Receipt namespaces that include the authenticated author (and, where stored, instance).
    pub const fn actor_bound(self) -> bool {
        matches!(
            self,
            Self::Resource
                | Self::Scope
                | Self::Group
                | Self::Asset
                | Self::Authorization
                | Self::Registration
                | Self::AgentConfiguration
                | Self::RegistrationRecovery
                | Self::DeviceManagement
                | Self::DeviceControlRequest
                | Self::SoftwarePublication
                | Self::SoftwareSourceSnapshot
                | Self::Content
                | Self::Pki
                | Self::FirstUse
                | Self::UserProfile
                | Self::DeviceAccess
                | Self::EnterpriseConfiguration
                | Self::DaPublication
                | Self::AgentDelivery
                | Self::CertificateArchive
                | Self::PolicyEvent
        )
    }
}

/// Tenant and storage profile are supplied by the verified request, never this value.
/// Actor and instance identify the original namespace; they cannot impersonate its owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationLocator {
    pub product: crate::StorageProfile,
    pub owner: OperationOwner,
    pub operation_id: Uuid,
    pub actor: Option<String>,
    pub instance: Option<Uuid>,
    pub target: Option<String>,
    pub device: Option<rss_mdm_agent_wire::DeviceId>,
}
impl OperationLocator {
    pub(crate) fn from_snapshot(
        product: crate::StorageProfile,
        owner: OperationOwner,
        snapshot: &crate::Snapshot,
    ) -> Result<Option<Self>, crate::InvalidFact> {
        let Some(operation_id) = snapshot.operation_id else {
            return Ok(None);
        };
        if operation_id.is_nil() {
            return Err(crate::InvalidFact::Coordinates);
        }
        Ok(Some(Self {
            product,
            owner,
            operation_id,
            actor: if owner.invocation() {
                Some(
                    snapshot
                        .receipt_actor
                        .clone()
                        .filter(|v| !v.is_empty() && v.len() <= 256)
                        .ok_or(crate::InvalidFact::Coordinates)?,
                )
            } else {
                owner
                    .actor_bound()
                    .then(|| snapshot.actor.clone())
                    .flatten()
            },
            instance: snapshot
                .instance
                .as_deref()
                .filter(|_| owner.actor_bound())
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|_| crate::InvalidFact::Coordinates)?,
            target: snapshot.target.clone(),
            device: snapshot.device_target,
        }))
    }
}

/// Safe facts selected by a receipt's owner, never an arbitrary stored JSON document.
/// `state` retains that owner's vocabulary; it is not a cross-domain state machine.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptSummary {
    pub operation_id: Uuid,
    pub object: Option<String>,
    pub revision: Option<i64>,
    pub state: Option<String>,
    pub accepted: Option<bool>,
    pub enabled: Option<bool>,
    pub recorded_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub executions: Vec<Uuid>,
    pub stages: Vec<ReceiptStage>,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptStage {
    pub phase: String,
    pub revision: Option<i64>,
    pub state: Option<String>,
}
impl ReceiptSummary {
    pub fn new(operation_id: Uuid) -> Self {
        Self {
            operation_id,
            object: None,
            revision: None,
            state: None,
            accepted: None,
            enabled: None,
            recorded_at: None,
            completed_at: None,
            executions: Vec::new(),
            stages: Vec::new(),
        }
    }
}
