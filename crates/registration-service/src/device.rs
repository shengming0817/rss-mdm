//! Product gateway seam. F04 owns cryptographic verification; I01 owns persistent binding.
//! No network DTO can construct credential evidence or a device principal.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
pub mod coordinates;
pub mod directory;
pub mod endpoints;
pub mod linked;
mod management;
pub mod read;
pub mod registration_user;
pub mod store;
use crate::{Error, Store, device::coordinates::Coordinates};

use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_observation::{Epoch, Id, Registration, Scope};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use uuid::Uuid;

use rss_mdm_inventory::{Channel, ReportSource};
/// Registration authority purpose. WinDC never publishes Inventory observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Primary,
    WindowsDeclared,
    DaDevice,
}
impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::WindowsDeclared => "windows_declared",
            Self::DaDevice => "da_device",
        }
    }
    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "primary" => Ok(Self::Primary),
            "windows_declared" => Ok(Self::WindowsDeclared),
            "da_device" => Ok(Self::DaDevice),
            _ => Err(Error::Storage),
        }
    }
}
/// Evidence from a trusted channel verifier, not a credential ID submitted by a device.
/// I01 has no production constructor. F04 must verify the actual channel credential first.
/// ```compile_fail
/// let proof: rss_mdm_registration_service::VerifiedChannelCredential = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// let proof = rss_mdm_registration_service::VerifiedChannelCredential::new("fingerprint");
/// ```
pub struct VerifiedChannelCredential {
    profile: rss_mdm_install_support::StorageProfile,
    tenant: TenantId,
    channel: Channel,
    source: ReportSource,
    locator: [u8; 32],
    purpose: Purpose,
}
/// A composition-time authority bound to one tenant and report source.
#[derive(Clone)]
pub struct ChannelMount {
    profile: rss_mdm_install_support::StorageProfile,
    tenant: TenantId,
    source: ReportSource,
    purpose: Purpose,
}
impl ChannelMount {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn new(
        profile: rss_mdm_install_support::StorageProfile,
        tenant: TenantId,
        source: ReportSource,
        purpose: Purpose,
    ) -> Self {
        Self {
            profile,
            tenant,
            source,
            purpose,
        }
    }
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn credential(&self, locator: [u8; 32]) -> Result<VerifiedChannelCredential, Error> {
        if self.source.channel() != Channel::Mdm {
            return Err(Error::Forbidden);
        }
        Ok(VerifiedChannelCredential {
            profile: self.profile,
            tenant: self.tenant,
            channel: self.source.channel(),
            source: self.source,
            locator,
            purpose: self.purpose,
        })
    }
}
/// Registration identity is independent of Inventory transport channels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationKind {
    Agent,
    NativeMdm,
    DaDevice,
}
impl RegistrationKind {
    pub fn channel(self) -> Option<Channel> {
        match self {
            Self::Agent => Some(Channel::Agent),
            Self::NativeMdm => Some(Channel::Mdm),
            Self::DaDevice => None,
        }
    }
    pub(crate) fn from_channel(channel: Channel) -> Self {
        match channel {
            Channel::Agent => Self::Agent,
            Channel::Mdm => Self::NativeMdm,
        }
    }
    pub(crate) fn lock_name(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::NativeMdm => "mdm",
            Self::DaDevice => "da_device",
        }
    }
}
/// Closed actual consumers, selected by services rather than HTTP request strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumerUse {
    AgentTask,
    DaConfiguration,
}
impl ConsumerUse {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentTask => "agent_task",
            Self::DaConfiguration => "da_configuration",
        }
    }
}
/// Only current credentials and enabled sources define a use's consumers.
pub async fn consumers_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    usage: ConsumerUse,
) -> Result<Vec<String>, Error> {
    consumers_for_device_in(profile, c, tenant, usage, None).await
}
/// Current consumers for one endpoint, using the same registration-owned eligibility rule.
pub async fn consumers_for_device_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    usage: ConsumerUse,
    device: Option<&str>,
) -> Result<Vec<String>, Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_trust_consumers)
        .bind(tenant.to_string())
        .bind(usage.as_str())
        .bind(device)
        .fetch_all(c)
        .await
        .map_err(crate::database::db)
}

/// Immutable request-scoped identity resolved from the authoritative registration mapping.
/// ```compile_fail
/// let proof: rss_mdm_registration_service::DevicePrincipal = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone)]
pub struct DevicePrincipal {
    profile: rss_mdm_install_support::StorageProfile,
    tenant: TenantId,
    device: String,
    kind: RegistrationKind,
    installation: Uuid,
    credential: Uuid,
    enrolled_user: bool,
    purpose: Purpose,
    protocol_request: Option<Uuid>,
    epoch: Uuid,
}
impl DevicePrincipal {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    /// WinDC context is identified by its enrollment request, within this device.
    pub fn protocol_request(&self) -> Option<Uuid> {
        self.protocol_request
    }
    pub fn epoch(&self) -> Uuid {
        self.epoch
    }
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn device(&self) -> &str {
        &self.device
    }
    pub fn kind(&self) -> RegistrationKind {
        self.kind
    }
    pub fn installation(&self) -> Uuid {
        self.installation
    }
    pub fn channel(&self) -> Option<Channel> {
        self.kind.channel()
    }
    pub fn require_channel(&self) -> Result<Channel, Error> {
        self.channel().ok_or(Error::Forbidden)
    }
    /// Full enrollment permits only its enrolled-user scope; this is not an OS or organization identity.
    pub fn enrolled_user(&self) -> bool {
        self.enrolled_user
    }
    pub fn credential(&self) -> Uuid {
        self.credential
    }
}
/// Product-internal operation, not an Agent wire schema. No tenant/device overrides.
#[derive(Clone, Debug, Serialize)]
pub struct BindRegistration {
    pub operation_id: Uuid,
    pub request_id: Uuid,
    pub source: ReportSource,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationReceipt {
    pub operation_id: Uuid,
    pub request_id: Uuid,
    pub device: String,
    pub channel: Channel,
    pub credential: Uuid,
    pub epoch: Uuid,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationReceipt {
    pub operation_id: Uuid,
    pub device: String,
}

/// App-owned service; the router and trusted channel adapters share the same policy/store.
/// The caller retains ownership of both pools; this service creates or closes none.
pub struct DeviceService {
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    access: Arc<Store>,
    tenant: String,
}
impl DeviceService {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.access.profile()
    }
    pub fn retirement(&self) -> &dyn crate::Retirement {
        self.access.retirement.as_ref()
    }
    pub fn new(
        access: Arc<Store>,
        tenant: String,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    ) -> Self {
        Self {
            access,
            tenant,
            audit_store,
        }
    }
    pub fn retirement_budget(&self) -> rss_mdm_audit_integration::budget::AuditBudget {
        rss_mdm_audit_integration::budget::AuditBudget::retirement(None)
    }

    /// Resolve one committed identity snapshot without waiting for channel writers.
    /// Consumers recheck this principal under their existing mutation locks.
    pub async fn management_principal(
        &self,
        credential: &VerifiedChannelCredential,
    ) -> Result<DevicePrincipal, Error> {
        let profile = self.profile();

        if self.profile() != credential.profile || self.tenant != credential.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let mut tx = self.access.snapshot(&self.tenant).await?;
        let principal = management::read(profile, &mut tx, credential).await?;
        tx.commit().await.map_err(crate::database::db)?;
        Ok(principal)
    }
}
pub fn scope(
    profile: rss_mdm_install_support::StorageProfile,
    tenant: TenantId,
    device: &str,
    source: &str,
    epoch: Uuid,
) -> Result<Scope, DeviceError> {
    scope_dataset(
        profile,
        tenant,
        device,
        source,
        epoch,
        rss_mdm_inventory::DATASET,
    )
}
pub fn scope_dataset(
    profile: rss_mdm_install_support::StorageProfile,
    tenant: TenantId,
    device: &str,
    source: &str,
    epoch: Uuid,
    dataset: &str,
) -> Result<Scope, DeviceError> {
    Ok(Scope::new(
        tenant,
        // Lifecycle CAS is object-wide. Each independently activated fixed dataset
        // has its own subject within the device. The library Registration wrapper carries deviceId.
        Id::new(if dataset == rss_mdm_inventory::DATASET {
            match profile {
                rss_mdm_install_support::StorageProfile::Mdm => device.to_owned(),
                rss_mdm_install_support::StorageProfile::Da => format!("da:{device}"),
            }
        } else {
            match profile {
                rss_mdm_install_support::StorageProfile::Mdm => format!("{device}:{dataset}"),
                rss_mdm_install_support::StorageProfile::Da => {
                    format!("da:{device}:{dataset}")
                }
            }
        })
        .map_err(|_| DeviceError::InvalidSource)?,
        Registration::new(device.to_owned()).map_err(|_| DeviceError::InvalidSource)?,
        Id::new(source).map_err(|_| DeviceError::InvalidSource)?,
        Id::new(dataset).map_err(|_| DeviceError::InvalidSource)?,
        Epoch::new(epoch.to_string()).map_err(|_| DeviceError::InvalidSource)?,
    ))
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("invalid source identity")]
    InvalidSource,
}

use rss_mdm_audit_integration::RequestAudit;

impl VerifiedChannelCredential {
    pub fn channel(&self) -> Channel {
        self.channel
    }
}
impl DeviceService {
    #[allow(
        clippy::too_many_arguments,
        reason = "all inputs are checked inside the existing registration transaction"
    )]
    pub async fn bind_in(
        &self,
        tx: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        credential: &VerifiedChannelCredential,
        command: &BindRegistration,
        device: String,
        ids: [Uuid; 2],
    ) -> Result<RegistrationReceipt, Error> {
        let profile = self.profile();

        store::bind_in(profile, tx, proof, credential, command, device, ids).await
    }
    /// Both native authority kinds enter the same registration mutation after live admission.
    #[allow(
        clippy::too_many_arguments,
        reason = "one borrowed registration transaction"
    )]
    pub async fn bind_native_in(
        &self,
        tx: &mut sqlx::PgConnection,
        admission: &crate::enrollment::native::Admission,
        credential: &VerifiedChannelCredential,
        ids: [Uuid; 2],
    ) -> Result<RegistrationReceipt, Error> {
        let profile = self.profile();

        store::bind_native_in(profile, tx, admission, credential, ids).await
    }
}

/// Resolve an Agent only from the certificate owner's sealed TLS verification result.
pub async fn authenticate_endpoint_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    peer: &rss_mdm_device_trust::device_identity::VerifiedDevicePeer,
) -> Result<DevicePrincipal, Error> {
    use crate::database::db;
    use rss_mdm_agent_wire::enroll::ErrorCode as C;
    use sqlx::Row;
    let installation = installation_in(profile, c).await?;
    if peer.metadata().service_id != installation
        || peer.metadata().tenant.to_string() != tenant.to_string()
    {
        return Err(Error::Unauthorized);
    }
    let (kind, purpose) = match peer.metadata().purpose {
        rss_mdm_agent_wire::pki::Purpose::Agent => (RegistrationKind::Agent, Purpose::Primary),
        rss_mdm_agent_wire::pki::Purpose::DaDevice => {
            (RegistrationKind::DaDevice, Purpose::DaDevice)
        }
        _ => return Err(Error::Unauthorized),
    };
    let fingerprint: String = peer
        .metadata()
        .fingerprint
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let row = sqlx::query(crate::storage_profile::sql(profile).device_authenticate_endpoint_in_1)
        .bind(tenant.to_string())
        .bind(fingerprint)
        .bind(purpose.as_str())
        .fetch_optional(&mut *c)
        .await
        .map_err(db)?
        .ok_or(Error::Unauthorized)?;
    let device: String = row.try_get("device").map_err(db)?;
    store::lock_registration(profile, c, &tenant.to_string(), &device, kind).await?;
    let p = DevicePrincipal {
        profile,
        tenant,
        device,
        epoch: row.try_get("epoch").map_err(db)?,
        credential: row.try_get("credential").map_err(db)?,
        kind,
        installation,
        purpose,
        protocol_request: None,
        enrolled_user: false,
    };
    if row.try_get::<String, _>("identity").map_err(db)? != peer.metadata().identity {
        return Err(Error::Unauthorized);
    }
    match row
        .try_get::<String, _>("credential_state")
        .map_err(db)?
        .as_str()
    {
        "revoked" => return Err(Error::Agent(C::CredentialRevoked)),
        "superseded" => return Err(Error::Agent(C::CredentialRetired)),
        _ => {}
    }
    management::revalidate(profile, c, &p).await?;
    Ok(p)
}

/// Read the one admitted installation; never resolve an instance from client identifiers.
pub async fn installation_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
) -> Result<Uuid, Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_installation_identity)
        .fetch_one(c)
        .await
        .map_err(crate::database::db)
}
/// Current use is checked inside the caller's transaction and registration fence.
pub async fn require_use_in(
    c: &mut sqlx::PgConnection,
    p: &DevicePrincipal,
    usage: ConsumerUse,
) -> Result<(), Error> {
    if installation_in(p.profile(), c).await? != p.installation() {
        return Err(Error::Forbidden);
    }
    match (usage, p.kind()) {
        (ConsumerUse::AgentTask, RegistrationKind::Agent) => {
            store::revalidate_source(p.profile(), c, p, ReportSource::AgentBuiltin)
                .await
                .map(|_| ())
        }
        (ConsumerUse::DaConfiguration, RegistrationKind::DaDevice) => {
            management::revalidate(p.profile(), c, p).await
        }
        _ => Err(Error::Forbidden),
    }
}
