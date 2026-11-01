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
}
impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::WindowsDeclared => "windows_declared",
        }
    }
    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "primary" => Ok(Self::Primary),
            "windows_declared" => Ok(Self::WindowsDeclared),
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
/// Immutable request-scoped identity resolved from the authoritative registration mapping.
/// ```compile_fail
/// let proof: rss_mdm_registration_service::DevicePrincipal = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone)]
pub struct DevicePrincipal {
    profile: rss_mdm_install_support::StorageProfile,
    tenant: TenantId,
    device: String,
    registration: Uuid,
    generation: i64,
    channel: Channel,
    credential: Uuid,
    user_context: Option<Uuid>,
    purpose: Purpose,
    parent: Option<(Uuid, i64)>,
    epoch: Uuid,
}
impl DevicePrincipal {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    pub fn parent(&self) -> Option<(Uuid, i64)> {
        self.parent
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
    pub fn registration(&self) -> Uuid {
        self.registration
    }
    pub fn generation(&self) -> i64 {
        self.generation
    }
    pub fn channel(&self) -> Channel {
        self.channel
    }
    /// Full enrollment permits only its enrolled-user scope; this is not an OS or organization identity.
    pub fn user_context(&self) -> Option<Uuid> {
        self.user_context
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
    /// Zero denotes a never-registered channel. Includes revoked/superseded history.
    pub expected_generation: i64,
    pub source: ReportSource,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationReceipt {
    pub operation_id: Uuid,
    pub request_id: Uuid,
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
    pub channel: Channel,
    pub credential: Uuid,
    pub epoch: Uuid,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationReceipt {
    pub operation_id: Uuid,
    pub registration: Uuid,
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
    registration: Uuid,
    source: &str,
    epoch: Uuid,
) -> Result<Scope, DeviceError> {
    scope_dataset(
        profile,
        tenant,
        registration,
        source,
        epoch,
        rss_mdm_inventory::DATASET,
    )
}
pub fn scope_dataset(
    profile: rss_mdm_install_support::StorageProfile,
    tenant: TenantId,
    registration: Uuid,
    source: &str,
    epoch: Uuid,
    dataset: &str,
) -> Result<Scope, DeviceError> {
    Ok(Scope::new(
        tenant,
        // Lifecycle CAS is object-wide. Each independently activated fixed dataset
        // has its own subject within the registration; Device identity stays in our mapping.
        Id::new(if dataset == rss_mdm_inventory::DATASET {
            match profile {
                rss_mdm_install_support::StorageProfile::Mdm => registration.to_string(),
                rss_mdm_install_support::StorageProfile::Da => format!("da:{registration}"),
            }
        } else {
            match profile {
                rss_mdm_install_support::StorageProfile::Mdm => format!("{registration}:{dataset}"),
                rss_mdm_install_support::StorageProfile::Da => {
                    format!("da:{registration}:{dataset}")
                }
            }
        })
        .map_err(|_| DeviceError::InvalidSource)?,
        Registration::new(registration.to_string()).map_err(|_| DeviceError::InvalidSource)?,
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
        ids: [Uuid; 3],
        facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    ) -> Result<RegistrationReceipt, Error> {
        let profile = self.profile();

        store::bind_in(
            profile,
            tx,
            proof,
            credential,
            command,
            device,
            ids,
            facts,
            self.access.retirement.as_ref(),
        )
        .await
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
        ids: [Uuid; 3],
        facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    ) -> Result<RegistrationReceipt, Error> {
        let profile = self.profile();

        store::bind_native_in(
            profile,
            tx,
            admission,
            credential,
            ids,
            facts,
            self.access.retirement.as_ref(),
        )
        .await
    }
}

/// Resolve an Agent only from the certificate owner's sealed TLS verification result.
pub async fn authenticate_agent_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    peer: &rss_mdm_device_trust::agent::VerifiedAgentPeer,
) -> Result<DevicePrincipal, Error> {
    use crate::database::db;
    use rss_mdm_agent_wire::enroll::ErrorCode as C;
    use sqlx::Row;
    let fingerprint: String = peer
        .metadata()
        .fingerprint
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let row = sqlx::query(crate::storage_profile::sql(profile).device_authenticate_agent_in_1)
        .bind(tenant.to_string())
        .bind(fingerprint)
        .fetch_optional(&mut *c)
        .await
        .map_err(db)?
        .ok_or(Error::Unauthorized)?;
    let device: String = row.try_get("device").map_err(db)?;
    store::lock_channel(profile, c, &tenant.to_string(), &device, Channel::Agent).await?;
    let p = DevicePrincipal {
        profile,
        tenant,
        device,
        registration: row.try_get("id").map_err(db)?,
        generation: row.try_get("generation").map_err(db)?,
        epoch: row.try_get("epoch").map_err(db)?,
        credential: row.try_get("credential").map_err(db)?,
        channel: Channel::Agent,
        purpose: Purpose::Primary,
        parent: None,
        user_context: None,
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
