//! Product gateway seam. F04 owns cryptographic verification; I01 owns persistent binding.
//! No network DTO can construct credential evidence or a device principal.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
pub mod coordinates;
pub mod directory;
pub mod linked;
mod management;
pub mod read;
pub mod store;
use crate::{Error, Store, device::coordinates::Coordinates};
#[cfg(any(test, feature = "integration"))]
use rss_mdm_audit_integration::{FailureReason, WriteOutcome};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_observation::{Epoch, Id, Registration, Scope};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[cfg(any(test, feature = "integration"))]
use std::time::Duration;
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
    tenant: TenantId,
    channel: Channel,
    source: ReportSource,
    locator: [u8; 32],
    purpose: Purpose,
}
/// A composition-time authority bound to one tenant and report source.
#[derive(Clone)]
pub struct ChannelMount {
    tenant: TenantId,
    source: ReportSource,
    purpose: Purpose,
}
impl ChannelMount {
    pub fn new(tenant: TenantId, source: ReportSource, purpose: Purpose) -> Self {
        Self {
            tenant,
            source,
            purpose,
        }
    }
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn credential(&self, locator: [u8; 32]) -> VerifiedChannelCredential {
        VerifiedChannelCredential {
            tenant: self.tenant,
            channel: self.source.channel(),
            source: self.source,
            locator,
            purpose: self.purpose,
        }
    }
}
/// Immutable request-scoped identity resolved from the authoritative registration mapping.
/// ```compile_fail
/// let proof: rss_mdm_registration_service::DevicePrincipal = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone)]
pub struct DevicePrincipal {
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    #[cfg(any(test, feature = "integration"))]
    retirement_test_budget: Option<Duration>,
}
impl DeviceService {
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
            #[cfg(any(test, feature = "integration"))]
            retirement_test_budget: None,
        }
    }
    pub fn retirement_budget(&self) -> rss_mdm_audit_integration::budget::AuditBudget {
        #[cfg(any(test, feature = "integration"))]
        if let Some(total) = self.retirement_test_budget {
            return rss_mdm_audit_integration::budget::AuditBudget::retirement_test(total, None);
        }
        rss_mdm_audit_integration::budget::AuditBudget::retirement(None)
    }
    /// Only real-protocol correctness fixtures may choose a larger budget. No production knob.
    #[cfg(any(test, feature = "integration"))]
    pub fn with_retirement_test_budget(mut self, total: Duration) -> Self {
        self.retirement_test_budget = Some(total);
        self
    }
    pub async fn management_principal(
        &self,
        credential: &VerifiedChannelCredential,
    ) -> Result<DevicePrincipal, Error> {
        if self.tenant != credential.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let mut tx = self.access.begin(&self.tenant).await?;
        let principal = store::management_in(&mut tx, credential).await?;
        tx.commit().await.map_err(crate::database::db)?;
        Ok(principal)
    }
    #[cfg(any(test, feature = "integration"))]
    pub async fn bind(
        &self,
        admin: &AuthorizedPrincipal,
        credential: &VerifiedChannelCredential,
        command: BindRegistration,
    ) -> Result<RegistrationReceipt, Error> {
        let audit = RequestAudit::new(admin.tenant_id().into(), "registration_bind");
        admin.bind_audit(&audit)?;
        audit.operation(command.operation_id, "registration_bind");
        self.audited(&audit, self.bind_inner(admin, credential, &command, &audit))
            .await
    }
    #[cfg(any(test, feature = "integration"))]
    pub async fn revoke(
        &self,
        admin: &AuthorizedPrincipal,
        device: &str,
        registration: Uuid,
        operation_id: Uuid,
    ) -> Result<RevocationReceipt, Error> {
        let audit = RequestAudit::new(admin.tenant_id().into(), "credential_revoke");
        admin.bind_audit(&audit)?;
        audit.operation(operation_id, "credential_revoke");
        audit.target(device);
        self.audited(
            &audit,
            self.revoke_inner(admin, device, registration, operation_id, &audit),
        )
        .await
    }
    #[cfg(any(test, feature = "integration"))]
    async fn audited<T>(
        &self,
        audit: &RequestAudit,
        work: impl std::future::Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let result = tokio::time::timeout(Duration::from_secs(8), work)
            .await
            .unwrap_or_else(|_| {
                Err(crate::device::audit_deadline(
                    audit.snapshot().write_outcome,
                ))
            });
        if audit.snapshot().write_outcome == WriteOutcome::Committed
            && !matches!(
                audit.snapshot().management_result,
                Some(rss_mdm_audit_integration::ManagementResult::Replayed)
            )
        {
            audit.finalize(None);
            return result;
        }
        // New writes already recorded success atomically. A remaining Ok is a stored receipt.
        self.record_result(audit, result, "replay").await
    }
    #[cfg(any(test, feature = "integration"))]
    async fn record_result<T>(
        &self,
        audit: &RequestAudit,
        result: Result<T, Error>,
        success: &'static str,
    ) -> Result<T, Error> {
        let (status, outcome) = match &result {
            Ok(_) => (200, success),
            Err(_) if audit.snapshot().write_outcome == WriteOutcome::Unknown => (503, "unknown"),
            Err(Error::CommitUnknown) => (503, "unknown"),
            Err(Error::Unauthorized) => (401, "denied"),
            Err(Error::Forbidden) => (403, "denied"),
            Err(Error::Conflict) => (409, "denied"),
            Err(Error::Malformed) => (400, "denied"),
            Err(_) => (503, "failed"),
        };
        let store = &self.audit_store;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(2));
        let control = budget.control();
        if let Err(error) = store.settle_request(audit, status, outcome, &control).await {
            audit.finalize(Some(FailureReason::Persistent));
            return Err(error.into());
        }
        audit.finalize(None);
        result
    }
}
pub fn scope(
    tenant: TenantId,
    registration: Uuid,
    source: &str,
    epoch: Uuid,
) -> Result<Scope, DeviceError> {
    scope_dataset(
        tenant,
        registration,
        source,
        epoch,
        rss_mdm_inventory::DATASET,
    )
}
pub fn scope_dataset(
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
            registration.to_string()
        } else {
            format!("{registration}:{dataset}")
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

#[cfg(any(test, feature = "integration"))]
fn audit_deadline(outcome: rss_mdm_audit_integration::WriteOutcome) -> Error {
    use rss_mdm_audit_integration::WriteOutcome;
    match outcome {
        WriteOutcome::Unknown | WriteOutcome::Committed => Error::CommitUnknown,
        WriteOutcome::RollbackFailed => Error::RollbackFailed,
        WriteOutcome::RolledBack | WriteOutcome::CommitNotStarted => Error::Deadline,
    }
}

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
        store::bind_in(
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
    #[cfg(feature = "integration")]
    pub fn fixture_audit_store(&self) -> &rss_mdm_audit_integration::AuditStore {
        &self.audit_store
    }
    #[cfg(feature = "integration")]
    pub async fn fixture_request(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
        channel: Channel,
    ) -> Result<Uuid, Error> {
        let audit = RequestAudit::new(proof.tenant_id().into(), "enrollment_create");
        proof.bind_audit(&audit)?;
        audit.target(device);
        let key = Uuid::new_v4();
        audit.operation(key, "enrollment_create");
        let receipt = crate::enrollment::store::create_enrollment(
            &self.audit_store,
            proof.enrollment(device)?,
            &crate::enrollment::Password::new(crate::enrollment::random())?,
            match channel {
                Channel::Agent => ReportSource::AgentBuiltin,
                Channel::Mdm => ReportSource::MdmWindows,
            },
            (channel == Channel::Mdm).then_some(crate::enrollment::WindowsProfile::Device),
            Uuid::new_v4(),
            key,
            &audit,
        )
        .await?;
        audit.finalize(None);
        Ok(receipt.enrollment_id)
    }
}
