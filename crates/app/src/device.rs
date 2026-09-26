//! Product gateway seam. F04 owns cryptographic verification; I01 owns persistent binding.
//! No network DTO can construct credential evidence or a device principal.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
pub(crate) mod admission;
pub(crate) mod coordinates;
pub(crate) mod read;
pub(crate) mod store;
#[cfg(test)]
pub(crate) mod tests;
use crate::authorization::context::AuthorizedPrincipal;
use crate::{Database, Error, Failure, device::coordinates::Coordinates};
#[cfg(test)]
use rss_mdm_audit_integration::{FailureReason, WriteOutcome};
use rss_observation::{Epoch, Id, Registration, Scope};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;
use uuid::Uuid;

use rss_mdm_inventory::{Channel, ReportSource};
/// Evidence from a trusted channel verifier, not a credential ID submitted by a device.
/// I01 has no production constructor. F04 must verify the actual channel credential first.
/// ```compile_fail
/// let proof: rss_mdm_app::device::VerifiedChannelCredential = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// let proof = rss_mdm_app::device::VerifiedChannelCredential::new("fingerprint");
/// ```
pub struct VerifiedChannelCredential {
    tenant: TenantId,
    channel: Channel,
    source: ReportSource,
    locator: [u8; 32],
}
impl VerifiedChannelCredential {
    pub(crate) fn agent(tenant: TenantId, secret: &rss_mdm_agent_wire::Secret) -> Self {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"rss-mdm.agent.credential.v1\0");
        hash.update(tenant.to_string().as_bytes());
        hash.update(b"\0");
        hash.update(secret.expose().as_bytes());
        Self {
            tenant,
            channel: Channel::Agent,
            source: ReportSource::AgentBuiltin,
            locator: hash.finalize().into(),
        }
    }
    pub(crate) fn apple(
        tenant: TenantId,
        checked: &crate::apple::certificate::CheckedLeaf,
    ) -> Self {
        Self {
            tenant,
            channel: Channel::Mdm,
            source: ReportSource::MdmApple,
            locator: checked.fingerprint(),
        }
    }
    pub(crate) fn windows(
        tenant: TenantId,
        checked: &crate::windows::certificate::CheckedLeaf,
    ) -> Self {
        Self {
            tenant,
            channel: Channel::Mdm,
            source: ReportSource::MdmWindows,
            locator: checked.fingerprint(),
        }
    }
}
/// Immutable request-scoped identity resolved from the authoritative registration mapping.
/// ```compile_fail
/// let proof: rss_mdm_app::device::DevicePrincipal = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone)]
pub struct DevicePrincipal {
    tenant: TenantId,
    device: String,
    registration: Uuid,
    generation: i64,
    channel: Channel,
    credential: Uuid,
}
impl DevicePrincipal {
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
    access: Arc<Database>,
    tenant: String,
    #[cfg(test)]
    retirement_test_budget: Option<Duration>,
}
impl DeviceService {
    pub(crate) fn new(
        access: Arc<Database>,
        tenant: String,
        audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    ) -> Self {
        Self {
            access,
            tenant,
            audit_store,
            #[cfg(test)]
            retirement_test_budget: None,
        }
    }
    pub(crate) fn retirement_budget(&self) -> crate::audit_budget::AuditBudget {
        #[cfg(test)]
        if let Some(total) = self.retirement_test_budget {
            return crate::audit_budget::AuditBudget::retirement_test(total, None);
        }
        crate::audit_budget::AuditBudget::retirement(None)
    }
    /// Only real-protocol correctness fixtures may choose a larger budget. No production knob.
    #[cfg(test)]
    pub(crate) fn with_retirement_test_budget(mut self, total: Duration) -> Self {
        self.retirement_test_budget = Some(total);
        self
    }
    pub(crate) async fn management_principal(
        &self,
        credential: &VerifiedChannelCredential,
    ) -> Result<DevicePrincipal, Error> {
        self.authorize_report(credential, credential.source)
            .await
            .map(|(principal, _)| principal)
    }
    #[cfg(test)]
    pub(crate) async fn bind(
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
    #[cfg(test)]
    pub(crate) async fn revoke(
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
    #[cfg(test)]
    async fn audited<T>(
        &self,
        audit: &RequestAudit,
        work: impl std::future::Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let result = tokio::time::timeout(Duration::from_secs(8), work)
            .await
            .unwrap_or_else(|_| {
                Err(crate::error_projection::audit_deadline(
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
    #[cfg(test)]
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
        let budget = crate::audit_budget::AuditBudget::new(Duration::from_secs(2));
        let control = budget.control();
        if let Err(error) = store.settle_request(audit, status, outcome, &control).await {
            audit.finalize(Some(FailureReason::Persistent));
            return Err(error.into());
        }
        audit.finalize(None);
        result
    }
}
pub(crate) fn coverage_key() -> String {
    serde_json::to_string(&rss_mdm_inventory::coverage()).expect("fixed coverage")
}
pub(crate) fn scope(
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
pub(crate) fn scope_dataset(
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
pub(crate) enum DeviceError {
    #[error("invalid source identity")]
    InvalidSource,
}

pub(crate) const IDENTITY_MIGRATION_SQL: &str =
    include_str!("../migrations/0003_device_identity.sql");

pub(crate) const AGENT_ACCESS_MIGRATION_SQL: &str =
    include_str!("../migrations/0012_agent_access.sql");

pub(crate) const AUTHORITY_HISTORY_MIGRATION_SQL: &str =
    include_str!("../migrations/0012_asset_history.sql");

use rss_mdm_audit_integration::RequestAudit;
