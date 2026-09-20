//! Product gateway seam. F04 owns cryptographic verification; I01 owns persistent binding.
//! No network DTO can construct credential evidence or a device principal.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
pub(crate) mod store;
#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
use crate::audit::{FailureReason, WriteOutcome};
use crate::identity::Principal;
use crate::{AccessStore, Error, Failure, access::Coordinates, audit::Audit};
use rss_observation::{Epoch, Id, Registration, Scope};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Agent,
    Mdm,
}
impl Channel {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Mdm => "mdm",
        }
    }
}
/// Explicit V1 producers. New adapters add their real source here, never a third channel.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ReportSource {
    #[serde(rename = "mdm.windows")]
    MdmWindows,
    #[serde(rename = "agent.builtin")]
    AgentBuiltin,
}
impl ReportSource {
    pub(crate) fn channel(self) -> Channel {
        match self {
            Self::MdmWindows => Channel::Mdm,
            Self::AgentBuiltin => Channel::Agent,
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::MdmWindows => "mdm.windows",
            Self::AgentBuiltin => "agent.builtin",
        }
    }
}
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
    locator: [u8; 32],
}
impl VerifiedChannelCredential {
    pub(crate) fn windows(
        tenant: TenantId,
        checked: &crate::windows::certificate::CheckedLeaf,
    ) -> Self {
        Self {
            tenant,
            channel: Channel::Mdm,
            locator: checked.fingerprint(),
        }
    }
}
/// Immutable request-scoped identity resolved from the authoritative registration mapping.
/// ```compile_fail
/// let proof: rss_mdm_app::device::DevicePrincipal = serde_json::from_str("{}").unwrap();
/// ```
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
    access: Arc<AccessStore>,
    tenant: String,
}
impl DeviceService {
    pub(crate) fn new(access: Arc<AccessStore>, tenant: String) -> Self {
        Self { access, tenant }
    }
    pub(crate) async fn management_principal(
        &self,
        credential: &VerifiedChannelCredential,
    ) -> Result<DevicePrincipal, Error> {
        self.authorize_report(credential, ReportSource::MdmWindows)
            .await
            .map(|(principal, _)| principal)
    }
    #[cfg(test)]
    pub(crate) async fn bind(
        &self,
        admin: &Principal,
        credential: &VerifiedChannelCredential,
        command: BindRegistration,
    ) -> Result<RegistrationReceipt, Error> {
        let audit = Audit::new(admin.tenant_id().into(), "registration_bind");
        audit.identify(admin);
        audit.operation(command.operation_id, "registration_bind");
        self.audited(&audit, self.bind_inner(admin, credential, &command, &audit))
            .await
    }
    #[cfg(test)]
    pub(crate) async fn revoke(
        &self,
        admin: &Principal,
        device: &str,
        registration: Uuid,
        operation_id: Uuid,
    ) -> Result<RevocationReceipt, Error> {
        let audit = Audit::new(admin.tenant_id().into(), "credential_revoke");
        audit.identify(admin);
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
        audit: &Audit,
        work: impl std::future::Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let result = tokio::time::timeout(Duration::from_secs(8), work)
            .await
            .unwrap_or_else(|_| Err(audit.snapshot().write_outcome.deadline_error()));
        if audit.snapshot().write_outcome == WriteOutcome::Committed {
            audit.finalize(None);
            return result;
        }
        // New writes already recorded success atomically. A remaining Ok is a stored receipt.
        self.record_result(audit, result, "replay").await
    }
    #[cfg(test)]
    async fn record_result<T>(
        &self,
        audit: &Audit,
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
        if !matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                self.access.record(audit, status, outcome)
            )
            .await,
            Ok(Ok(()))
        ) {
            audit.finalize(Some(FailureReason::Persistent));
            return Err(Error::Unavailable(Failure::Audit));
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
) -> Result<Scope, Error> {
    Ok(Scope::new(
        tenant,
        // RSS's lifecycle fence is object-wide. Each independently registered channel
        // generation is its own observation subject; Device identity lives in our mapping.
        Id::new(registration.to_string()).map_err(|_| Error::Malformed)?,
        Registration::new(registration.to_string()).map_err(|_| Error::Malformed)?,
        Id::new(source).map_err(|_| Error::Malformed)?,
        Id::new("inventory").expect("fixed dataset"),
        Epoch::new(epoch.to_string()).map_err(|_| Error::Malformed)?,
    ))
}
