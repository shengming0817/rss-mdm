//! Product gateway seam. F04 owns cryptographic verification; I01 owns persistent binding.
//! No network DTO can construct credential evidence or a device principal.
//! ref: sqlx v0.9.0 sqlx-core/src/transaction.rs
mod store;
#[cfg(test)]
mod tests;
use crate::{
    AccessStore, Error, Failure,
    access::{Coordinates, Policy},
    audit::{Audit, FailureReason, WriteOutcome},
};
use rss_identity_client::VerifiedIdentity;
use rss_observation::{Access, Authority, Batch, Epoch, Id, Registration, Scope};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Agent,
    Mdm,
}
impl Channel {
    fn as_str(self) -> &'static str {
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
    fn channel(self) -> Channel {
        match self {
            Self::MdmWindows => Channel::Mdm,
            Self::AgentBuiltin => Channel::Agent,
        }
    }
    fn as_str(self) -> &'static str {
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
    policy: Arc<Policy>,
    journal_tenant: Option<TenantId>,
    clock: Arc<dyn rss_observation::Clock>,
}
impl DeviceService {
    pub(crate) fn new(
        access: Arc<AccessStore>,
        policy: Arc<Policy>,
        journal_tenant: Option<TenantId>,
        clock: Arc<dyn rss_observation::Clock>,
    ) -> Self {
        Self {
            access,
            policy,
            journal_tenant,
            clock,
        }
    }
    pub async fn bind(
        &self,
        admin: &VerifiedIdentity,
        credential: &VerifiedChannelCredential,
        command: BindRegistration,
    ) -> Result<RegistrationReceipt, Error> {
        let audit = Audit::new(admin.tenant_id().into(), "registration_bind");
        audit.identify(admin);
        audit.operation(command.operation_id, "registration_bind");
        self.audited(&audit, self.bind_inner(admin, credential, &command, &audit))
            .await
    }
    pub async fn revoke(
        &self,
        admin: &VerifiedIdentity,
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
    /// Rechecks persisted authority on every submission; grants never escape this operation.
    pub async fn ingest<C: rss_observation::Clock>(
        &self,
        credential: &VerifiedChannelCredential,
        source: ReportSource,
        batch: Batch,
        observation: &rss_observation_postgres::PgStore<C>,
        deadline: rss_request_context::Deadline,
    ) -> Result<rss_observation::ReceiveOutcome, Error> {
        let audit = Audit::new(self.policy.tenant().into(), "device_report");
        // One deadline domain; RSS owns cancellation/settlement of its writes.
        let deadline = deadline.shortened_to(self.clock.now() + Duration::from_secs(8));
        let result = async {
            let budget = deadline
                .remaining(self.clock.now())
                .ok_or(Error::Unavailable(Failure::RequestDeadline))?;
            // This transaction is read-only. It is safe to cancel before admitting effects.
            let (principal, authority) =
                tokio::time::timeout(budget, self.authorize_report(credential, source))
                    .await
                    .map_err(|_| Error::Unavailable(Failure::RequestDeadline))??;
            audit.target(principal.device());
            audit.registration(principal.registration());
            audit.identify_device(principal.registration());
            rss_mdm_inventory::validate(&batch).map_err(|_| Error::Malformed)?;
            let verified =
                rss_observation::VerifiedBatch::verify(&authority, authority.scope.clone(), batch)
                    .map_err(|_| Error::Forbidden)?;
            let lifecycle =
                rss_observation::LifecycleGrant::verify(&authority, authority.scope.clone())
                    .map_err(|_| Error::Forbidden)?;
            use rss_observation::ObservationStore;
            // Until RSS returns, cancelling the caller cannot prove absence of a receipt.
            audit.mark_commit_started();
            let received = async {
                observation
                    .activate(
                        &lifecycle,
                        None,
                        &rss_observation::Policy::new(86400, 3600, 3600).expect("fixed policy"),
                        deadline,
                    )
                    .await?;
                observation.receive(&verified, deadline).await
            }
            .await;
            match &received {
                Ok(_) => audit.mark_committed(),
                Err(error)
                    if matches!(
                        error.kind(),
                        rss_observation::ErrorKind::CommitUnknown
                            | rss_observation::ErrorKind::RollbackFailed
                    ) => {}
                Err(_) => audit.mark_not_committed(),
            }
            received.map_err(observation_error)
        }
        .await;
        // Observation receipts and product audit are separate transactions. Even a known
        // receipt commit needs this audit; registration's atomic-audit shortcut does not apply.
        let success = match &result {
            Ok(rss_observation::ReceiveOutcome::Replay(_)) => "replay",
            Ok(rss_observation::ReceiveOutcome::Accepted(_)) | Err(_) => "success",
        };
        self.record_result(&audit, result, success).await
    }
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
fn observation_error(error: rss_observation::Error) -> Error {
    #[cfg(test)]
    eprintln!("test Observation error category: {:?}", error.kind());
    match error.kind() {
        rss_observation::ErrorKind::CommitUnknown => Error::CommitUnknown,
        rss_observation::ErrorKind::Conflict | rss_observation::ErrorKind::LifecycleConflict => {
            Error::Conflict
        }
        rss_observation::ErrorKind::InvalidInput => Error::Malformed,
        rss_observation::ErrorKind::Unauthorized => Error::Forbidden,
        _ => Error::Unavailable(Failure::Observation),
    }
}
struct ReportAuthority {
    scope: Scope,
}
impl Authority for ReportAuthority {
    fn authorize(&self, request: Access<'_>) -> Result<(), rss_observation::Error> {
        let allowed = match request {
            Access::Activate { scope } => scope == &self.scope,
            Access::Submit { scope, coverage } => {
                scope == &self.scope && coverage == &rss_mdm_inventory::coverage()
            }
            Access::Read { .. } | Access::ReadJournal { .. } => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(rss_observation::ErrorKind::Unauthorized.into())
        }
    }
}
/// A local host lease, independent from every device principal. Revocation is cancel+join
/// of the bounded host invocation; no report can construct or extend this authority.
struct JournalAuthority {
    tenant: TenantId,
    cancelled: tokio_util::sync::CancellationToken,
}
impl Authority for JournalAuthority {
    fn authorize(&self, request: Access<'_>) -> Result<(), rss_observation::Error> {
        if !self.cancelled.is_cancelled()
            && matches!(request, Access::ReadJournal { tenant } if tenant == self.tenant)
        {
            Ok(())
        } else {
            Err(rss_observation::ErrorKind::Unauthorized.into())
        }
    }
}
impl DeviceService {
    /// Host-owned bounded worker permission, independent of device/report credentials.
    /// The management HTTP assembly has no journal permission. F05 owns worker assembly.
    pub fn journal_grant(
        &self,
        tenant: TenantId,
        cancelled: &tokio_util::sync::CancellationToken,
    ) -> Result<rss_observation::JournalReadGrant, rss_observation::Error> {
        if self.journal_tenant != Some(tenant) || self.policy.tenant() != tenant.to_string() {
            return Err(rss_observation::ErrorKind::Unauthorized.into());
        }
        rss_observation::JournalReadGrant::verify(
            &JournalAuthority {
                tenant,
                cancelled: cancelled.clone(),
            },
            tenant,
        )
    }
}

fn coverage_key() -> String {
    serde_json::to_string(&rss_mdm_inventory::coverage()).expect("fixed coverage")
}
fn scope(tenant: TenantId, registration: Uuid, source: &str, epoch: Uuid) -> Result<Scope, Error> {
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
