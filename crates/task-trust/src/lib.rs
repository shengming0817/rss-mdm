//! Task signing, durable trust and installation evidence owned independently of execution.
pub mod configuration;
mod error;
pub mod observations;
pub mod service;
mod signing;
pub mod trust;
pub use error::Error;
pub use rss_mdm_registration_service::device::ConsumerUse as Use;
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Audit,
    AuditAdmission,
    AuditContract,
    AuditIntegrity,
    AuditIsolation,
    Capacity,
    CommandInvariant,
    Database,
    RequestDeadline,
    Runtime,
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigIssue {
    TaskSigning,
    IdentityConfiguration,
}
use rss_mdm_agent_wire::runtime::{SignedTask, TaskPayload};
use rss_mdm_registration_service::DevicePrincipal;
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::sync::Arc;

pub const ACCESS_CONTRACT: &str =
    crate::storage_profile::sql(rss_mdm_install_support::StorageProfile::Mdm, Use::AgentTask)
        .access_contract;

/// The caller supplies the original transaction; implementations never settle it.
pub trait RetirementGuard: Send + Sync {
    fn pending<'a>(
        &'a self,
        connection: &'a mut PgConnection,
        tenant: TenantId,
        key: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, Error>> + Send + 'a>>;
}

/// Shared signing capability. Private key operations cannot bypass durable admission.
pub struct Signing {
    profile: rss_mdm_install_support::StorageProfile,
    tenant: TenantId,
    usage: Use,
    signer: Option<signing::Signer>,
}
impl Signing {
    pub const fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn new(
        profile: rss_mdm_install_support::StorageProfile,
        usage: Use,
        tenant: TenantId,
        loaded: Option<trust::Loaded>,
    ) -> Result<Self, Error> {
        if loaded
            .as_ref()
            .is_some_and(|v| v.tenant != tenant || v.profile != profile || v.usage != usage)
        {
            return Err(Error::Forbidden);
        }
        Ok(Self {
            profile,
            tenant,
            usage,
            signer: loaded.map(|v| v.task),
        })
    }
    pub fn loaded_key(&self) -> Option<&str> {
        self.signer.as_ref().map(|s| s.key_id())
    }
    async fn revalidate(&self, c: &mut PgConnection, p: &DevicePrincipal) -> Result<(), Error> {
        if p.profile() != self.profile || p.tenant() != self.tenant {
            return Err(Error::Forbidden);
        }
        rss_mdm_registration_service::device::require_use_in(c, p, self.usage).await?;
        Ok(())
    }
    pub async fn sign_task_on(
        &self,
        c: &mut PgConnection,
        p: &DevicePrincipal,
        payload: TaskPayload,
    ) -> Result<SignedTask, Error> {
        if self.usage != Use::AgentTask {
            return Err(Error::Forbidden);
        }
        let (tenant, device) = match &payload {
            TaskPayload::DeviceAccess(v) => (v.tenant_id, v.device_id.as_str()),
            TaskPayload::Credential(v) => (v.tenant_id, v.device_id.as_str()),
            TaskPayload::Collection(v) => (v.tenant_id, v.device_id.as_str()),
            TaskPayload::Script(v) => (v.tenant_id, v.device_id.as_str()),
            TaskPayload::Software(v) => (v.tenant_id, v.device_id.as_str()),
            TaskPayload::Enrollment(v) => (v.tenant_id, v.device_id.as_str()),
            TaskPayload::Unmanage(v) => (v.tenant_id, v.device_id.as_str()),
        };
        if tenant.to_string() != p.tenant().to_string() || device != p.device() {
            return Err(Error::Forbidden);
        }
        self.revalidate(c, p).await?;
        let signer = self.signer.as_ref().ok_or(Error::Unsupported)?;
        trust::require_issue(self.profile, self.usage, c, p, signer.key_id()).await?;
        signer.sign(payload)
    }
}

pub struct Service {
    tenant: TenantId,
    signing: Arc<Signing>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    retirement: Option<Arc<dyn RetirementGuard>>,
}
impl Service {
    pub fn new(
        tenant: TenantId,
        signing: Arc<Signing>,
        protection: Arc<rss_mdm_native_protection::Protector>,
        audit: Arc<rss_mdm_audit_integration::AuditStore>,
        retirement: Arc<dyn RetirementGuard>,
    ) -> Result<Self, Error> {
        if signing.tenant != tenant || signing.usage != Use::AgentTask {
            return Err(Error::Forbidden);
        }
        Ok(Self {
            tenant,
            signing,
            protection,
            audit,
            retirement: Some(retirement),
        })
    }
}

impl Service {
    /// Configuration signatures retain their own durable verification horizon; no Agent runtime is assembled.
    pub fn for_configurations(
        tenant: TenantId,
        signing: Arc<Signing>,
        protection: Arc<rss_mdm_native_protection::Protector>,
        audit: Arc<rss_mdm_audit_integration::AuditStore>,
    ) -> Result<Self, Error> {
        if signing.tenant != tenant
            || signing.usage != Use::DaConfiguration
            || signing.profile != rss_mdm_install_support::StorageProfile::Da
        {
            return Err(Error::Forbidden);
        }
        Ok(Self {
            tenant,
            signing,
            protection,
            audit,
            retirement: None,
        })
    }
}

mod storage_profile;

/// Shared owner objects, combined by the host for complete schema admission.
pub const fn object_manifest(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile, Use::AgentTask).object_manifest
}
/// Exact access-role contract for this installation.
pub const fn access_contract(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    storage_profile::sql(profile, Use::AgentTask).access_contract
}
