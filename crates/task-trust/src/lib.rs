//! Task signing, durable trust and installation evidence owned independently of execution.
mod error;
pub mod observations;
pub mod service;
mod signing;
pub mod trust;
pub use error::Error;
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

pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

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
    tenant: TenantId,
    signer: Option<signing::Signer>,
}
impl Signing {
    pub fn new(tenant: TenantId, loaded: Option<trust::Loaded>) -> Result<Self, Error> {
        if loaded.as_ref().is_some_and(|v| v.tenant != tenant) {
            return Err(Error::Forbidden);
        }
        Ok(Self {
            tenant,
            signer: loaded.map(|v| v.task),
        })
    }
    pub fn loaded_key(&self) -> Option<&str> {
        self.signer.as_ref().map(|s| s.key_id())
    }
    async fn revalidate(&self, c: &mut PgConnection, p: &DevicePrincipal) -> Result<(), Error> {
        if p.tenant() != self.tenant
            || p.channel() != rss_mdm_inventory::Channel::Agent
            || p.purpose() != rss_mdm_registration_service::Purpose::Primary
        {
            return Err(Error::Forbidden);
        }
        rss_mdm_registration_service::device::store::revalidate_source(
            c,
            p,
            rss_mdm_inventory::ReportSource::AgentBuiltin,
        )
        .await?;
        Ok(())
    }
    pub async fn sign_task_on(
        &self,
        c: &mut PgConnection,
        p: &DevicePrincipal,
        payload: TaskPayload,
    ) -> Result<SignedTask, Error> {
        let (tenant, device, registration, generation) = match &payload {
            TaskPayload::DeviceAccess(v) => (
                v.tenant_id,
                v.device_id.as_str(),
                v.registration_id,
                v.generation,
            ),
            TaskPayload::Credential(v) => (
                v.tenant_id,
                v.device_id.as_str(),
                v.registration_id,
                v.generation,
            ),
            TaskPayload::Collection(v) => (
                v.tenant_id,
                v.device_id.as_str(),
                v.registration_id,
                v.generation,
            ),
            TaskPayload::Script(v) => (
                v.tenant_id,
                v.device_id.as_str(),
                v.registration_id,
                v.generation,
            ),
            TaskPayload::Software(v) => (
                v.tenant_id,
                v.device_id.as_str(),
                v.registration_id,
                v.generation,
            ),
            TaskPayload::Enrollment(v) => (
                v.tenant_id,
                v.device_id.as_str(),
                v.registration_id,
                v.generation,
            ),
            TaskPayload::Unmanage(v) => (
                v.tenant_id,
                v.device_id.as_str(),
                v.registration_id,
                v.generation,
            ),
        };
        if tenant.to_string() != p.tenant().to_string()
            || device != p.device()
            || registration != p.registration()
            || generation != p.generation() as u64
        {
            return Err(Error::Forbidden);
        }
        self.revalidate(c, p).await?;
        let signer = self.signer.as_ref().ok_or(Error::Unsupported)?;
        trust::require_issue(c, p, signer.key_id()).await?;
        signer.sign(payload)
    }
}

pub struct Service {
    tenant: TenantId,
    signing: Arc<Signing>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    retirement: Arc<dyn RetirementGuard>,
}
impl Service {
    pub fn new(
        tenant: TenantId,
        signing: Arc<Signing>,
        protection: Arc<rss_mdm_native_protection::Protector>,
        audit: Arc<rss_mdm_audit_integration::AuditStore>,
        retirement: Arc<dyn RetirementGuard>,
    ) -> Result<Self, Error> {
        if signing.tenant != tenant {
            return Err(Error::Forbidden);
        }
        Ok(Self {
            tenant,
            signing,
            protection,
            audit,
            retirement,
        })
    }
}
