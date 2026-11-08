//! Borrow shared owners without retaining Identity's verifier through its own authority.
use super::*;
use std::sync::Weak;
#[derive(Clone)]
pub struct Context {
    pub tenant: rss_request_context::TenantId,
    pub instance: rss_identity_core::InstanceId,
    pub installation: uuid::Uuid,
    pub access: Arc<rss_mdm_registration_service::Store>,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub access_admission: Arc<dyn crate::device_access::Admission>,
    pub platform_sso: Option<Arc<Runtime>>,
}
impl Context {
    pub fn runtime(&self) -> Result<&Runtime, Error> {
        self.platform_sso.as_deref().ok_or(Error::Unsupported)
    }
    pub async fn registration_binding_on(
        &self,
        c: &mut sqlx::PgConnection,
        p: &rss_mdm_registration_service::DevicePrincipal,
        id: uuid::Uuid,
        generation: i64,
    ) -> Result<crate::device_access::Binding, Error> {
        let target = crate::delivery::resolve_on(c, p).await?;
        let b = crate::device_access::storage::locked_in(
            c,
            uuid::Uuid::parse_str(&self.tenant.to_string()).map_err(|_| Error::Corrupt)?,
            id,
        )
        .await?;
        if b.device != target.device()
            || b.device != target.device()
            || b.generation != generation
            || b.state == rss_mdm_device_access::State::Revoked
            || !b.configuration.enabled
        {
            return Err(Error::Forbidden);
        }
        self.access_admission
            .binding_session(c, b.tenant, &b)
            .await?;
        let selection = self
            .access_admission
            .policy(c, b.tenant, &b.device, b.policy)
            .await?;
        if selection.version != b.policy_version || selection.configuration != b.configuration {
            return Err(Error::Forbidden);
        }
        Ok(b)
    }
    pub async fn active_binding_on(
        &self,
        c: &mut sqlx::PgConnection,
        id: uuid::Uuid,
        generation: i64,
    ) -> Result<crate::device_access::Binding, Error> {
        let tenant = uuid::Uuid::parse_str(&self.tenant.to_string()).map_err(|_| Error::Corrupt)?;
        let b = crate::device_access::storage::require_active_in(c, tenant, id, generation).await?;
        let selection = self
            .access_admission
            .policy(c, tenant, &b.device, b.policy)
            .await?;
        if selection.version != b.policy_version || selection.configuration != b.configuration {
            return Err(Error::Forbidden);
        }
        Ok(b)
    }
}
pub struct Binding {
    tenant: rss_request_context::TenantId,
    instance: rss_identity_core::InstanceId,
    installation: uuid::Uuid,
    access: Arc<rss_mdm_registration_service::Store>,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    admission: Weak<dyn crate::device_access::Admission>,
    platform_sso: Option<Arc<Runtime>>,
}
impl Binding {
    pub fn new(c: Context) -> Self {
        Self {
            tenant: c.tenant,
            instance: c.instance,
            installation: c.installation,
            access: c.access,
            audit_store: c.audit_store,
            protection: c.protection,
            admission: Arc::downgrade(&c.access_admission),
            platform_sso: c.platform_sso,
        }
    }
    pub fn matches(&self, c: &Context) -> bool {
        self.tenant == c.tenant
            && self.instance == c.instance
            && self.installation == c.installation
            && Arc::ptr_eq(&self.access, &c.access)
            && Arc::ptr_eq(&self.audit_store, &c.audit_store)
            && Arc::ptr_eq(&self.protection, &c.protection)
            && Weak::ptr_eq(&self.admission, &Arc::downgrade(&c.access_admission))
            && match (&self.platform_sso, &c.platform_sso) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
    pub fn get(&self) -> Option<Context> {
        Some(Context {
            tenant: self.tenant,
            instance: self.instance,
            installation: self.installation,
            access: self.access.clone(),
            audit_store: self.audit_store.clone(),
            protection: self.protection.clone(),
            access_admission: self.admission.upgrade()?,
            platform_sso: self.platform_sso.clone(),
        })
    }
}
