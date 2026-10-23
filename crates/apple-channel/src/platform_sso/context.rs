//! Borrow existing owners without retaining Identity's verifier through its own authority.
use super::*;
use std::sync::Weak;
pub(super) struct Context {
    pub tenant: rss_request_context::TenantId,
    pub instance: rss_identity_core::InstanceId,
    pub access: Arc<crate::Store>,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub platform_objects: Arc<rss_mdm_device_service::planning::PlanningObjects>,
    pub execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub platform_sso: Option<Arc<Runtime>>,
}
impl Context {
    pub fn new(app: &HttpState) -> Self {
        Self {
            tenant: app.identity.tenant(),
            instance: app.authentication.authority.instance(),
            access: app.access.clone(),
            audit_store: app.audit_store.clone(),
            protection: app.protection.clone(),
            platform_objects: app.platform_objects.clone(),
            execution: app.execution.clone(),
            platform_sso: app.platform_sso.clone(),
        }
    }
    pub fn runtime(&self) -> Result<&Runtime, Error> {
        self.platform_sso.as_deref().ok_or(Error::Unsupported)
    }
}
pub(super) struct Binding {
    tenant: rss_request_context::TenantId,
    instance: rss_identity_core::InstanceId,
    access: Arc<crate::Store>,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    protection: Arc<rss_mdm_native_protection::Protector>,
    objects: Arc<rss_mdm_device_service::planning::PlanningObjects>,
    execution: Weak<rss_mdm_execution_service::ExecutionService>,
    configuration: Option<Arc<Runtime>>,
}
impl Binding {
    pub fn new(c: Context) -> Self {
        Self {
            tenant: c.tenant,
            instance: c.instance,
            access: c.access,
            audit_store: c.audit_store,
            protection: c.protection,
            objects: c.platform_objects,
            execution: Arc::downgrade(&c.execution),
            configuration: c.platform_sso,
        }
    }
    pub fn matches(&self, c: &Context) -> bool {
        self.tenant == c.tenant
            && self.instance == c.instance
            && Arc::ptr_eq(&self.access.registration, &c.access.registration)
            && Arc::ptr_eq(&self.access.authorization, &c.access.authorization)
            && Arc::ptr_eq(&self.audit_store, &c.audit_store)
            && Arc::ptr_eq(&self.protection, &c.protection)
            && Weak::ptr_eq(&self.execution, &Arc::downgrade(&c.execution))
            && match (&self.configuration, &c.platform_sso) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            }
    }
    pub fn get(&self) -> Option<Context> {
        Some(Context {
            tenant: self.tenant,
            instance: self.instance,
            access: self.access.clone(),
            audit_store: self.audit_store.clone(),
            protection: self.protection.clone(),
            platform_objects: self.objects.clone(),
            execution: self.execution.upgrade()?,
            platform_sso: self.configuration.clone(),
        })
    }
}
