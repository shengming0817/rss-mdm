//! Request-scoped product authorization, separate from Identity authentication facts.
use crate::{Error, Permission};
use rss_identity_postgres::AuthenticatedSession;

pub struct AuthorizedPrincipal {
    identity: Principal,
    authorization: Option<crate::Snapshot>,
}
impl AuthorizedPrincipal {
    pub fn from_identity(identity: Principal) -> Self {
        Self {
            identity,
            authorization: None,
        }
    }
    pub fn new(session: AuthenticatedSession) -> Result<Self, Error> {
        Ok(Self::from_identity(Principal::new(session)?))
    }
    /// Bind authenticated identity to the same tenant's audit facts, including denied requests.
    /// Expiry/authorization is checked by the operation; recording the known actor is not a grant.
    pub fn bind_audit(&self, audit: &rss_mdm_audit_integration::RequestAudit) -> Result<(), Error> {
        if audit.tenant() != self.tenant_id() {
            return Err(Error::Forbidden);
        }
        audit.set_principal(self.principal_id(), self.instance_id());
        Ok(())
    }
    pub fn session(&self) -> &AuthenticatedSession {
        self.identity.session()
    }
    pub fn check_live(&self) -> Result<(), Error> {
        self.identity.check_live()
    }
    pub fn instance_id(&self) -> &str {
        self.identity.instance_id()
    }
    pub fn tenant_id(&self) -> &str {
        self.identity.tenant_id()
    }
    pub fn principal_id(&self) -> &str {
        self.identity.principal_id()
    }
    pub fn session_id(&self) -> String {
        self.identity.session_id()
    }
    pub fn user(&self) -> crate::User {
        crate::User {
            instance_id: self.instance_id().into(),
            tenant_id: self.tenant_id().into(),
            principal_id: self.principal_id().into(),
        }
    }
    pub async fn load_authorization(mut self, access: &crate::Store) -> Result<Self, Error> {
        self.authorization = Some(crate::store::authorization_snapshot(access, &self).await?);
        Ok(self)
    }
    pub fn authorization(&self) -> Result<&crate::Snapshot, Error> {
        self.check_live()?;
        self.authorization.as_ref().ok_or(Error::Unauthorized)
    }
    pub fn require_all_devices(&self, permission: crate::Permission) -> Result<(), Error> {
        let grants = self.authorization()?.effective(self)?;
        if grants.iter().any(|g| {
            g.grant.operation == permission && matches!(g.grant.scope, crate::Scope::AllDevices)
        }) {
            self.check_live()
        } else {
            Err(Error::Forbidden)
        }
    }
    pub fn require(&self, operation: crate::Permission, device: Option<&str>) -> Result<(), Error> {
        self.authorization()?
            .require(self, operation, device)
            .map_err(Into::into)
    }
}
pub struct DangerousAction<'a> {
    _proof: &'a AuthorizedPrincipal,
}
impl AuthorizedPrincipal {
    pub fn enrollment(&self, device: &str) -> Result<EnrollmentPermission<'_>, Error> {
        self.require(Permission::Enrollment, Some(device))?;
        Ok(EnrollmentPermission {
            proof: self,
            device: device.into(),
        })
    }
    pub fn credentials(&self, device: &str) -> Result<(), Error> {
        self.require(Permission::Credentials, Some(device))
    }
    pub fn manage(&self, permission: Permission) -> Result<(), Error> {
        self.require(permission, None)
    }
    pub fn dangerous(&self, device: &str) -> Result<DangerousAction<'_>, Error> {
        self.require(Permission::DeviceWipe, Some(device))?;
        Ok(DangerousAction { _proof: self })
    }
}
pub struct EnrollmentPermission<'a> {
    pub proof: &'a AuthorizedPrincipal,
    pub device: String,
}
impl EnrollmentPermission<'_> {
    pub fn proof(&self) -> &AuthorizedPrincipal {
        self.proof
    }
    pub fn device(&self) -> &str {
        &self.device
    }
}

use std::sync::Arc;
#[derive(Clone)]
pub struct RequestAuth {
    pub proof: Arc<AuthorizedPrincipal>,
}

/// A single private projection, created only from a request's authoritative component result.
pub struct Principal {
    session: AuthenticatedSession,
    instance: String,
    tenant: String,
    principal: String,
}
impl Principal {
    pub fn new(session: AuthenticatedSession) -> Result<Self, Error> {
        session.assurance().map_err(|_| Error::Unauthorized)?;
        Ok(Self {
            instance: session.instance().to_string(),
            tenant: session.account().tenant.to_string(),
            principal: session.account().principal.as_uuid().to_string(),
            session,
        })
    }
    pub fn session(&self) -> &AuthenticatedSession {
        &self.session
    }

    pub fn check_live(&self) -> Result<(), Error> {
        self.session
            .assurance()
            .map(|_| ())
            .map_err(|_| Error::Unauthorized)
    }
    pub fn instance_id(&self) -> &str {
        &self.instance
    }
    pub fn tenant_id(&self) -> &str {
        &self.tenant
    }
    pub fn session_id(&self) -> String {
        self.session.view().id.to_string()
    }
    pub fn principal_id(&self) -> &str {
        &self.principal
    }
}
