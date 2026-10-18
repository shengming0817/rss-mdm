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
        audit.set_authenticated(
            self.principal_id(),
            self.instance_id(),
            self.identity.audit_kind(),
        );
        Ok(())
    }
    pub fn shared_session(&self) -> Result<Arc<AuthenticatedSession>, Error> {
        self.identity.shared_session()
    }
    pub fn session(&self) -> Result<&AuthenticatedSession, Error> {
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
    pub fn session_id(&self) -> Result<String, Error> {
        Ok(self.session()?.view().id.to_string())
    }
    pub fn credential_binding(&self) -> String {
        self.identity.credential_binding()
    }
    pub fn actor(&self) -> crate::Actor {
        self.identity.actor.clone()
    }
    pub(crate) fn key_proof(&self) -> Option<&crate::api_key::KeyProof> {
        self.identity.key_proof()
    }
    pub fn user(&self) -> Result<crate::User, Error> {
        self.identity.actor.account().cloned()
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
        self.authorization()?.require_all_devices(self, permission)
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
            self_service: false,
        })
    }
    /// Live identity for a self-service request. Registration validates its server-owned target.
    pub fn self_enrollment(&self, device: &str) -> Result<EnrollmentPermission<'_>, Error> {
        self.session()?;
        self.check_live()?;
        Ok(EnrollmentPermission {
            proof: self,
            device: device.into(),
            self_service: true,
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
    self_service: bool,
    pub proof: &'a AuthorizedPrincipal,
    pub device: String,
}
impl EnrollmentPermission<'_> {
    pub fn self_service(&self) -> bool {
        self.self_service
    }
    pub fn check(&self) -> Result<(), Error> {
        if self.self_service {
            self.proof.check_live()
        } else {
            self.proof
                .require(Permission::Enrollment, Some(&self.device))
        }
    }
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
    proof: Authentication,
    actor: crate::Actor,
    subject: String,
}
enum Authentication {
    Account(Arc<AuthenticatedSession>),
    ApiKey(crate::api_key::KeyProof),
}
impl Principal {
    pub fn new(session: AuthenticatedSession) -> Result<Self, Error> {
        session.assurance().map_err(|_| Error::Unauthorized)?;
        let user = crate::User {
            instance_id: session.instance().to_string(),
            tenant_id: session.account().tenant.to_string(),
            principal_id: session.account().principal.as_uuid().to_string(),
        };
        Ok(Self {
            subject: user.principal_id.clone(),
            actor: crate::Actor::Account { user },
            proof: Authentication::Account(Arc::new(session)),
        })
    }
    pub(crate) fn from_key(proof: crate::api_key::KeyProof) -> Self {
        let actor = crate::Actor::ApiKey {
            instance: proof.instance.clone(),
            tenant: proof.tenant.clone(),
            id: proof.id,
        };
        Self {
            subject: actor.subject(),
            actor,
            proof: Authentication::ApiKey(proof),
        }
    }
    pub fn session(&self) -> Result<&AuthenticatedSession, Error> {
        match &self.proof {
            Authentication::Account(session) => Ok(session),
            Authentication::ApiKey(_) => Err(Error::Forbidden),
        }
    }
    fn shared_session(&self) -> Result<Arc<AuthenticatedSession>, Error> {
        match &self.proof {
            Authentication::Account(session) => Ok(session.clone()),
            Authentication::ApiKey(_) => Err(Error::Forbidden),
        }
    }
    fn key_proof(&self) -> Option<&crate::api_key::KeyProof> {
        match &self.proof {
            Authentication::ApiKey(proof) => Some(proof),
            _ => None,
        }
    }
    fn audit_kind(&self) -> rss_mdm_audit_integration::AuthenticationKind {
        use rss_mdm_audit_integration::AuthenticationKind;
        match &self.proof {
            Authentication::ApiKey(_) => AuthenticationKind::ApiKey,
            Authentication::Account(proof) => match proof.view().credential_kind {
                rss_identity_core::session::CredentialKind::Cookie => AuthenticationKind::Cookie,
                rss_identity_core::session::CredentialKind::Bearer => AuthenticationKind::Bearer,
            },
        }
    }
    pub fn check_live(&self) -> Result<(), Error> {
        match &self.proof {
            Authentication::Account(session) => session
                .assurance()
                .map(|_| ())
                .map_err(|_| Error::Unauthorized),
            Authentication::ApiKey(proof) if proof.clock.now() < proof.deadline => Ok(()),
            Authentication::ApiKey(_) => Err(Error::Unauthorized),
        }
    }
    pub fn instance_id(&self) -> &str {
        self.actor.instance_id()
    }
    pub fn tenant_id(&self) -> &str {
        self.actor.tenant_id()
    }
    pub fn principal_id(&self) -> &str {
        &self.subject
    }
    pub fn credential_binding(&self) -> String {
        match &self.proof {
            Authentication::Account(session) => format!(
                "{}:{}",
                session.view().credential_kind.as_str(),
                session.view().id
            ),
            Authentication::ApiKey(proof) => {
                format!("api-key:{}:{}", proof.id, proof.credential_revision)
            }
        }
    }
}

/// Audit identity is derived solely from Identity's live native proof.
pub fn bind_native_audit(
    proof: &crate::entra::RevalidatedAccount,
    audit: &rss_mdm_audit_integration::RequestAudit,
) -> Result<(), Error> {
    proof.check_live().map_err(|_| Error::Unauthorized)?;
    if audit.tenant() != proof.account().tenant.to_string() {
        return Err(Error::Forbidden);
    }
    audit.set_principal(
        &proof.account().principal.as_uuid().to_string(),
        &proof.instance().to_string(),
    );
    Ok(())
}
