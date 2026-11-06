//! Request-scoped product authorization, separate from Identity authentication facts.
use crate::{Error, Permission};
use rss_identity_postgres::AuthenticatedSession;

pub struct AuthorizedPrincipal {
    profile: rss_mdm_install_support::StorageProfile,
    authority_profile: rss_mdm_install_support::StorageProfile,
    identity: Principal,
    authorization: Option<crate::Snapshot>,
}
impl AuthorizedPrincipal {
    /// Bind a verified identity to the host's product and authority before any purpose check.
    pub fn from_identity(access: &crate::Store, identity: Principal) -> Result<Self, Error> {
        if identity
            .key_proof()
            .is_some_and(|key| key.authority_profile != access.authority_profile())
        {
            return Err(Error::Forbidden);
        }
        Ok(Self {
            profile: access.profile(),
            authority_profile: access.authority_profile(),
            identity,
            authorization: None,
        })
    }
    /// Bind authenticated identity to the same tenant's audit facts, including denied requests.
    /// Expiry/authorization is checked by the operation; recording the known actor is not a grant.
    pub fn bind_audit(&self, audit: &rss_mdm_audit_integration::RequestAudit) -> Result<(), Error> {
        if audit.profile() != self.profile() || audit.tenant() != self.tenant_id() {
            audit.intent(rss_mdm_audit_integration::AuditIntent::Security);
            return Err(Error::Forbidden);
        }
        if let Some(kind) = self.identity.audit_kind() {
            audit.set_authenticated(self.principal_id(), self.instance_id(), kind);
        } else {
            audit.set_principal(self.principal_id(), self.instance_id());
        }
        Ok(())
    }
    pub(crate) fn from_initialization(
        authority: Arc<crate::baseline::Authority>,
        clock: Arc<dyn rss_request_context::Clock>,
    ) -> Self {
        let user = authority.user().clone();
        Self {
            profile: authority.profile(),
            authority_profile: authority.profile(),
            identity: Principal {
                subject: user.principal_id.clone(),
                actor: crate::Actor::Account { user },
                proof: Authentication::Initialization {
                    authority,
                    deadline: clock.now() + std::time::Duration::from_secs(60),
                    clock,
                },
            },
            authorization: None,
        }
    }
    /// Durable attempts cannot leave their fixed initialization object set.
    pub fn require_initialization_target(&self, target: &str) -> Result<(), Error> {
        if self
            .initialization_authority()
            .is_some_and(|a| !a.allows_target(target))
        {
            return Err(Error::Forbidden);
        }
        self.check_live()
    }
    pub fn initialization_authority(&self) -> Option<&crate::baseline::Authority> {
        match &self.identity.proof {
            Authentication::Initialization { authority, .. } => Some(authority),
            _ => None,
        }
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
    /// Recent authentication is an assurance fact, independent of session issuance/refresh.
    pub fn recently_authenticated(&self, now: i64, max_age_seconds: i64) -> Result<bool, Error> {
        let assurance = self
            .session()?
            .assurance()
            .map_err(|_| Error::Unauthorized)?;
        Ok(recent_authentication(
            assurance.auth_time(),
            now,
            max_age_seconds,
        ))
    }

    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    /// Rules and credentials source bound by the host's Store during authorization loading.
    pub fn authority_profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.authority_profile
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
        format!(
            "{}:{}:{}",
            self.profile.name(),
            self.authority_profile.name(),
            self.identity.credential_binding()
        )
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
        if self.profile != access.profile()
            || self.authority_profile != access.authority_profile()
            || self
                .identity
                .key_proof()
                .is_some_and(|k| k.authority_profile != access.authority_profile())
            || self
                .initialization_authority()
                .is_some_and(|a| a.profile() != access.authority_profile())
        {
            return Err(Error::Forbidden);
        }
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
    pub sessions: crate::session::SessionAuthority,
    pub deadline: std::time::Instant,
}
impl RequestAuth {
    pub fn remaining(
        &self,
    ) -> Result<rss_transactional_messaging::policy::OperationDeadline, Error> {
        let remaining = self
            .deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or(Error::Deadline)?;
        if remaining.is_zero() {
            return Err(Error::Deadline);
        }
        Ok(rss_transactional_messaging::policy::OperationDeadline::from_remaining(remaining))
    }
    /// Refresh Identity before acquiring product locks; never renew the request budget.
    pub async fn revalidate(&self) -> Result<Option<crate::session::RevalidatedSession>, Error> {
        self.proof.check_live()?;
        if self.sessions.tenant().to_string() != self.proof.tenant_id() {
            return Err(Error::Forbidden);
        }
        match &self.proof.identity.proof {
            Authentication::Account(session) => {
                let reference = session
                    .reference()
                    .map_err(crate::session::authority_error)?;
                Ok(Some(
                    self.sessions.recheck(&reference, self.remaining()?).await?,
                ))
            }
            Authentication::ApiKey(_) | Authentication::Initialization { .. } => {
                self.remaining()?;
                Ok(None)
            }
        }
    }
    /// Only fresh session facts can produce an account's response authorization binding.
    pub fn current_binding(
        &self,
        snapshot: &crate::Snapshot,
        fresh: Option<&crate::session::RevalidatedSession>,
    ) -> Result<String, Error> {
        self.remaining()?;
        match (&self.proof.identity.proof, fresh) {
            (Authentication::Account(_), Some(facts)) => {
                snapshot.query_binding_revalidated(&self.proof, facts)
            }
            (Authentication::ApiKey(_) | Authentication::Initialization { .. }, None) => {
                snapshot.query_binding(&self.proof)
            }
            _ => Err(Error::Unauthorized),
        }
    }
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
    Initialization {
        authority: Arc<crate::baseline::Authority>,
        deadline: std::time::Instant,
        clock: Arc<dyn rss_request_context::Clock>,
    },
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
            Authentication::ApiKey(_) | Authentication::Initialization { .. } => {
                Err(Error::Forbidden)
            }
        }
    }
    fn shared_session(&self) -> Result<Arc<AuthenticatedSession>, Error> {
        match &self.proof {
            Authentication::Account(session) => Ok(session.clone()),
            Authentication::ApiKey(_) | Authentication::Initialization { .. } => {
                Err(Error::Forbidden)
            }
        }
    }
    fn key_proof(&self) -> Option<&crate::api_key::KeyProof> {
        match &self.proof {
            Authentication::ApiKey(proof) => Some(proof),
            _ => None,
        }
    }
    fn audit_kind(&self) -> Option<rss_mdm_audit_integration::AuthenticationKind> {
        use rss_mdm_audit_integration::AuthenticationKind;
        match &self.proof {
            Authentication::ApiKey(_) => Some(AuthenticationKind::ApiKey),
            Authentication::Initialization { .. } => None,
            Authentication::Account(proof) => Some(match proof.view().credential_kind {
                rss_identity_core::session::CredentialKind::Cookie => AuthenticationKind::Cookie,
                rss_identity_core::session::CredentialKind::Bearer => AuthenticationKind::Bearer,
            }),
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
            Authentication::Initialization {
                deadline, clock, ..
            } if clock.now() < *deadline => Ok(()),
            Authentication::Initialization { .. } => Err(Error::Unauthorized),
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
            Authentication::Initialization { .. } => {
                format!("initialization:{}", self.principal_id())
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

fn recent_authentication(authenticated: Option<i64>, now: i64, max_age: i64) -> bool {
    max_age > 0
        && authenticated.is_some_and(|at| {
            at > 0
                && now
                    .checked_sub(at)
                    .is_some_and(|age| (0..=max_age).contains(&age))
        })
}
#[cfg(test)]
mod recent_tests {
    #[test]
    fn unknown_future_old_and_overflow_authentication_are_rejected() {
        for time in [
            None,
            Some(0),
            Some(-1),
            Some(1001),
            Some(699),
            Some(i64::MIN),
        ] {
            assert!(!super::recent_authentication(time, 1000, 300));
        }
        assert!(super::recent_authentication(Some(700), 1000, 300));
        assert!(super::recent_authentication(Some(1000), 1000, 300));
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use rss_mdm_install_support::StorageProfile;
    use uuid::Uuid;

    struct Clock(std::time::Instant);
    impl rss_request_context::Clock for Clock {
        fn now(&self) -> std::time::Instant {
            self.0
        }
    }

    #[allow(clippy::disallowed_methods, reason = "fixed test clock origin")]
    fn key_principal(
        product: StorageProfile,
        source: StorageProfile,
    ) -> (AuthorizedPrincipal, crate::Snapshot) {
        let user = crate::User {
            tenant_id: Uuid::from_u128(1).to_string(),
            instance_id: Uuid::from_u128(2).to_string(),
            principal_id: Uuid::from_u128(3).to_string(),
        };
        let now = std::time::Instant::now();
        let id = Uuid::from_u128(4);
        let key = crate::api_key::KeyProof {
            authority_profile: source,
            instance: user.instance_id.clone(),
            tenant: user.tenant_id.clone(),
            id,
            credential_revision: 1,
            deadline: now + std::time::Duration::from_secs(10),
            clock: Arc::new(Clock(now)),
            authority_revision: 1,
        };
        let principal = AuthorizedPrincipal {
            profile: product,
            authority_profile: source,
            identity: Principal::from_key(key),
            authorization: None,
        };
        let snapshot = crate::Snapshot {
            rules: vec![],
            groups: vec![],
            keys: vec![crate::api_key::KeyRecord {
                id,
                revision: 1,
                authority_revision: 1,
                credential_revision: 1,
                metadata: crate::api_key::KeyMetadata {
                    name: "operator".into(),
                    enabled: true,
                    expires_at: None,
                    grants: vec![crate::Grant {
                        operation: Permission::AccountWrite,
                        scope: crate::Scope::AllDevices,
                    }],
                },
                created_by: user,
                created_at: 1,
                revoked: false,
            }],
            installation: None,
        };
        (principal, snapshot)
    }

    #[test]
    fn product_audit_and_authority_source_remain_distinct() {
        let (mut proof, snapshot) = key_principal(StorageProfile::Da, StorageProfile::Mdm);
        let evidence =
            crate::OperationAuthority::all_devices(&snapshot, &proof, Permission::AccountWrite)
                .unwrap();
        let document = serde_json::to_value(evidence).unwrap();
        assert_eq!(document["profile"], "da");
        assert_eq!(document["source"], "mdm");

        let audit = |product| {
            rss_mdm_audit_integration::RequestAudit::new(
                product,
                proof.tenant_id().into(),
                "test",
                rss_mdm_audit_integration::AuditIntent::Management,
            )
        };
        assert!(proof.bind_audit(&audit(StorageProfile::Da)).is_ok());
        assert!(proof.bind_audit(&audit(StorageProfile::Mdm)).is_err());

        let bound = snapshot.query_binding(&proof).unwrap();
        let credential = proof.credential_binding();
        for (product, source) in [
            (StorageProfile::Mdm, StorageProfile::Mdm),
            (StorageProfile::Da, StorageProfile::Da),
        ] {
            let (other, snapshot) = key_principal(product, source);
            assert_ne!(snapshot.query_binding(&other).unwrap(), bound);
            assert_ne!(other.credential_binding(), credential);
        }

        // A matching key ID and grants from another source cannot validate this credential.
        proof.authority_profile = StorageProfile::Da;
        assert!(snapshot.query_binding(&proof).is_err());
        assert!(
            crate::OperationAuthority::all_devices(&snapshot, &proof, Permission::AccountWrite)
                .is_err()
        );
    }
}
