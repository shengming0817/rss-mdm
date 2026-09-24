//! Request-scoped product authorization, separate from Identity authentication facts.
use crate::{
    Error, authorization::Permission, device::coordinates::Coordinates, identity::Principal,
};
use rss_identity_postgres::AuthenticatedSession;

pub(crate) struct AuthorizedPrincipal {
    identity: Principal,
    authorization: Option<crate::authorization::Snapshot>,
}
impl AuthorizedPrincipal {
    pub(crate) fn from_identity(identity: Principal) -> Self {
        Self {
            identity,
            authorization: None,
        }
    }
    #[cfg(test)]
    pub(crate) fn new(session: AuthenticatedSession) -> Result<Self, Error> {
        Ok(Self::from_identity(Principal::new(session)?))
    }
    pub(crate) fn session(&self) -> &AuthenticatedSession {
        self.identity.session()
    }
    pub(crate) fn check_live(&self) -> Result<(), Error> {
        self.identity.check_live()
    }
    pub(crate) fn instance_id(&self) -> &str {
        self.identity.instance_id()
    }
    pub(crate) fn tenant_id(&self) -> &str {
        self.identity.tenant_id()
    }
    pub(crate) fn principal_id(&self) -> &str {
        self.identity.principal_id()
    }
    pub(crate) fn session_id(&self) -> String {
        self.identity.session_id()
    }
    pub(crate) fn user(&self) -> crate::authorization::User {
        crate::authorization::User {
            instance_id: self.instance_id().into(),
            tenant_id: self.tenant_id().into(),
            principal_id: self.principal_id().into(),
        }
    }
    pub(crate) async fn load_authorization(
        mut self,
        access: &crate::Database,
    ) -> Result<Self, Error> {
        self.authorization =
            Some(crate::authorization::store::authorization_snapshot(access, &self).await?);
        Ok(self)
    }
    pub(crate) fn authorization(&self) -> Result<&crate::authorization::Snapshot, Error> {
        self.check_live()?;
        self.authorization.as_ref().ok_or(Error::Unauthorized)
    }
    pub(crate) fn require(
        &self,
        operation: crate::authorization::Permission,
        device: Option<&str>,
    ) -> Result<(), Error> {
        self.authorization()?
            .require(self, operation, device)
            .map_err(Into::into)
    }
}
pub(crate) struct InventoryRead<'a> {
    pub(crate) proof: &'a AuthorizedPrincipal,
    pub(crate) device: String,
    pub(crate) coordinates: Coordinates,
}
pub(crate) struct DangerousAction<'a> {
    _proof: &'a AuthorizedPrincipal,
}
impl AuthorizedPrincipal {
    pub(crate) fn enrollment(&self, device: &str) -> Result<EnrollmentPermission<'_>, Error> {
        self.require(Permission::Enrollment, Some(device))?;
        Ok(EnrollmentPermission {
            proof: self,
            device: device.into(),
        })
    }
    pub(crate) fn inventory(
        &self,
        device: &str,
        coordinates: Coordinates,
    ) -> Result<InventoryRead<'_>, Error> {
        self.require(Permission::InventoryRead, Some(device))?;
        Ok(InventoryRead {
            proof: self,
            device: device.into(),
            coordinates,
        })
    }
    pub(crate) fn credentials(&self, device: &str) -> Result<(), Error> {
        self.require(Permission::Credentials, Some(device))
    }
    pub(crate) fn manage(&self, permission: Permission) -> Result<(), Error> {
        self.require(permission, None)
    }
    pub(crate) fn dangerous(&self, device: &str) -> Result<DangerousAction<'_>, Error> {
        self.require(Permission::DeviceWipe, Some(device))?;
        Ok(DangerousAction { _proof: self })
    }
}
pub(crate) struct EnrollmentPermission<'a> {
    pub(crate) proof: &'a AuthorizedPrincipal,
    pub(crate) device: String,
}
impl EnrollmentPermission<'_> {
    pub(crate) fn proof(&self) -> &AuthorizedPrincipal {
        self.proof
    }
    pub(crate) fn device(&self) -> &str {
        &self.device
    }
}

use std::sync::Arc;
#[derive(Clone)]
pub(crate) struct RequestAuth {
    pub(crate) proof: Arc<AuthorizedPrincipal>,
}
