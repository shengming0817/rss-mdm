//! Installation owns the management tenant; grants never determine a tenant's purpose.
use crate::{Error, Permission, Rule, Subject, context::AuthorizedPrincipal};
use sqlx::{PgConnection, Row};

pub const MANAGEMENT_EPOCH: i64 = 1;

pub struct InstallationTenants {
    instance: String,
    management: String,
}
impl InstallationTenants {
    /// Load immutable coordinates from the installation, on the caller's scoped connection.
    pub async fn load(connection: &mut PgConnection) -> Result<Self, Error> {
        let row = sqlx::query(
            "SELECT instance_id::text,management_tenant_id::text FROM public.mdm_installation",
        )
        .fetch_one(connection)
        .await
        .map_err(crate::database::db)?;
        Ok(Self {
            instance: row.try_get("instance_id").map_err(crate::database::db)?,
            management: row
                .try_get("management_tenant_id")
                .map_err(crate::database::db)?,
        })
    }
    pub fn management_tenant(&self) -> &str {
        &self.management
    }
    pub fn is_management(&self, tenant: &str) -> bool {
        tenant == self.management
    }
    pub fn require(
        &self,
        proof: &AuthorizedPrincipal,
        permission: Permission,
    ) -> Result<(), Error> {
        proof.check_live()?;
        self.require_identity(proof.instance_id(), proof.tenant_id(), permission)
    }
    pub(crate) fn require_identity(
        &self,
        instance: &str,
        tenant: &str,
        permission: Permission,
    ) -> Result<(), Error> {
        if instance != self.instance
            || (self.is_management(tenant) && !permission.management_allowed())
            || (!self.is_management(tenant) && permission.tenant_management())
        {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    pub(crate) fn validate_rule(&self, tenant: &str, rule: &Rule) -> Result<(), Error> {
        let management = self.is_management(tenant);
        if (management && !matches!(rule.subject, Subject::User { .. }))
            || rule.grants.iter().any(|grant| {
                if management {
                    !grant.operation.management_allowed()
                } else {
                    grant.operation.tenant_management()
                }
            })
        {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
}
