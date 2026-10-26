//! Tenant-owned API credentials. Creator coordinates are audit metadata only.
use crate::{Error, Grant, Permission, User};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyMetadata {
    pub name: String,
    pub enabled: bool,
    pub expires_at: Option<i64>,
    pub grants: Vec<Grant>,
}
impl KeyMetadata {
    pub fn validate(&self) -> Result<(), Error> {
        crate::exact_id(&self.name)?;
        if self.expires_at.is_some_and(|value| value <= 0)
            || self.grants.is_empty()
            || self.grants.len() > 256
        {
            return Err(Error::Malformed);
        }
        for (index, grant) in self.grants.iter().enumerate() {
            grant.validate()?;
            if !grant.operation.api_key_allowed() || self.grants[..index].contains(grant) {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
}
impl Permission {
    pub fn api_key_allowed(self) -> bool {
        !self.tenant_management()
            && !matches!(
                self,
                Self::IdentityAccountsManage
                    | Self::IdentityProvidersManage
                    | Self::EnterpriseApplicationsWrite
                    | Self::AuthorizationRead
                    | Self::AuthorizationWrite
                    | Self::UserGroupRead
                    | Self::UserGroupWrite
                    | Self::DepartmentRead
            )
    }
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyRecord {
    pub id: Uuid,
    pub revision: u64,
    pub authority_revision: u64,
    pub credential_revision: u64,
    pub metadata: KeyMetadata,
    pub created_by: User,
    pub created_at: i64,
    pub revoked: bool,
}
/// Constructed only after a tenant-scoped database credential lookup.
pub(crate) struct KeyProof {
    pub(crate) instance: String,
    pub(crate) tenant: String,
    pub(crate) id: Uuid,
    pub(crate) credential_revision: u64,
    pub(crate) deadline: std::time::Instant,
    pub(crate) clock: std::sync::Arc<dyn rss_request_context::Clock>,
    pub(crate) authority_revision: u64,
}

impl crate::Store {
    pub async fn authenticate_key(
        &self,
        tenant: &str,
        secret: &crate::credential::ApiKeySecret,
    ) -> Result<crate::context::Principal, Error> {
        use sqlx::{Acquire, Row};
        let start = self.clock.now();
        let mut connection = None;
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            connection = Some(self.acquire().await?);
            let mut tx = connection.as_mut().expect("acquired").begin().await.map_err(crate::database::db)?;
            Self::configure_transaction(&mut tx, tenant).await?;
            let instance: String = sqlx::query_scalar("SELECT instance_id::text FROM public.mdm_installation WHERE singleton")
                .fetch_one(&mut *tx).await.map_err(crate::database::db)?;
            let row = sqlx::query("SELECT authority_revision,credential_revision,extract(epoch FROM (to_timestamp(expires_at)-clock_timestamp()))::double precision AS remaining FROM mdm_access.api_keys WHERE tenant_id=$1::uuid AND instance=$2::uuid AND id=$3 AND secret_digest=$4 AND enabled AND NOT revoked AND (expires_at IS NULL OR to_timestamp(expires_at)>clock_timestamp())")
                .bind(tenant).bind(&instance).bind(secret.id()).bind(secret.digest(&instance, tenant))
                .fetch_optional(&mut *tx).await.map_err(crate::database::db)?.ok_or(Error::Unauthorized)?;
            let revision: i64 = row.try_get("credential_revision").map_err(crate::database::db)?;
            let authority_revision: i64 = row.try_get("authority_revision").map_err(crate::database::db)?;
            let remaining: Option<f64> = row.try_get("remaining").map_err(crate::database::db)?;
            let seconds = remaining.unwrap_or(10.0).clamp(0.0, 10.0);
            let proof = KeyProof { clock: self.clock.clone(), authority_revision: authority_revision.try_into().map_err(|_| Error::Corrupt)?, instance, tenant: tenant.into(), id: secret.id(), credential_revision: revision.try_into().map_err(|_| Error::Corrupt)?, deadline: start + std::time::Duration::from_secs_f64(seconds) };
            tx.rollback().await.map_err(crate::database::db)?;
            let principal = crate::context::Principal::from_key(proof);
            principal.check_live()?;
            Ok(principal)
        }).await;
        if !matches!(result, Ok(Ok(_)))
            && let Some(connection) = &mut connection
        {
            connection.close_on_drop();
        }
        result.map_err(|_| Error::Deadline)?
    }
}
