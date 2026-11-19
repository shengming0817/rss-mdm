use crate::{Error, Failure};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
pub struct Store {
    pub(crate) pool: PgPool,
    pub(crate) registration: Arc<rss_mdm_registration_service::Store>,
    pub(crate) authorization: Arc<rss_mdm_authorization_service::Store>,
}
impl Store {
    pub fn from_pool(
        pool: PgPool,
        registration: Arc<rss_mdm_registration_service::Store>,
        authorization: Arc<rss_mdm_authorization_service::Store>,
    ) -> Self {
        Self {
            pool,
            registration,
            authorization,
        }
    }
    pub(crate) fn registration(&self) -> Arc<rss_mdm_registration_service::Store> {
        self.registration.clone()
    }
    pub(crate) async fn begin(&self, tenant: &str) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)").bind(tenant).execute(&mut *tx).await.map_err(db)?;
        Ok(tx)
    }
    pub(crate) async fn snapshot(&self, tenant: &str) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true)").bind(tenant).execute(&mut *tx).await.map_err(db)?;
        Ok(tx)
    }
    pub(crate) async fn confirm_certificate_query(
        &self,
        p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        before: &str,
    ) -> Result<(), Error> {
        p.check_live()?;
        let mut tx = self.begin(p.tenant_id()).await?;
        rss_mdm_authorization_service::lock_on(
            rss_mdm_install_support::StorageProfile::Mdm,
            &mut tx,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?;
        let auth = rss_mdm_authorization_service::snapshot_on(
            rss_mdm_install_support::StorageProfile::Mdm,
            &mut tx,
            p.tenant_id(),
            p.instance_id(),
        )
        .await?;
        if auth.query_binding(p)? != before {
            return Err(Error::Conflict);
        }
        p.check_live()?;
        tx.rollback().await.map_err(db)
    }
    pub(crate) async fn begin_read(
        &self,
        tenant: &str,
    ) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.begin(tenant).await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        Ok(tx)
    }
}
pub(crate) fn db(e: sqlx::Error) -> Error {
    if e.as_database_error()
        .and_then(|e| e.code())
        .is_some_and(|c| c == "40001" || c == "40P01")
    {
        Error::Conflict
    } else {
        Error::Unavailable(Failure::Database)
    }
}

/// Validate product UUIDs at this native channel's persistence boundary.
pub(crate) fn device_id(id: uuid::Uuid) -> Result<rss_mdm_agent_wire::DeviceId, sqlx::Error> {
    rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}

impl Store {
    /// Locate a current or pending renewal certificate without treating the locator as authority.
    pub async fn locate_certificate(
        &self,
        fingerprint: [u8; 32],
    ) -> Result<Option<rss_request_context::TenantId>, Error> {
        let rows: Vec<uuid::Uuid> =
            sqlx::query_scalar("SELECT tenant_id FROM mdm_windows.renewal_certificate_tenants($1)")
                .bind(fingerprint.as_slice())
                .fetch_all(&self.pool)
                .await
                .map_err(db)?;
        let renewal = match rows.as_slice() {
            [] => None,
            [tenant] => Some(
                rss_request_context::TenantId::parse(&tenant.to_string())
                    .map_err(|_| Error::Unavailable(Failure::Database))?,
            ),
            _ => return Err(Error::Unauthorized),
        };
        let credential = self.registration.locate_certificate(fingerprint).await?;
        match (renewal, credential) {
            (Some(a), Some(b)) if a != b => Err(Error::Unauthorized),
            (Some(t), _) | (_, Some(t)) => Ok(Some(t)),
            _ => Ok(None),
        }
    }
}

impl Store {
    pub async fn locate_entra_profile(
        &self,
        tenant: uuid::Uuid,
        audience: &str,
    ) -> Result<Option<rss_request_context::TenantId>, Error> {
        unique_tenant(
            sqlx::query_scalar("SELECT tenant_id FROM mdm_windows.entra_profile_tenants($1,$2)")
                .bind(tenant)
                .bind(audience)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?,
        )
    }
    pub async fn locate_entra_flow(
        &self,
        id: uuid::Uuid,
    ) -> Result<
        (
            rss_request_context::TenantId,
            rss_transactional_messaging::fence::Epoch,
        ),
        Error,
    > {
        let rows: Vec<(uuid::Uuid, i64)> =
            sqlx::query_as("SELECT * FROM mdm_windows.entra_flow_scopes($1)")
                .bind(id)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?;
        match rows.as_slice() {
            [(tenant, epoch)] => Ok((
                rss_request_context::TenantId::parse(&tenant.to_string())
                    .map_err(|_| Error::Unauthorized)?,
                rss_transactional_messaging::fence::Epoch::new(*epoch)
                    .map_err(|_| Error::Unauthorized)?,
            )),
            _ => Err(Error::Unauthorized),
        }
    }
}

impl Store {
    pub(crate) async fn next_session_expiry(
        &self,
        include_expired: bool,
    ) -> Result<Option<std::time::Duration>, Error> {
        let millis: Option<i64> =
            sqlx::query_scalar("SELECT mdm_windows.next_session_expiry_ms($1)")
                .bind(include_expired)
                .fetch_one(&self.pool)
                .await
                .map_err(db)?;
        Ok(millis.map(|ms| std::time::Duration::from_millis(ms.max(1) as u64)))
    }
    pub async fn retention_scopes(
        &self,
        after: Option<(uuid::Uuid, i64)>,
    ) -> Result<Vec<(uuid::Uuid, i64)>, Error> {
        sqlx::query_as("SELECT * FROM mdm_windows.retention_scopes($1,$2)")
            .bind(after.map(|v| v.0))
            .bind(after.map(|v| v.1))
            .fetch_all(&self.pool)
            .await
            .map_err(db)
    }
}

fn unique_tenant(rows: Vec<uuid::Uuid>) -> Result<Option<rss_request_context::TenantId>, Error> {
    match rows.as_slice() {
        [] => Ok(None),
        [tenant] => rss_request_context::TenantId::parse(&tenant.to_string())
            .map(Some)
            .map_err(|_| Error::Unauthorized),
        _ => Err(Error::Unauthorized),
    }
}
