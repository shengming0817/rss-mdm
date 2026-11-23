use crate::{Error, Failure};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
pub struct Store {
    pool: PgPool,
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
    pub(crate) async fn material_snapshot(
        &self,
        tenant: &str,
    ) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)").bind(tenant).execute(&mut *tx).await.map_err(db)?;
        Ok(tx)
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

/// Product registration identities are independent of Apple protocol identifiers.
pub(crate) fn device_id(id: uuid::Uuid) -> Result<rss_mdm_agent_wire::DeviceId, sqlx::Error> {
    rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}

impl Store {
    pub async fn locate_scep_attempt(
        &self,
        attempt: uuid::Uuid,
        enrollment: uuid::Uuid,
    ) -> Result<
        Option<(
            rss_request_context::TenantId,
            rss_transactional_messaging::fence::Epoch,
        )>,
        Error,
    > {
        let rows: Vec<(uuid::Uuid, i64)> = sqlx::query_as(
            "SELECT tenant_id,expected_epoch FROM mdm_apple.scep_attempt_tenants($1,$2)",
        )
        .bind(attempt)
        .bind(enrollment)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        match rows.as_slice() {
            [] => Ok(None),
            [(tenant, epoch)] => Ok(Some((
                rss_request_context::TenantId::parse(&tenant.to_string())
                    .map_err(|_| Error::Unauthorized)?,
                rss_transactional_messaging::fence::Epoch::new(*epoch)
                    .map_err(|_| Error::Unauthorized)?,
            ))),
            _ => Err(Error::Unauthorized),
        }
    }
    pub async fn locate_certificate(
        &self,
        fingerprint: [u8; 32],
    ) -> Result<Option<rss_request_context::TenantId>, Error> {
        let attempt = unique_tenant(
            sqlx::query_scalar("SELECT tenant_id FROM mdm_apple.scep_certificate_tenants($1)")
                .bind(fingerprint.as_slice())
                .fetch_all(&self.pool)
                .await
                .map_err(db)?,
        )?;
        let credential = self.registration.locate_certificate(fingerprint).await?;
        match (attempt, credential) {
            (Some(a), Some(b)) if a != b => Err(Error::Unauthorized),
            (Some(t), _) | (_, Some(t)) => Ok(Some(t)),
            _ => Ok(None),
        }
    }
}
fn unique_tenant(tenants: Vec<uuid::Uuid>) -> Result<Option<rss_request_context::TenantId>, Error> {
    match tenants.as_slice() {
        [] => Ok(None),
        [tenant] => rss_request_context::TenantId::parse(&tenant.to_string())
            .map(Some)
            .map_err(|_| Error::Unavailable(Failure::Database)),
        _ => Err(Error::Unauthorized),
    }
}

impl Store {
    pub async fn locate_account_configuration(
        &self,
        target: uuid::Uuid,
    ) -> Result<Option<rss_request_context::TenantId>, Error> {
        unique_tenant(
            sqlx::query_scalar("SELECT tenant_id FROM mdm_apple.account_configuration_tenants($1)")
                .bind(target)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?,
        )
    }
    pub async fn locate_account_domain(
        &self,
        target: &str,
    ) -> Result<Option<rss_request_context::TenantId>, Error> {
        unique_tenant(
            sqlx::query_scalar("SELECT tenant_id FROM mdm_apple.account_domain_tenants($1)")
                .bind(target)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?,
        )
    }
    pub async fn locate_ade_server(
        &self,
        target: uuid::Uuid,
    ) -> Result<Option<rss_request_context::TenantId>, Error> {
        unique_tenant(
            sqlx::query_scalar("SELECT tenant_id FROM mdm_apple.ade_server_tenants($1)")
                .bind(target)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?,
        )
    }
    pub async fn locate_account_flow(
        &self,
        id: uuid::Uuid,
    ) -> Result<
        Option<(
            rss_request_context::TenantId,
            rss_transactional_messaging::fence::Epoch,
        )>,
        Error,
    > {
        let rows: Vec<(uuid::Uuid, i64)> =
            sqlx::query_as("SELECT * FROM mdm_apple.account_flow_scopes($1)")
                .bind(id)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?;
        match rows.as_slice() {
            [] => Ok(None),
            [(tenant, epoch)] => Ok(Some((
                rss_request_context::TenantId::parse(&tenant.to_string())
                    .map_err(|_| Error::Unauthorized)?,
                rss_transactional_messaging::fence::Epoch::new(*epoch)
                    .map_err(|_| Error::Unauthorized)?,
            ))),
            _ => Err(Error::Unauthorized),
        }
    }
}

impl Store {
    pub async fn ade_work_scopes(
        &self,
        after: Option<(uuid::Uuid, i64)>,
        fresh_epoch: rss_transactional_messaging::fence::Epoch,
        observed_at: i64,
    ) -> Result<Vec<(uuid::Uuid, i64)>, Error> {
        sqlx::query_as("SELECT * FROM mdm_apple.ade_work_scopes($1,$2,$3,$4)")
            .bind(after.map(|v| v.0))
            .bind(after.map(|v| v.1))
            .bind(fresh_epoch.get())
            .bind(observed_at)
            .fetch_all(&self.pool)
            .await
            .map_err(db)
    }
}

impl Store {
    pub(crate) async fn push_channel_page(&self,after:Option<crate::push::Candidate>) -> Result<Vec<crate::push::Candidate>,Error>{
        sqlx::query_as::<_,crate::push::Candidate>("SELECT * FROM mdm_apple.push_channel_page($1,$2,$3)")
                   .bind(after.as_ref().map(|r|r.0)).bind(after.as_ref().map(|r|r.1)).bind(after.as_ref().map(|r|&r.2))
                   .fetch_all(&self.pool).await.map_err(db)
    }
    pub async fn maintenance_work_scopes(
        &self,
        after: Option<uuid::Uuid>,
    ) -> Result<Vec<uuid::Uuid>, Error> {
        sqlx::query_scalar("SELECT tenant_id FROM mdm_apple.maintenance_work_scopes($1)")
            .bind(after)
            .fetch_all(&self.pool)
            .await
            .map_err(db)
    }
}
