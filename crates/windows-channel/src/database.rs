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
        rss_mdm_authorization_service::lock_on(&mut tx, p.tenant_id(), p.instance_id()).await?;
        let auth =
            rss_mdm_authorization_service::snapshot_on(&mut tx, p.tenant_id(), p.instance_id())
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
pub(crate) fn db(_: sqlx::Error) -> Error {
    Error::Unavailable(Failure::Database)
}
