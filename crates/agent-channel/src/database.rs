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
}
pub(crate) fn db(_: sqlx::Error) -> Error {
    Error::Unavailable(Failure::Database)
}
