use crate::{Error, Failure};
use sqlx::{PgPool, Postgres, Transaction};
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}
impl Store {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
    pub(crate) async fn begin(&self, tenant: &str) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)").bind(tenant).execute(&mut *tx).await.map_err(db)?;
        Ok(tx)
    }
    pub(crate) async fn begin_read(
        &self,
        tenant: &str,
    ) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)").bind(tenant).execute(&mut *tx).await.map_err(db)?;
        Ok(tx)
    }
}
pub(crate) fn db(_: sqlx::Error) -> Error {
    Error::Unavailable(Failure::Database)
}
