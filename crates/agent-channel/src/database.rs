use crate::{Error, Failure};
use sqlx::{PgPool, Postgres, Transaction};
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
