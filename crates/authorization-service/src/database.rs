//! Authorization borrows the host-owned pool; it never exposes a connection owner.
use crate::Error;
use sqlx::{PgPool, Postgres, Transaction};
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}
impl Store {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
    pub(crate) async fn acquire(&self) -> Result<sqlx::pool::PoolConnection<Postgres>, Error> {
        self.pool.acquire().await.map_err(db)
    }
    pub(crate) async fn configure_transaction(
        tx: &mut Transaction<'_, Postgres>,
        tenant: &str,
    ) -> Result<(), Error> {
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)")
            .bind(tenant).execute(&mut **tx).await.map_err(db)?;
        Ok(())
    }
}
pub(crate) fn db(_: sqlx::Error) -> Error {
    Error::Storage
}
