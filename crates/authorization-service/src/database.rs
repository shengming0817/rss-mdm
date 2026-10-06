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
    /// Purpose is installation-owned, even for routes requiring identity but no grants.
    pub async fn require_tenant_purpose(
        &self,
        proof: &crate::context::AuthorizedPrincipal,
        management: bool,
    ) -> Result<(), Error> {
        let mut connection = None;
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            proof.check_live()?;
            connection = Some(self.acquire().await?);
            let binding = crate::tenancy::InstallationTenants::load(
                connection.as_mut().expect("acquired connection"),
            )
            .await?;
            binding.require(proof, crate::Permission::AuthorizationRead)?;
            if binding.is_management(proof.tenant_id()) != management {
                return Err(Error::Forbidden);
            }
            Ok(())
        })
        .await;
        if !matches!(result, Ok(Ok(())))
            && let Some(connection) = &mut connection
        {
            connection.close_on_drop();
        }
        result.map_err(|_| Error::Deadline)?
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
