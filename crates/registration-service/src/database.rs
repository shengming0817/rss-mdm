use crate::{Error, Retirement};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;

pub struct Store {
    profile: rss_mdm_install_support::StorageProfile,
    pool: PgPool,
    pub(crate) retirement: Arc<dyn Retirement>,
}
impl Store {
    pub fn from_pool(
        profile: rss_mdm_install_support::StorageProfile,
        pool: PgPool,
        retirement: Arc<dyn Retirement>,
    ) -> Self {
        Self {
            profile,
            pool,
            retirement,
        }
    }
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub(crate) async fn begin(&self, tenant: &str) -> Result<Transaction<'_, Postgres>, Error> {
        self.begin_mode(tenant, false).await
    }
    pub(crate) async fn snapshot(&self, tenant: &str) -> Result<Transaction<'_, Postgres>, Error> {
        self.begin_mode(tenant, true).await
    }
    /// Check current authorization only after the data snapshot has been released.
    pub(crate) async fn confirm_query(
        &self,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        expected: &str,
    ) -> Result<(), Error> {
        if proof.profile() != self.profile {
            return Err(Error::Forbidden);
        }
        proof.check_live()?;
        let mut tx = self.begin(proof.tenant_id()).await?;
        rss_mdm_authorization_service::lock_on(
            self.profile,
            &mut tx,
            proof.tenant_id(),
            proof.instance_id(),
        )
        .await?;
        let current = rss_mdm_authorization_service::snapshot_on(
            self.profile,
            &mut tx,
            proof.tenant_id(),
            proof.instance_id(),
        )
        .await?;
        if current.query_binding(proof)? != expected {
            return Err(Error::ReadConflict);
        }
        if proof.profile() != self.profile {
            return Err(Error::Forbidden);
        }
        proof.check_live()?;
        tx.rollback().await.map_err(db)
    }

    async fn begin_mode(
        &self,
        tenant: &str,
        read_only: bool,
    ) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        if read_only {
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)")
            .bind(tenant).execute(&mut *tx).await.map_err(db)?;
        Ok(tx)
    }
}
pub(crate) fn db(_: sqlx::Error) -> Error {
    Error::Storage
}
