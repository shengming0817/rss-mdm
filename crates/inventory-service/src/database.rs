use crate::{Error, Failure};
use sqlx::{PgPool, Postgres, Transaction};
#[derive(Clone)]
pub struct Store {
    profile: rss_mdm_install_support::StorageProfile,
    pool: PgPool,
}
impl Store {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn from_pool(profile: rss_mdm_install_support::StorageProfile, pool: PgPool) -> Self {
        Self { profile, pool }
    }
    pub(crate) async fn begin(&self, tenant: &str) -> Result<Transaction<'_, Postgres>, Error> {
        self.begin_delivery(tenant).await.map_err(db)
    }
    /// Preserve SQLSTATE only for the idempotent delivery acknowledgement seam.
    pub(crate) async fn begin_delivery(
        &self,
        tenant: &str,
    ) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)").bind(tenant).execute(&mut *tx).await?;
        Ok(tx)
    }
    pub(crate) async fn begin_execution(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
        let mut tx = self.begin_delivery(&binding.tenant().to_string()).await?;
        sqlx::query("SELECT set_config('rss.storage_target',$1,true),set_config('rss.storage_lineage',$2,true),set_config('rss.execution_epoch',$3,true)")
            .bind(uuid::Uuid::from_bytes(binding.storage().target()).simple().to_string())
            .bind(uuid::Uuid::from_bytes(binding.storage().lineage()).simple().to_string())
            .bind(binding.epoch().get().to_string()).execute(&mut *tx).await?;
        sqlx::query("SELECT rss_transactional_messaging.check_execution()")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }
    pub(crate) async fn delivery_scopes(
        &self,
        after: Option<(uuid::Uuid, i64)>,
    ) -> Result<Vec<(uuid::Uuid, i64)>, Error> {
        sqlx::query_as(crate::storage_profile::sql(self.profile).collection_delivery_scopes)
            .bind(after.map(|v| v.0))
            .bind(after.map(|v| v.1))
            .fetch_all(&self.pool)
            .await
            .map_err(db)
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
pub(crate) fn db(error: sqlx::Error) -> Error {
    let _ = error;
    Error::Unavailable(Failure::Database)
}

/// Validate product device coordinates at the native PostgreSQL boundary.
pub(crate) fn device_id(id: uuid::Uuid) -> Result<rss_mdm_agent_wire::DeviceId, sqlx::Error> {
    rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}
