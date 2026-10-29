use crate::{Error, Retirement};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
#[cfg(feature = "integration")]
type ReadGate = (tokio::sync::oneshot::Sender<()>, Arc<tokio::sync::Notify>);
pub struct Store {
    #[cfg(feature = "integration")]
    read_gate: std::sync::Mutex<Option<ReadGate>>,
    pool: PgPool,
    pub(crate) retirement: Arc<dyn Retirement>,
}
impl Store {
    pub fn from_pool(pool: PgPool, retirement: Arc<dyn Retirement>) -> Self {
        Self {
            pool,
            retirement,
            #[cfg(feature = "integration")]
            read_gate: Default::default(),
        }
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
        #[cfg(feature = "integration")]
        self.read_checkpoint().await?;
        proof.check_live()?;
        let mut tx = self.begin(proof.tenant_id()).await?;
        rss_mdm_authorization_service::lock_on(&mut tx, proof.tenant_id(), proof.instance_id())
            .await?;
        let current = rss_mdm_authorization_service::snapshot_on(
            &mut tx,
            proof.tenant_id(),
            proof.instance_id(),
        )
        .await?;
        if current.query_binding(proof)? != expected {
            return Err(Error::ReadConflict);
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

#[cfg(feature = "integration")]
impl Store {
    pub fn pause_query_before_authority(
        &self,
    ) -> (tokio::sync::oneshot::Receiver<()>, Arc<tokio::sync::Notify>) {
        let (send, receive) = tokio::sync::oneshot::channel();
        let resume = Arc::new(tokio::sync::Notify::new());
        assert!(
            self.read_gate
                .lock()
                .expect("read gate")
                .replace((send, resume.clone()))
                .is_none()
        );
        (receive, resume)
    }
    pub(crate) async fn read_checkpoint(&self) -> Result<(), Error> {
        let gate = self.read_gate.lock().expect("read gate").take();
        if let Some((send, resume)) = gate {
            let _ = send.send(());
            tokio::time::timeout(std::time::Duration::from_secs(5), resume.notified())
                .await
                .map_err(|_| Error::Storage)?;
        }
        Ok(())
    }
}
