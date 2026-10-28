//! Content-only admission. A session lock spans physical work, never a network transaction.
use crate::{Error, Store, storage};
use sqlx::{Postgres, pool::PoolConnection};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Read,
    Mutation,
}
impl Kind {
    pub(crate) fn discriminator(self) -> i64 {
        match self {
            Self::Read => 30040,
            Self::Mutation => 30041,
        }
    }
}

/// Kept by the actual I/O owner (including blocking work), not only its awaiting future.
/// Closing this dedicated session releases locks while retaining its pool slot until close.
pub(crate) struct Permit {
    connection: Option<PoolConnection<Postgres>>,
    cleanup: tokio_util::task::TaskTracker,
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take()
            && tokio::runtime::Handle::try_current().is_ok()
        {
            self.cleanup.spawn(async move {
                let _ = connection.close().await;
            });
        }
    }
}
impl Store {
    pub(crate) async fn admit(&self, kind: Kind) -> Result<Arc<Permit>, Error> {
        if !self.backend.available() {
            return Err(Error::Storage);
        }
        let timeout = std::time::Duration::from_secs(6);
        let mut connection = tokio::time::timeout(timeout, self.admission_pool.acquire())
            .await
            .map_err(|_| Error::Deadline)?
            .map_err(|_| storage())?;
        // A cancelled lock query must close the session, never return a possibly locked one.
        connection.close_on_drop();
        let mut permit = Permit {
            connection: Some(connection),
            cleanup: self.cleanup_tasks.clone(),
        };
        let c = permit.connection.as_mut().ok_or(Error::Invariant)?;
        let acquired: bool = tokio::time::timeout(
            timeout,
            sqlx::query_scalar("SELECT pg_try_advisory_lock_shared(hashtextextended($1,$2))")
                .bind(self.tenant.to_string())
                .bind(kind.discriminator())
                .fetch_one(&mut **c),
        )
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(|_| storage())?;
        if !acquired {
            return Err(Error::Conflict);
        }
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false),set_config('statement_timeout','6000',false)")
            .bind(self.tenant.to_string()).execute(&mut **c).await.map_err(|_| storage())?;
        let (generation, mut phase): (uuid::Uuid, String) = sqlx::query_as(
            "SELECT active_generation,maintenance FROM mdm_content.settings WHERE tenant_id=$1::uuid",
        ).bind(self.tenant.to_string()).fetch_one(&mut **c).await.map_err(|_| storage())?;
        if generation == self.generation && phase == "switching" {
            let observed: bool = sqlx::query_scalar("SELECT mdm_content.observe_generation($1)")
                .bind(generation)
                .fetch_one(&mut **c)
                .await
                .map_err(|_| storage())?;
            if observed {
                phase = "normal".into();
            }
        }
        if generation != self.generation
            || phase == "switching"
            || (matches!(kind, Kind::Mutation) && phase != "normal")
        {
            return Err(Error::Conflict);
        }
        if matches!(kind, Kind::Mutation) {
            self.verify_marker().await?;
        }
        Ok(Arc::new(permit))
    }
}

#[cfg(test)]
impl Permit {
    pub(crate) fn test() -> Arc<Self> {
        Arc::new(Self {
            connection: None,
            cleanup: tokio_util::task::TaskTracker::new(),
        })
    }
}
