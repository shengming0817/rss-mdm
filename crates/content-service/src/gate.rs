//! Content-only admission. A session lock spans physical work, never a network transaction.
use crate::{Error, Store, storage};
use sqlx::{Postgres, pool::PoolConnection};
use std::sync::{Arc, Weak};

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

/// A generation's readers and writers each share a reference-counted session fence.
/// Weak entries never extend a fence beyond its actual operations or I/O owners.
#[derive(Default)]
pub(crate) struct Admissions {
    reads: tokio::sync::Mutex<Weak<Permit>>,
    mutations: tokio::sync::Mutex<Weak<Permit>>,
}

/// Kept by the actual I/O owner (including blocking work), not only its awaiting future.
/// Closing this dedicated session releases locks while retaining its pool slot until close.
pub(crate) struct Permit {
    generation: uuid::Uuid,
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
        let permit = self.session_fence(kind).await?;
        // Every new operation rechecks admission, even when an earlier operation already
        // holds the shared session. Sharing a fence never admits new work while frozen.
        let mut tx = self.pool.begin().await.map_err(|_| storage())?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','6000',true)")
            .bind(self.tenant.to_string()).execute(&mut *tx).await.map_err(|_| storage())?;
        let (generation, mut phase): (uuid::Uuid, String) = sqlx::query_as(
            "SELECT active_generation,maintenance FROM mdm_content.settings WHERE tenant_id=$1::uuid",
        ).bind(self.tenant.to_string()).fetch_one(&mut *tx).await.map_err(|_| storage())?;
        if generation == self.generation && phase == "switching" {
            let observed: bool = sqlx::query_scalar("SELECT mdm_content.observe_generation($1)")
                .bind(generation)
                .fetch_one(&mut *tx)
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
        crate::journal::commit(tx).await?;
        if matches!(kind, Kind::Mutation) {
            self.verify_marker().await?;
        }
        Ok(permit)
    }
    async fn session_fence(&self, kind: Kind) -> Result<Arc<Permit>, Error> {
        let timeout = std::time::Duration::from_secs(6);
        let slot = match kind {
            Kind::Read => &self.admissions.reads,
            Kind::Mutation => &self.admissions.mutations,
        };
        let mut cached = tokio::time::timeout(timeout, slot.lock())
            .await
            .map_err(|_| Error::Deadline)?;
        if let Some(permit) = cached.upgrade() {
            if permit.generation != self.generation {
                return Err(Error::Conflict);
            }
            return Ok(permit);
        }
        let mut connection = self.admission_pool.acquire().await.map_err(|_| storage())?;
        // Cancellation must close a possibly locked session, retaining its pool slot through close.
        connection.close_on_drop();
        let mut permit = Permit {
            generation: self.generation,
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
        let permit = Arc::new(permit);
        *cached = Arc::downgrade(&permit);
        Ok(permit)
    }
}

#[cfg(test)]
impl Permit {
    pub(crate) fn test() -> Arc<Self> {
        Arc::new(Self {
            generation: uuid::Uuid::nil(),
            connection: None,
            cleanup: tokio_util::task::TaskTracker::new(),
        })
    }
}
