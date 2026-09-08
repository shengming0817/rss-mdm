//! ref: launchbadge/sqlx sqlx-core/src/pool/mod.rs@v0.9.0
use anyhow::{Context, Result, ensure};
use rss_request_context::Deadline;
use sha2::{Digest, Sha256};
use sqlx::{
    Connection, PgConnection, PgPool, Row,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::time::{Duration, Instant};

pub const BUDGET: Duration = Duration::from_secs(30);
/// Shared monotonic source selected by the composition root; no implicit system default.
#[derive(Clone)]
pub struct Clock {
    now: std::sync::Arc<dyn Fn() -> Instant + Send + Sync>,
    origin: Instant,
}
impl Clock {
    pub fn new(now: impl Fn() -> Instant + Send + Sync + 'static) -> Self {
        let origin = now();
        Self {
            now: std::sync::Arc::new(now),
            origin,
        }
    }
    pub fn now(&self) -> Instant {
        (self.now)()
    }
    pub fn deadline(&self) -> Deadline {
        Deadline::at(self.now() + BUDGET)
    }
    pub fn cutoff(&self, budget: Duration) -> Duration {
        self.elapsed() + budget
    }
    fn elapsed(&self) -> Duration {
        self.now().saturating_duration_since(self.origin)
    }
}
impl rss_observation::Clock for Clock {
    fn now(&self) -> Instant {
        self.now()
    }
}
impl rss_projection::Timer for Clock {
    fn now(&self) -> Duration {
        self.elapsed()
    }
    async fn sleep_until(&self, end: Duration) {
        tokio::time::sleep(end.saturating_sub(self.elapsed())).await;
    }
}
pub fn options() -> Result<PgConnectOptions> {
    let url = std::env::var("DATABASE_URL").context("DATABASE_URL required")?;
    let ca = std::env::var("PG_CA_FILE").context("PG_CA_FILE required")?;
    Ok(url
        .parse::<PgConnectOptions>()
        .context("invalid DATABASE_URL")?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca))
}
pub async fn pool(options: &PgConnectOptions) -> Result<PgPool> {
    Ok(tokio::time::timeout(
        BUDGET,
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(BUDGET)
            .connect_with(options.clone()),
    )
    .await??)
}
pub async fn close_pool(pool: &PgPool) -> Result<()> {
    tokio::time::timeout(BUDGET, pool.close())
        .await
        .context("pool drain deadline")
}

pub async fn migrate(options: &PgConnectOptions) -> Result<()> {
    let mut conn = tokio::time::timeout(BUDGET, PgConnection::connect_with(options)).await??;
    let result = migrate_on(&mut conn).await;
    let closed = tokio::time::timeout(BUDGET, conn.close()).await;
    crate::failure::finish(
        result.map_err(|e| crate::failure::at("migration", e)),
        [(
            "migration_close",
            match closed {
                Ok(result) => result.map_err(Into::into),
                Err(error) => Err(error.into()),
            },
        )],
    )
}
async fn migrate_on(conn: &mut PgConnection) -> Result<()> {
    sqlx::raw_sql("SET statement_timeout='30s'; SET lock_timeout='30s'; SELECT pg_advisory_lock(2346); CREATE TABLE IF NOT EXISTS public.mdm_migrations(name text PRIMARY KEY,digest text NOT NULL,complete boolean NOT NULL DEFAULT false);").execute(&mut *conn).await?;
    for (name, sql) in [
        ("observation-v2", rss_observation_postgres::MIGRATION_SQL),
        ("projection-v3", rss_projection_postgres::MIGRATION_SQL),
        (
            "inventory-v1",
            include_str!("../migrations/0001_inventory.sql"),
        ),
    ] {
        let digest = format!("{:x}", Sha256::digest(sql));
        let old = sqlx::query("SELECT digest,complete FROM public.mdm_migrations WHERE name=$1")
            .bind(name)
            .fetch_optional(&mut *conn)
            .await?;
        if let Some(row) = old {
            ensure!(
                row.try_get::<String, _>("digest")? == digest
                    && row.try_get::<bool, _>("complete")?,
                "migration {name} changed or interrupted; restore/recreate the dedicated database before retry"
            );
            continue;
        }
        // Component scripts own transaction statements. Persist intent before invoking them;
        // an interrupted installation cannot be silently adopted on the next invocation.
        sqlx::query("INSERT INTO public.mdm_migrations(name,digest) VALUES($1,$2)")
            .bind(name)
            .bind(digest)
            .execute(&mut *conn)
            .await?;
        sqlx::raw_sql(sql).execute(&mut *conn).await?;
        sqlx::query("UPDATE public.mdm_migrations SET complete=true WHERE name=$1")
            .bind(name)
            .execute(&mut *conn)
            .await?;
    }
    Ok(()) // session advisory lock released by explicit connection close
}
