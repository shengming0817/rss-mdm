//! ref: launchbadge/sqlx sqlx-core/src/pool/mod.rs@v0.9.0
use anyhow::{Context, Result};
use rss_request_context::Deadline;
use sqlx::{
    PgPool,
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
