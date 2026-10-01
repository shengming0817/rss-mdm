#[path = "../../../../../tests/support/context.rs"]
mod case;
use crate::{app::App, fixture::FixtureAuthority, storage};
use anyhow::{Result, ensure};
use rss_mdm_inventory as model;
use rss_mdm_inventory_postgres::{Inventory, definition};
use rss_observation::{
    Batch, Body, Change, Id, ObservationStore, ReceiveOutcome, Scope, VerifiedBatch,
};
use rss_projection::{BatchLimit, Control, Execution, RunLimit, Source};
use rss_projection_postgres::{PgEffect, PgEffectOutcome, PgOperationError, PgTransaction};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn scope(tenant: u8, device: &str) -> Scope {
    serde_json::from_value(serde_json::json!({"tenant":if tenant == 1 { case::tenant() } else { case::peer() },"object":case::name(device),"registration":"reg-1","source":"agent.builtin","dataset":"inventory","epoch":"epoch-1"})).unwrap()
}
#[allow(
    clippy::disallowed_methods,
    reason = "Real PG fixture timestamp must track server wall time"
)]
fn batch(id: &str, sequence: u64, body: Body) -> Batch {
    Batch::new(
        Id::new(id).unwrap(),
        sequence,
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
        .try_into()
        .unwrap(),
        crate::fixture::definition().coverage().unwrap(),
        body,
    )
    .unwrap()
}
fn facts(value: &str) -> Vec<Change> {
    vec![
        Change::upsert(
            Id::new("device.model").unwrap(),
            rss_mdm_inventory::CollectedValue::Value(model::Scalar::String(value.into()))
                .encode(
                    crate::fixture::definition()
                        .field(model::builtin::MODEL)
                        .unwrap(),
                )
                .unwrap(),
        ),
        Change::upsert(
            Id::new("device.os.version").unwrap(),
            rss_mdm_inventory::CollectedValue::Value(model::Scalar::String("1".into()))
                .encode(
                    crate::fixture::definition()
                        .field(model::builtin::OS_VERSION)
                        .unwrap(),
                )
                .unwrap(),
        ),
    ]
}
fn url(name: &str) -> Result<PgConnectOptions> {
    Ok(std::env::var(name)?
        .parse::<PgConnectOptions>()?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?))
}
async fn app(s: Scope) -> Result<App> {
    Box::pin(App::open(
        &storage::options()?,
        FixtureAuthority::new(s),
        system_clock(),
    ))
    .await
}
async fn inspect(a: &App, id: &str) -> Result<serde_json::Value> {
    a.inspect(&Id::new(id)?).await
}

fn scope_for_app() -> Scope {
    scope(1, "d1")
}

#[allow(
    clippy::disallowed_methods,
    reason = "test composition root injects the real monotonic clock"
)]
fn system_clock() -> storage::Clock {
    storage::Clock::new(std::time::Instant::now)
}

mod cli;
mod process;
mod projection;
mod recovery;
