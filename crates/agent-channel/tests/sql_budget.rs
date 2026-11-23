//! Real connection, statement and lock budgets inherited from a request.
#[path = "support/database.rs"]
mod database;
use super::Store;
use anyhow::{Context, Result};
use axum::{
    Router,
    extract::{Extension, State},
    routing::get,
};
use sqlx::Connection as _;
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

#[tokio::test]
#[ignore = "T2: Agent SQL lock and pool reuse obey the original non-default HTTP cutoff"]
async fn agent_sql_observes_request_cutoff() -> Result<()> {
    let path = std::env::var("RSS_MDM_T2_ENV")?;
    let inputs: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let database: database::Database =
        serde_json::from_value(inputs["databases"]["agent_foundation"]["da_access"].clone())?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(database.options()?)
        .await?;
    let store = Arc::new(Store::from_pool(
        rss_mdm_install_support::StorageProfile::Da,
        pool.clone(),
    ));
    let tenant = uuid::Uuid::new_v4();
    let key = tenant.as_u128() as i64;
    let (started, mut ready) = tokio::sync::mpsc::channel(2);
    let handler = get(
        move |State(store): State<Arc<Store>>,
              Extension(control): Extension<rss_axum::RequestControl>| {
            let started = started.clone();
            async move {
                let mut tx = store.begin(&tenant.to_string(), &control).await.unwrap();
                let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
                started.send(pid).await.unwrap();
                sqlx::query("SELECT pg_sleep(0.08)")
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                let result = sqlx::query("SELECT pg_advisory_xact_lock($1)")
                    .bind(key)
                    .execute(&mut *tx)
                    .await;
                if result.is_ok() {
                    tx.commit().await.unwrap();
                    axum::http::StatusCode::OK
                } else {
                    axum::http::StatusCode::GATEWAY_TIMEOUT
                }
            }
        },
    );
    let router = Router::new().route("/", handler).with_state(store);
    let make = |duration| {
        router.clone().layer(axum::middleware::from_fn_with_state(
            rss_axum::RequestBudget::new(duration).unwrap(),
            rss_axum::request_control,
        ))
    };
    let request = || axum::extract::Request::new(axum::body::Body::empty());
    let mut lock = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *lock)
        .await?;
    let long = tokio::spawn(make(Duration::from_secs(4)).oneshot(request()));
    ready.recv().await.context("Agent acquired transaction")?;
    tokio::time::sleep(Duration::from_millis(1150)).await;
    lock.rollback().await?;
    assert_eq!(long.await??.status(), 200);
    let mut lock = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *lock)
        .await?;
    let short = tokio::spawn(make(Duration::from_millis(150)).oneshot(request()));
    let waiter = ready
        .recv()
        .await
        .context("Agent acquired short transaction")?;
    let locker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *lock)
        .await?;
    let mut observer = sqlx::PgConnection::connect_with(&database.options()?).await?;
    assert!(
        !tokio::time::timeout(Duration::from_secs(1), short)
            .await???
            .status()
            .is_success()
    );
    tokio::time::timeout(Duration::from_millis(65), async {
        while sqlx::query_scalar::<_, bool>("SELECT $1=ANY(pg_blocking_pids($2))")
            .bind(locker)
            .bind(waiter)
            .fetch_one(&mut observer)
            .await?
        {
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        anyhow::Ok(())
    })
    .await??;
    lock.rollback().await?;
    assert_eq!(
        make(Duration::from_secs(2))
            .oneshot(request())
            .await?
            .status(),
        200
    );
    pool.close().await;
    Ok(())
}
