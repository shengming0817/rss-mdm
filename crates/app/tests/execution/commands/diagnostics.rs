//! Retired diagnostics inputs cannot regain generic direct execution.
use crate::execution::test_support::*;
use anyhow::ensure;
use axum::http::{Method, StatusCode};
use serde_json::json;
#[tokio::test]
#[ignore = "MODULE=execution.commands.windows: closed HTTP execution contract"]
async fn diagnostic_input_is_rejected_before_any_execution() -> anyhow::Result<()> {
    let (host, mut client) = ordinary(rss_device_command_postgres::CommandClock::Postgres).await?;
    let result=client.call(Method::POST,"",Some(json!({"operationId":client.operation,"deadline":client.app.clock.unix_seconds()?+300,"inputVersion":"diagnostic-1","target":{"kind":"device"},"task":{"platform":"windows","request":{"kind":"diagnostic_log","request":{"trigger":null,"fileContext":"DeviceManagement","blockSizeKb":1,"maxBytes":4096}}}}))).await?;
    ensure!(
        result.0 == StatusCode::BAD_REQUEST,
        "retired diagnostic: {result:?}"
    );
    ensure!(
        client
            .call(Method::GET, &format!("/{}", client.operation), None)
            .await?
            .0
            == StatusCode::NOT_FOUND
    );
    host.close().await?;
    Ok(())
}
