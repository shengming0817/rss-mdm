use anyhow::{Context, Result};
use rss_mdm_examples::{Clock, app::App, failure, fixture::FixtureAuthority};
use rss_observation::{Batch, Id, ReceiveOutcome, Scope};
use std::{io::Read, path::Path};
use tokio_util::sync::CancellationToken;

fn read_bounded(path: &str) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    std::fs::File::open(Path::new(path))?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut value)?;
    anyhow::ensure!(value.len() <= 4 * 1024 * 1024, "fixture exceeds 4 MiB");
    Ok(value)
}
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match execute().await {
        Ok(value) => {
            println!("{value}");
            std::process::ExitCode::SUCCESS
        }
        // Avoid printing provider chains: they can contain SQL values or credentials.
        Err(error) => {
            eprintln!("{}", rss_mdm_examples::failure::report(error));
            std::process::ExitCode::FAILURE
        }
    }
}
async fn execute() -> Result<serde_json::Value> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let command = args
        .first()
        .context("command required")
        .map_err(|e| failure::at("usage", e))?;
    match (command.as_str(), args.len()) {
        ("project", 1) | ("ingest-fixture" | "inspect", 2) => {}
        _ => return Err(failure::at("usage", anyhow::anyhow!("invalid arguments"))),
    }
    let options = rss_mdm_examples::options().map_err(|e| failure::at("config", e))?;
    let scope: Scope = serde_json::from_slice(
        &read_bounded(&std::env::var("MDM_SCOPE_FILE").map_err(|e| failure::at("scope", e))?)
            .map_err(|e| failure::at("scope", e))?,
    )
    .map_err(|e| failure::at("scope", e))?;
    // Trusted operator configuration, never inferred from the submitted report.
    let app = App::open(&options, FixtureAuthority::new(scope), system_clock()).await?;
    let cancel = CancellationToken::new();
    let operation = async {
        match command.as_str() {
            "ingest-fixture" => {
                let outcome = app
                    .ingest(
                        Batch::decode(
                            &read_bounded(&args[1]).map_err(|e| failure::at("fixture_read", e))?,
                        )
                        .map_err(|e| failure::at("decode", e))?,
                    )
                    .await
                    .map_err(|e| failure::at("ingest", e))?;
                Ok(
                    serde_json::json!({"receipt":if matches!(outcome,ReceiveOutcome::Replay(_)){"replay"}else{"accepted"},"batchId":outcome.record().batch().id().as_str(),"decision":outcome.record().decision(),"inventory":"not_confirmed"}),
                )
            }
            "project" => app.project(&cancel).await,
            "inspect" => app.inspect(&Id::new(&args[1])?).await,
            _ => unreachable!(),
        }
    };
    let result = {
        tokio::pin!(operation);
        tokio::select! {
            result = &mut operation => result,
            signal = tokio::signal::ctrl_c() => {
                cancel.cancel();
                let interrupted = failure::signal(signal);
                // Cooperatively drain; dropping the operation after the budget quarantines
                // unconfirmed component transactions before pool shutdown begins.
                let _ = tokio::time::timeout(rss_mdm_examples::BUDGET, &mut operation).await;
                Err(interrupted)
            }
        }
    };
    let closed = app.close().await;
    failure::finish(result, [("close", closed)])
}

#[allow(
    clippy::disallowed_methods,
    reason = "CLI composition root selects the real monotonic source"
)]
fn system_clock() -> Clock {
    Clock::new(std::time::Instant::now)
}
