//! Dedicated DA executable;
// operator commands never run inside a request handler.
use rss_da_app::{Error, Result, config};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match execute().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");

            std::process::ExitCode::FAILURE
        }
    }
}
async fn execute() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();

    if args.as_slice() == ["--version"] {
        println!("rss-da {}", env!("CARGO_PKG_VERSION"));

        return Ok(());
    }
    if args.as_slice() == ["--describe"] {
        println!("{}", rss_da_app::installation::describe());

        return Ok(());
    }
    if args.as_slice() == ["http-contract"] {
        println!("{}", rss_da_app::http_contract()?);

        return Ok(());
    }
    if args.as_slice() == ["status-mapping"] {
        println!("{}", rss_mdm_device_access_http::exports::status_mapping());

        return Ok(());
    }
    if args.len() != 3 || args[1] != "--config" {
        return Err(Error::Configuration);
    }
    let path = std::path::Path::new(&args[2]);

    match args[0].as_str() {
        "serve" => rss_da_app::host::serve(config::load(path)?, stop()).await,
        "install" => rss_da_app::installation::install(config::load(path)?).await,
        "prepare-database" => rss_da_app::installation::prepare_database(config::load(path)?).await,
        "initialize-account" => {
            rss_da_app::maintenance::account(
                config::load(path)?,
                rss_da_app::maintenance::AccountOperation::Initialize,
            )
            .await
        }
        "initialize-authorization" => {
            rss_da_app::maintenance::account(
                config::load(path)?,
                rss_da_app::maintenance::AccountOperation::Authorize,
            )
            .await
        }
        "recover-account" => {
            rss_da_app::maintenance::account(
                config::load(path)?,
                rss_da_app::maintenance::AccountOperation::Recover,
            )
            .await
        }
        "diagnose" => rss_da_app::maintenance::diagnose(config::load(path)?).await,
        "public-configuration" => {
            let c: config::Config = config::load(path)?;

            c.validate()?;

            println!(
                "{}",
                serde_json::json!({"product":"da","instance":c.installation.instance,"tenant":c.installation.tenant,"browserOrigin":c.browser.origin,"deviceOrigin":c.registration.listener.origin,"contractVersion":1})
            );

            Ok(())
        }
        "backup-installation" => rss_da_app::backup::capture(config::load(path)?).await,
        "restore-installation" => rss_da_app::backup::restore(config::load(path)?).await,
        _ => Err(Error::Configuration),
    }
}
async fn stop() -> std::io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {result=tokio::signal::ctrl_c()=>result,_=terminate.recv()=>Ok(())}
}
