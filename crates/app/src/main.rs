//! ref: tokio-rs/axum axum/src/middleware/from_fn.rs@axum-v0.8.9
use rss_mdm_app::{ProcessError, config};
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match execute().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
async fn execute() -> Result<(), ProcessError> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("rss-mdm serve|migrate --config /absolute/private-config.json");
        return Ok(());
    }
    if args == ["--version"] {
        println!("rss-mdm {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.len() != 3 || args[1] != "--config" {
        return Err(ProcessError::Stage {
            stage: "arguments",
            kind: "use rss-mdm --help",
        });
    }
    let path = std::path::Path::new(&args[2]);
    match args[0].as_str() {
        "serve" => rss_mdm_app::serve(config::load(path)?, rss_mdm_app::signal()).await,
        "migrate" => {
            let config: config::MigrationConfig = config::load(path)?;
            let options = config
                .database
                .options()
                .map_err(|e| ProcessError::at("migration.database_configuration", e))?;
            rss_mdm_app::migration::migrate(&options).await?;
            Ok(())
        }
        _ => Err(ProcessError::Stage {
            stage: "arguments",
            kind: "use rss-mdm --help",
        }),
    }
}
