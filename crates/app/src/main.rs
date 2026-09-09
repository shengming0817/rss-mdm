//! ref: tokio-rs/axum axum/src/middleware/from_fn.rs@axum-v0.8.9
use rss_mdm_app::{Error, config};
#[tokio::main]
async fn main() -> std::process::ExitCode {
    let result = execute().await;
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
async fn execute() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 || args[1] != "--config" {
        return Err(Error::Configuration);
    }
    let path = std::path::Path::new(&args[2]);
    match args[0].as_str() {
        "serve" => rss_mdm_app::serve(config::load(path)?, rss_mdm_app::signal()).await,
        "migrate" => {
            let config: config::MigrationConfig = config::load(path)?;
            rss_mdm_app::migration::migrate(&config.database.options()?)
                .await
                .map_err(|_| Error::Unavailable)
        }
        _ => Err(Error::Configuration),
    }
}
