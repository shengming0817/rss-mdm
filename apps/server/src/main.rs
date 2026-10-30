//! ref: tokio-rs/axum axum/src/middleware/from_fn.rs@axum-v0.8.9
fn main() -> std::process::ExitCode {
    if let Err(error) = rss_mdm_app::install_diagnostics() {
        eprintln!("{error}");
        return std::process::ExitCode::FAILURE;
    }
    run()
}
#[tokio::main]
async fn run() -> std::process::ExitCode {
    match rss_mdm_app::commands::execute().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
