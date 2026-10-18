//! ref: tokio-rs/axum axum/src/middleware/from_fn.rs@axum-v0.8.9
use rss_mdm_app::{ProcessError, config};
fn main() -> std::process::ExitCode {
    if let Err(error) = rss_mdm_app::install_diagnostics() {
        eprintln!("{error}");
        return std::process::ExitCode::FAILURE;
    }
    run()
}
#[tokio::main]
async fn run() -> std::process::ExitCode {
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
        println!(
            "rss-mdm install|provision-hosts|serve|migrate|tenant-get|tenant-list|tenant-update|tenant-delete|tenant-operation-status|initialize|initialize-authorization|recover-password --config /absolute/private-config.json\nrss-mdm --version|--describe"
        );
        return Ok(());
    }
    if args == ["--describe"] {
        println!("{}", rss_mdm_app::migration::manifest());
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
        #[cfg(unix)]
        "install" => {
            let input = config::load(path)?;
            let receipt = rss_mdm_app::setup::installation::install(input)
                .await
                .map_err(|_| ProcessError::Stage {
                    stage: "installation",
                    kind: "installation failed; preserve the original journal and credentials",
                })?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public installation receipt")
            );
            Ok(())
        }
        #[cfg(unix)]
        "provision-hosts" => {
            let input = config::load(path)?;
            let shutdown = rss_mdm_app::signal();
            tokio::pin!(shutdown);
            let mut failed = false;
            loop {
                let result = tokio::select! {
                    biased;
                    result=&mut shutdown=>return result.map_err(|_|ProcessError::Stage {stage:"deployment.signal",kind:"shutdown signal unavailable"}),
                    result=rss_mdm_app::setup::tenant_hosts::reconcile(&input)=>result,
                };
                if result.is_err() != failed {
                    failed = result.is_err();
                    eprintln!(
                        "{}",
                        serde_json::json!({"event":"tenant_deployment_health","available":!failed})
                    );
                }
                tokio::select! {
                    result=&mut shutdown=>return result.map_err(|_|ProcessError::Stage {stage:"deployment.signal",kind:"shutdown signal unavailable"}),
                    ()=tokio::time::sleep(std::time::Duration::from_secs(5))=>{},
                }
            }
        }

        "serve" => {
            rss_mdm_app::serve(config::load(path)?, rss_mdm_app::signal(), monotonic()).await
        }
        "migrate" => {
            let config: config::MigrationConfig = config::load(path)?;
            let options = config
                .database
                .options()
                .map_err(|e| ProcessError::at("migration.database_configuration", e))?;
            rss_mdm_app::migration::migrate(&options, &config.installation).await?;
            Ok(())
        }
        "tenant-get" => {
            let tenant = rss_mdm_app::tenant_registry::get(config::load(path)?).await?;
            println!("{}", serde_json::to_string(&tenant).expect("public tenant"));
            Ok(())
        }
        "tenant-list" => {
            let tenants = rss_mdm_app::tenant_registry::list(config::load(path)?).await?;
            println!(
                "{}",
                serde_json::to_string(&tenants).expect("public tenants")
            );
            Ok(())
        }
        "tenant-update" => {
            let receipt = rss_mdm_app::tenant_registry::update(config::load(path)?).await?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public receipt")
            );
            Ok(())
        }
        "tenant-delete" => {
            let receipt = rss_mdm_app::tenant_registry::delete(config::load(path)?).await?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public receipt")
            );
            Ok(())
        }
        "tenant-operation-status" => {
            let receipt =
                rss_mdm_app::tenant_registry::query_operation(config::load(path)?).await?;
            println!(
                "{}",
                serde_json::json!({"status": if receipt.is_some() { "committed" } else { "not_found" }, "receipt":receipt})
            );
            Ok(())
        }
        "initialize-authorization" => {
            let receipt = rss_mdm_app::initialize_authorization(config::load(path)?)
                .await
                .map_err(|error| ProcessError::at("authorization.initialize", error))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("receipt serialization")
            );
            Ok(())
        }
        "initialize" | "recover-password" => {
            rss_mdm_app::maintenance::run(config::load(path)?, args[0] == "initialize")
                .await
                .map_err(|error| ProcessError::at("identity.maintenance", error))
        }
        _ => Err(ProcessError::Stage {
            stage: "arguments",
            kind: "use rss-mdm --help",
        }),
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "composition root selects the provider; the application receives the Clock trait explicitly"
)]
fn monotonic() -> std::sync::Arc<dyn rss_observation::Clock> {
    std::sync::Arc::new(rss_mdm_app::Monotonic(std::time::Instant::now))
}
