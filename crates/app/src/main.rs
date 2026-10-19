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
            "rss-mdm install|provision-hosts|rotate-protection|prepare-ca|configure-host|public-host-config|export-webhook-key|backup-installation|restore-installation|serve|migrate|tenant-get|tenant-list|tenant-update|tenant-delete|tenant-operation-status|initialize|initialize-authorization|recover-password --config /absolute/private-config.json\nrss-mdm --version|--describe"
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
        "public-host-config" => {
            let config = config::load(path)?;
            let public = rss_mdm_app::setup::public_configuration::read(&config)
                .await
                .map_err(|error| setup_failure("host.configuration", error))?;
            println!(
                "{}",
                serde_json::to_string(&public).map_err(|_| setup_failure(
                    "host.configuration",
                    rss_mdm_app::setup::Error::Input
                ))?
            );
            Ok(())
        }
        #[cfg(unix)]
        "install" => {
            let input = config::load(path)?;
            let receipt = rss_mdm_app::setup::installation::install(input)
                .await
                .map_err(|error| setup_failure("installation", error))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public installation receipt")
            );
            Ok(())
        }
        #[cfg(unix)]
        "export-webhook-key" => {
            let receipt = rss_mdm_app::setup::providers::webhook::export(config::load(path)?)
                .await
                .map_err(|error| setup_failure("webhook.delivery", error))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public receipt")
            );
            Ok(())
        }
        #[cfg(unix)]
        "configure-host" => {
            let receipt = rss_mdm_app::setup::configure::run(config::load(path)?)
                .await
                .map_err(|error| setup_failure("host.configuration", error))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public receipt")
            );
            Ok(())
        }
        #[cfg(unix)]
        "restore-installation" => {
            let receipt = rss_mdm_app::setup::backup::restore(config::load(path)?)
                .await
                .map_err(|error| setup_failure("installation.restore", error))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public receipt")
            );
            Ok(())
        }
        #[cfg(unix)]
        "backup-installation" => {
            let receipt = rss_mdm_app::setup::backup::capture(config::load(path)?)
                .await
                .map_err(|error| setup_failure("installation.backup", error))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public receipt")
            );
            Ok(())
        }
        #[cfg(unix)]
        "prepare-ca" => {
            let receipt = rss_mdm_app::setup::providers::step_ca::run(config::load(path)?)
                .await
                .map_err(|error| setup_failure("installation.ca", error))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public CA receipt")
            );
            Ok(())
        }
        #[cfg(unix)]
        "rotate-protection" => {
            let receipt = rss_mdm_app::setup::protection::rotate(config::load(path)?)
                .await
                .map_err(|error| setup_failure("protection.rotation", error))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public protection receipt")
            );
            Ok(())
        }
        #[cfg(unix)]
        "provision-hosts" => {
            let input = config::load(path)?;
            let shutdown = rss_mdm_app::signal();
            tokio::pin!(shutdown);
            let mut failed = false;
            let mut resumed = false;
            loop {
                let result = tokio::select! {
                    biased;
                    result=&mut shutdown=>{
                        rss_mdm_app::setup::deployment::stop_hosts(&input).await.map_err(|e| setup_failure("deployment.stop",e))?;
                        return result.map_err(|_| ProcessError::Stage {stage:"deployment.signal",kind:"shutdown signal unavailable"});
                    },
                    result=async {
                        if !resumed { rss_mdm_app::setup::deployment::resume_hosts(&input).await?; resumed=true; }
                        rss_mdm_app::setup::tenant_hosts::reconcile(&input).await
                    }=>result,
                };
                if result.is_err() != failed {
                    failed = result.is_err();
                    eprintln!(
                        "{}",
                        serde_json::json!({"event":"tenant_deployment_health","available":!failed})
                    );
                }
                tokio::select! {
                    result=&mut shutdown=>{
                        rss_mdm_app::setup::deployment::stop_hosts(&input).await.map_err(|e| setup_failure("deployment.stop",e))?;
                        return result.map_err(|_| ProcessError::Stage {stage:"deployment.signal",kind:"shutdown signal unavailable"});
                    },
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

fn setup_failure(stage: &'static str, error: rss_mdm_app::setup::Error) -> ProcessError {
    use rss_mdm_app::setup::Error;
    let kind = match error {
        Error::Input => "input_rejected: correct deployment inputs before retrying",
        Error::Busy => {
            "busy: preserve the operation and retry after the active maintenance finishes"
        }
        Error::Conflict => {
            "conflict: inspect the original operation and exact input; do not replace identities"
        }
        Error::Corrupt => {
            "corrupt: restore the original journal and protection materials before retrying"
        }
        Error::Storage => {
            "storage_unavailable: query the original operation before retrying; outcome may be unknown"
        }
    };
    ProcessError::Stage { stage, kind }
}
