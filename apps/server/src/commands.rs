//! Command-line parsing, dispatch and public receipts.
use crate::{ProcessError, config};
pub async fn execute() -> Result<(), ProcessError> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!(
            "rss-mdm install|maintain-content-storage|maintain-default-telemetry|prepare-telemetry|prepare-telemetry-tenant|maintain-telemetry-storage|prepare-hosts|rotate-protection|initialize-ca|configure-host|public-host-config|export-webhook-key|backup-installation|restore-installation|serve|migrate|tenant-get|tenant-list|tenant-update|tenant-delete|tenant-operation-status|initialize|initialize-authorization|recover-password --config /absolute/private-config.json\nrss-mdm --version|--describe"
        );
        return Ok(());
    }
    if args == ["--describe"] {
        println!("{}", crate::migration::manifest());
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
        "maintain-content-storage" => {
            let receipt = crate::installation::content_storage::maintain(config::load(path)?)
                .await
                .map_err(|e| setup_failure("content.storage", e))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public storage migration receipt")
            );
            Ok(())
        }
        #[cfg(unix)]
        "maintain-default-telemetry" => {
            crate::installation::default_telemetry::maintain(config::load(path)?)
                .await
                .map_err(|e| setup_failure("telemetry.partitions", e))?;
            Ok(())
        }
        #[cfg(unix)]
        "maintain-telemetry-storage" => {
            let receipt = crate::installation::providers::telemetry::maintain(config::load(path)?)
                .await
                .map_err(|e| setup_failure("telemetry.storage", e))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public telemetry receipt")
            );
            Ok(())
        }
        #[cfg(unix)]
        "prepare-telemetry" => {
            let receipt = crate::installation::providers::telemetry::prepare(config::load(path)?)
                .await
                .map_err(|e| setup_failure("telemetry.installation", e))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public telemetry receipt")
            );
            Ok(())
        }
        #[cfg(unix)]
        "prepare-telemetry-tenant" => {
            let receipt =
                crate::installation::providers::telemetry::prepare_tenant(config::load(path)?)
                    .await
                    .map_err(|e| setup_failure("telemetry.tenant", e))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("tenant telemetry receipt")
            );
            Ok(())
        }
        "public-host-config" => {
            let config = config::load(path)?;
            let public = crate::installation::public_configuration::read(&config)
                .await
                .map_err(|error| setup_failure("host.configuration", error))?;
            println!(
                "{}",
                serde_json::to_string(&public).map_err(|_| setup_failure(
                    "host.configuration",
                    crate::installation::Error::Input
                ))?
            );
            Ok(())
        }
        #[cfg(unix)]
        "install" => {
            let input = config::load(path)?;
            let receipt = crate::installation::install::install(input)
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
            let receipt = crate::installation::providers::webhook::export(config::load(path)?)
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
            let receipt = crate::installation::configure::run(config::load(path)?)
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
            let receipt = crate::installation::backup::restore(config::load(path)?)
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
            let receipt = crate::installation::backup::capture(config::load(path)?)
                .await
                .map_err(|error| setup_failure("installation.backup", error))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public receipt")
            );
            Ok(())
        }
        #[cfg(unix)]
        "initialize-ca" => {
            let receipt =
                crate::installation::providers::step_ca::initialize::run(config::load(path)?)
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
            let receipt = crate::installation::protection::rotate(config::load(path)?)
                .await
                .map_err(|error| setup_failure("protection.rotation", error))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public protection receipt")
            );
            Ok(())
        }
        #[cfg(unix)]
        "prepare-hosts" => {
            let completed = crate::installation::tenant_hosts::reconcile(&config::load(path)?)
                .await
                .map_err(|error| setup_failure("host.inputs", error))?;
            println!("{}", serde_json::json!({"observedHosts":completed}));
            Ok(())
        }

        "serve" => crate::serve(config::load(path)?, crate::signal(), monotonic()).await,
        "migrate" => {
            let config: config::MigrationConfig = config::load(path)?;
            let options = config
                .database
                .options()
                .map_err(|e| ProcessError::at("migration.database_configuration", e))?;
            crate::migration::migrate(&options, &config.installation).await?;
            Ok(())
        }
        "tenant-get" => {
            let tenant = crate::administration::tenants::get(config::load(path)?).await?;
            println!("{}", serde_json::to_string(&tenant).expect("public tenant"));
            Ok(())
        }
        "tenant-list" => {
            let tenants = crate::administration::tenants::list(config::load(path)?).await?;
            println!(
                "{}",
                serde_json::to_string(&tenants).expect("public tenants")
            );
            Ok(())
        }
        "tenant-update" => {
            let receipt = crate::administration::tenants::update(config::load(path)?).await?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public receipt")
            );
            Ok(())
        }
        "tenant-delete" => {
            let receipt = crate::administration::tenants::delete(config::load(path)?).await?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("public receipt")
            );
            Ok(())
        }
        "tenant-operation-status" => {
            let receipt =
                crate::administration::tenants::query_operation(config::load(path)?).await?;
            println!(
                "{}",
                serde_json::json!({"status": if receipt.is_some() { "committed" } else { "not_found" }, "receipt":receipt})
            );
            Ok(())
        }
        "initialize-authorization" => {
            let receipt = crate::initialize_authorization(config::load(path)?)
                .await
                .map_err(|error| ProcessError::at("authorization.initialize", error))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).expect("receipt serialization")
            );
            Ok(())
        }
        "initialize" | "recover-password" => {
            crate::maintenance::run(config::load(path)?, args[0] == "initialize")
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
    std::sync::Arc::new(crate::Monotonic(std::time::Instant::now))
}

fn setup_failure(stage: &'static str, error: crate::installation::Error) -> ProcessError {
    use crate::installation::Error;
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
