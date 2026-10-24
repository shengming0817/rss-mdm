//! Existing fixture carrier dispatches explicit preparation to each owner.
use super::*;

#[derive(serde::Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
enum Setup {
    Environment,
    ManagementDelegate { management: String, source_secret: std::path::PathBuf, login: String },
    Refresh,
    TaskSigning {
        directory: std::path::PathBuf,
    },
    Actors {
        cases: Vec<std::path::PathBuf>,
        management: String,
        source_secret: std::path::PathBuf,
        provisioning_database: crate::config::Database,
    },
}

#[tokio::test]
#[ignore = "make t2: explicit preparation through the owning capability"]
async fn prepare() -> Result<()> {
    let manifest: Setup =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_PREPARATION")?)?)?;
    let config_path = std::path::PathBuf::from(std::env::var("MDM_TEST_CONFIG")?);
    let root = config_path.parent().unwrap();
    let costs = match manifest {
        Setup::TaskSigning { directory } => {
            task_signing::prepare(&directory).await?;
            Vec::new()
        }
        Setup::ManagementDelegate { management, source_secret, login } => {
            identity::prepare_management_delegate(root, &management, &source_secret, &login).await?;
            Vec::new()
        }
        Setup::Environment => {
            identity::prepare_environment(root).await?;
            Vec::new()
        }
        Setup::Refresh => {
            identity::refresh_management(root).await?;
            Vec::new()
        }
        Setup::Actors {
            cases,
            management,
            source_secret,
            provisioning_database,
        } => {
            let mut costs = identity::prepare_accounts(
                &cases,
                &management,
                &source_secret,
                &provisioning_database,
            )
            .await?;
            costs.extend(identity::prepare_sessions(&cases).await?);
            costs
        }
    };
    std::fs::write(
        root.join("preparation-costs.json"),
        &serde_json::to_vec(&costs)?,
    )?;
    Ok(())
}
