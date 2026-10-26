//! Exercises the joint stopped-data seam with an actual published host projection.
//! Installation/control-plane publication is covered by its own installation T2 cases.
use super::*;
use anyhow::{Context, ensure};
use std::os::unix::fs::PermissionsExt;

pub(crate) async fn roundtrip(
    runtime: Value,
    profile: super::super::providers::telemetry::Request,
) -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let journal = Journal::open(&root.join("bundle"))?;
    let url = url::Url::parse(&std::env::var("MDM_ADMIN_URL")?)?;
    let password = journal.secret("administrator-password", url.password().unwrap().as_bytes())?;
    let administrator = crate::config::Database {
        host: url.host_str().unwrap().into(),
        port: url.port().unwrap(),
        name: url.path().trim_start_matches('/').into(),
        user: url.username().into(),
        password_file: password,
        ca_file: std::env::var("PG_CA_FILE")?.into(),
    };
    let mut c = sqlx::PgConnection::connect_with(&administrator.options()?).await?;
    let installation = crate::migration::Installation {
        instance_id: sqlx::query_scalar("SELECT instance_id::text FROM public.mdm_installation")
            .fetch_one(&mut c)
            .await?,
        audit_mode: crate::migration::AuditMode::Plain,
        target: [1; 16],
        lineage: [2; 16],
    };
    crate::migration::verify_identity(&mut c, &installation).await?;
    let tenant = crate::test_support::runtime::case_tenant().parse()?;
    let directory = root.join("installation");
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    // These are existing host inputs. This fixture starts after freeze_host, not after a
    // fabricated bootstrap receipt, and tests exactly the newly extended archive seam.
    let inputs = std::path::PathBuf::from(std::env::var("MDM_TEST_CONFIG")?)
        .parent()
        .unwrap()
        .to_owned();
    let frozen = Frozen {
        installation,
        hosts: vec![Host {
            id: Uuid::new_v4(),
            tenant,
            slot: None,
            runtime,
        }],
        request: Request {
            operation_id: Uuid::new_v4(),
            directory: root.join("bundle"),
            authorities: vec![],
            telemetry: vec![profile.clone()],
            installation: Input {
                directory,
                deployment: super::super::runtime_files::Config {
                    gateway_directory: root.join("gateway"),
                    directory: inputs.clone(),
                    probe_address: None,
                    probe_addresses: BTreeMap::new(),
                    certificate_file: inputs.join("server.crt"),
                    private_key_file: inputs.join("server.key"),
                    trust_file: inputs.join("ca.crt"),
                    content_volume: None,
                },
                additional_hosts: vec![],
                storage_profiles: vec![],
                mail_profiles: vec![],
                content_storage: Default::default(),
                database: super::super::installation::DatabaseInput {
                    name: administrator.name.clone(),
                    administrator: administrator.clone(),
                },
                audit_mode: crate::migration::AuditMode::Plain,
                organization_name: "Telemetry T2".into(),
                platform_login: "fixture".into(),
                administrator_login: "fixture".into(),
                platform_password_file: None,
                administrator_password_file: None,
                origin: "https://mdm.example.test".into(),
                listen: "127.0.0.1:0".parse()?,
                trusted_gateway: "127.0.0.1".parse()?,
            },
        },
    };
    telemetry::validate(&frozen).context("validate joint backup")?;
    journal.save("restore-source.json", &frozen)?;
    connection_fence(&mut c, &journal, true).await?;
    no_writers(&mut c).await?;
    capture_ledger_heads(&mut c, &frozen, &journal).await?;
    c.close().await?;
    telemetry::capture(&frozen, &journal)
        .await
        .context("capture telemetry")?;
    let hash = archive::seal(&journal, frozen.request.operation_id)?;
    archive::verify(&journal, &hash)?;

    restore_and_readmit(&journal, &frozen, &administrator, &profile, &root, hash).await
}

async fn restore_and_readmit(
    journal: &Journal,
    frozen: &Frozen,
    administrator: &crate::config::Database,
    profile: &super::super::providers::telemetry::Request,
    root: &std::path::Path,
    hash: String,
) -> anyhow::Result<()> {
    empty_targets(profile).await?;
    let restore = Restore {
        directory: root.join("bundle"),
        operation_id: Uuid::new_v4(),
        backup_manifest_sha256: hash.clone(),
        administrator: administrator.clone(),
        accounts: vec![],
    };
    let mut c = sqlx::PgConnection::connect_with(&administrator.options()?).await?;
    connection_fence(&mut c, journal, true).await?;
    crate::migration::verify_identity(&mut c, &frozen.installation).await?;
    c.close().await?;
    telemetry::restore(&restore, frozen, journal)
        .await
        .context("restore telemetry")?;
    // Replaying the same recovery identity must preserve the restored data.
    telemetry::restore(&restore, frozen, journal)
        .await
        .context("restore telemetry")?;
    telemetry::release(frozen, journal).await?;
    let mut c = sqlx::PgConnection::connect_with(&administrator.options()?).await?;
    connection_fence(&mut c, journal, false).await?;
    c.close().await?;
    telemetry::admit(frozen)
        .await
        .context("readmit telemetry")?;
    Ok(())
}

async fn empty_targets(
    profile: &super::super::providers::telemetry::Request,
) -> anyhow::Result<()> {
    // Product storage is not a provider-specific failure mode.
    recreate(&profile.administrator).await?;
    if profile.clickhouse.is_some() {
        super::super::providers::telemetry::clickhouse::execute(
            profile,
            "fixture-drop-owned-data",
            "DROP DATABASE rss_ts_ch SYNC",
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn recreate(database: &crate::config::Database) -> anyhow::Result<()> {
    let mut original = sqlx::PgConnection::connect_with(&database.options()?).await?;
    no_writers(&mut original).await?;
    let owner: String = sqlx::query_scalar(
        "SELECT pg_get_userbyid(datdba)::text FROM pg_database WHERE datname=current_database()",
    )
    .fetch_one(&mut original)
    .await?;
    original.close().await?;
    ensure!(
        database.name != "postgres" && database.name != "template0" && database.name != "template1"
    );
    let mut c = sqlx::PgConnection::connect_with(&database.options()?.database("postgres")).await?;
    let quote = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE {}",
        quote(&database.name)
    )))
    .execute(&mut c)
    .await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE {} OWNER {} TEMPLATE template0",
        quote(&database.name),
        quote(&owner)
    )))
    .execute(&mut c)
    .await?;
    c.close().await?;
    Ok(())
}
