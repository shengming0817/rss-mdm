//! Cold restore on the existing isolated DA database; original files intentionally remain.
use super::*;
use anyhow::Context as _;
use rss_da_app::{backup, config};
use rss_mdm_install_support::maintenance::journal::Journal;
use sqlx::Connection;
use std::os::unix::fs::PermissionsExt;

pub async fn verify(
    inputs: &Inputs,
    material: &material::Material,
    installed: host::InstalledHost,
) -> Result<()> {
    let administrator: config::Database =
        serde_json::from_value(serde_json::to_value(inputs.database("postgres"))?)?;
    let runtime: config::Config = config::load(&installed.runtime_file)?;
    let operation = Uuid::new_v4();
    let directory = inputs.directory.join(format!("da-backup-{operation}"));
    let offline = inputs.directory.join(format!("da-offline-{operation}"));
    std::fs::create_dir(&offline)?;
    std::fs::set_permissions(&offline, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(&material.directory, std::fs::Permissions::from_mode(0o700))?;
    let online = material.directory.join("task-trust-ca");
    let key = openssl::pkey::PKey::private_key_from_pem(&std::fs::read(online.join("ca.key"))?)?;
    host::private(
        &offline.join("root-password"),
        b"original-test-root-password",
    )?;
    host::private(
        &offline.join("root.pem"),
        &key.private_key_to_pem_pkcs8_passphrase(
            openssl::symm::Cipher::aes_256_cbc(),
            b"original-test-root-password",
        )?,
    )?;
    let configuration_file = online.join("backup-ca.json");
    host::private(
        &configuration_file,
        &serde_json::to_vec(&serde_json::json!({
            "crt":online.join("ca.pem"),"root":online.join("ca.pem")
        }))?,
    )?;
    let request = serde_json::to_value(backup::Request {
        operation_id: operation,
        directory: directory.clone(),
        installation_directory: material.directory.clone(),
        runtime_file: installed.runtime_file.clone(),
        administrator: administrator.clone(),
        authorities: vec![rss_mdm_pki_service::backup::Authority {
            purpose: rss_mdm_agent_wire::pki::Purpose::DaDevice,
            issuer: runtime.registration.providers[0].issuer.clone(),
            configuration_file,
            online_directory: online,
            offline_directory: offline.clone(),
            root_private_key_file: offline.join("root.pem"),
            root_password_file: offline.join("root-password"),
        }],
    })?;
    let mut connection = sqlx::PgConnection::connect_with(&administrator.options()?).await?;
    let revoked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_da.devices WHERE state = 'revoked'")
            .fetch_one(&mut connection)
            .await?;
    assert!(revoked > 0);
    let old_vault_epoch = Uuid::new_v4();
    sqlx::query("INSERT INTO rss_da.vault_epochs(tenant_id,incarnation) VALUES($1,$2) ON CONFLICT(tenant_id) DO UPDATE SET incarnation=excluded.incarnation").bind(runtime.installation.tenant).bind(old_vault_epoch).execute(&mut connection).await?;
    connection.close().await?;
    Box::pin(backup::capture(serde_json::from_value(request.clone())?))
        .await
        .context("capture cold baseline")?;
    // Reconstruct a crash after Complete, before the final local cleanup.
    Journal::open(&material.directory)?.save("backup-operation.json", &Some(operation))?;
    Box::pin(backup::capture(serde_json::from_value(request)?))
        .await
        .context("reenter completed capture")?;
    assert_eq!(
        Journal::open(&material.directory)?.load::<Option<Uuid>>("backup-operation.json")?,
        Some(None)
    );
    let progress: serde_json::Value = Journal::open(&directory)?
        .load("backup-progress.json")?
        .unwrap();
    let manifest = progress["digest"].as_str().unwrap().to_owned();

    // This database is the runner-owned, isolated fixture. Preserve all original material.
    let mut cluster =
        sqlx::PgConnection::connect_with(&administrator.options()?.database("postgres")).await?;
    for statement in [
        "SELECT format('DROP DATABASE %I', $1::text)",
        "SELECT format('CREATE DATABASE %I', $1::text)",
    ] {
        let sql: String = sqlx::query_scalar(statement)
            .bind(&administrator.name)
            .fetch_one(&mut cluster)
            .await?;
        // PostgreSQL format %I quotes the isolated database identifier.
        sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
            .execute(&mut cluster)
            .await?;
    }
    cluster.close().await?;
    let password = std::fs::read(&installed.accounts[0].password_file)?;
    let verification_password = inputs
        .directory
        .join(format!("da-restore-password-{operation}"));
    host::private(&verification_password, b"wrong-original-test-password")?;
    let mut accounts = installed.accounts;
    for account in &mut accounts {
        account.password_file = verification_password.clone();
    }
    let restore = serde_json::to_value(backup::Restore {
        operation_id: Uuid::new_v4(),
        directory,
        backup_manifest_sha256: manifest,
        administrator: administrator.clone(),
        accounts,
    })?;
    assert!(
        Box::pin(backup::restore(serde_json::from_value(restore.clone())?))
            .await
            .is_err()
    );
    let mut connection = sqlx::PgConnection::connect_with(&administrator.options()?).await?;
    let stage: (bool, bool) =
        sqlx::query_as("SELECT baseline_verified,complete FROM public.da_restore_operation")
            .fetch_one(&mut connection)
            .await?;
    assert_eq!(
        stage,
        (true, false),
        "failure occurs after the restored baseline was verified"
    );
    let grant: String = sqlx::query_scalar(
        "SELECT format('GRANT CONNECT ON DATABASE %I TO da_access',current_database())",
    )
    .fetch_one(&mut connection)
    .await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(grant))
        .execute(&mut connection)
        .await?;
    connection.close().await?;
    assert!(
        matches!(
            rss_da_app::maintenance::diagnose(config::load(&installed.runtime_file)?).await,
            Err(rss_da_app::Error::Admission)
        ),
        "even an open CONNECT cannot admit an incomplete restore"
    );
    let mut other = restore.clone();
    other["operation_id"] = serde_json::json!(Uuid::new_v4());
    assert!(
        Box::pin(backup::restore(serde_json::from_value(other)?))
            .await
            .is_err()
    );
    host::private(&verification_password, &password)?;
    Box::pin(backup::restore(serde_json::from_value(restore.clone())?))
        .await
        .context("resume verified restore")?;
    Box::pin(backup::restore(serde_json::from_value(restore)?))
        .await
        .context("reenter completed restore")?;
    let mut connection = sqlx::PgConnection::connect_with(&administrator.options()?).await?;
    let new_epoch: Uuid =
        sqlx::query_scalar("SELECT incarnation FROM rss_da.vault_epochs WHERE tenant_id=$1")
            .bind(runtime.installation.tenant)
            .fetch_one(&mut connection)
            .await?;
    assert_ne!(
        old_vault_epoch, new_epoch,
        "cold restore must not resurrect the backup's sync authority"
    );
    let preserved: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_da.devices WHERE state = 'revoked'")
            .fetch_one(&mut connection)
            .await?;
    assert_eq!(
        preserved, revoked,
        "recovery must not reactivate revoked registrations"
    );
    connection.close().await?;
    Box::pin(rss_da_app::maintenance::diagnose(config::load(
        &installed.runtime_file,
    )?))
    .await?;
    Ok(())
}
