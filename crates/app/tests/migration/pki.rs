use super::*;
#[tokio::test]
#[ignore = "make t2 MODULE=installation.migration: exact pre-PKI schema and read-only preparation"]
async fn explicit_upgrade_prepares_from_old_manifest_and_rejects_wrong_target_before_writes()
-> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let root = std::path::PathBuf::from(std::env::var("MDM_WINDOWS_FIXTURES")?);
    let scratch = tempfile::tempdir()?;
    let mut config: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))?;
    config["native_protocols"]["windows"] =
        serde_json::from_slice(&std::fs::read(root.join("windows.json"))?)?;
    let trust: Trust = serde_json::from_slice(&std::fs::read(
        config["native_protocols"]["windows"]["trust_file"]
            .as_str()
            .unwrap(),
    )?)?;
    config["identity"]["tenant_id"] = serde_json::json!(trust.tenant);
    config["agent_pki"] = serde_json::json!({"mode":"disabled"});
    for (key, text) in [
        ("database", "runtime-password"),
        ("audit_worker", "independent-worker-password"),
    ] {
        let path = scratch.path().join(key);
        std::fs::write(&path, text)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        config["identity"][key]["password_file"] = serde_json::json!(path);
    }
    let target = scratch.path().join("target.json");
    std::fs::write(&target, serde_json::to_vec(&config)?)?;
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))?;
    let installation = Installation {
        audit_mode: AuditMode::Plain,
        instance_id: config["identity"]["instance_id"].as_str().unwrap().into(),
        target: [1; 16],
        lineage: [2; 16],
        epoch: 1,
        tenants: vec![trust.tenant.to_string()],
    };
    let targets = target_profiles(&target, &installation, std::slice::from_ref(&trust))?;
    assert_eq!(targets.len(), 1);
    let options: PgConnectOptions = std::env::var("MDM_OWNER_URL")?.parse()?;
    let mut conn = PgConnection::connect_with(
        &options
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert(std::env::var("PG_CA_FILE")?),
    )
    .await?;
    let baseline = baseline_units()
        .into_iter()
        .filter(|(name, _)| *name != "device-pki-v1")
        .collect::<Vec<_>>();
    migrate_units(&mut conn, &installation, &baseline).await?;
    let profiles = prepare_on(&mut conn, &installation, &targets).await?;
    assert!(profiles.is_empty());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM public.mdm_migrations")
        .fetch_one(&mut conn)
        .await?;
    assert_eq!(
        count as usize,
        baseline.len(),
        "preparation must not migrate"
    );
    let database: crate::config::Database =
        serde_json::from_value(config["access_database"].clone())?;
    let mut input = Upgrade {
        database,
        installation,
        target_config_file: target,
        profiles: vec![Profile {
            purpose: Purpose::Windows,
            previous: "1".repeat(64),
            current: "2".repeat(64),
        }],
        trusts: vec![trust],
    };
    assert!(validate_profiles(&input).is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_migrations")
            .fetch_one(&mut conn)
            .await?,
        count
    );
    input.profiles.clear();
    validate_profiles(&input)?;
    on(&mut conn, &input).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_migrations WHERE complete")
            .fetch_one(&mut conn)
            .await? as usize,
        units().len()
    );
    on(&mut conn, &input).await?;
    conn.close().await?;
    Ok(())
}
