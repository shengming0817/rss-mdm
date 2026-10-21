use super::*;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
};

fn private(root: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf> {
    let path = root.join(name);
    std::fs::write(&path, bytes)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}
fn input(root: &Path, config: &crate::config::Config, fixture: &Value) -> Result<Input> {
    let administrator = storage::Administrator {
        access_key_file: private(
            root,
            "access",
            fixture["rootAccessKey"].as_str().unwrap().as_bytes(),
        )?,
        secret_key_file: private(
            root,
            "secret",
            fixture["rootSecretKey"].as_str().unwrap().as_bytes(),
        )?,
        session_token_file: None,
    };
    let mut input: Input = serde_json::from_value(json!({
        "directory":root,"deployment":{"directory":root.join("runtime"),"probe_address":null,"certificate_file":root.join("unused-cert"),"private_key_file":root.join("unused-key"),"trust_file":root.join("unused-ca")},
        "database":{"administrator":config.identity.database,"name":config.identity.database.name},
        "audit_mode":"plain","organization_name":"fixture","platform_login":"platform","administrator_login":"administrator","origin":"https://localhost:8445","listen":"127.0.0.1:8081","trusted_gateway":"127.0.0.1"
    }))?;
    input.storage_profiles.push(storage::Profile {
        id: "valid".into(),
        endpoint: fixture["endpoint"].as_str().unwrap().into(),
        region: fixture["region"].as_str().unwrap().into(),
        bucket: fixture["bucket"].as_str().unwrap().into(),
        namespace: fixture["namespace"].as_str().unwrap().into(),
        ca_file: fixture["ca"].as_str().unwrap().into(),
        rustfs_administrator: Some(administrator),
        boundary_verifier: None,
    });
    Ok(input)
}
async fn reserve(
    c: &mut PgConnection,
    tenant: Uuid,
    revision: i64,
    profile: &str,
    source: connections::Source,
    protection: &rss_mdm_native_protection::Protector,
) -> Result<Uuid> {
    let operation = Uuid::new_v4();
    let mut tx = c.begin().await?;
    scope(&mut tx, tenant).await?;
    connections::prepare(
        &mut tx,
        TenantId::parse(&tenant.to_string())?,
        operation,
        &connections::Request {
            expected_revision: revision,
            profile: profile.into(),
            source,
        },
        "reconcile-fixture",
        protection,
    )
    .await?;
    tx.commit().await?;
    Ok(operation)
}
async fn receipt(
    c: &mut PgConnection,
    tenant: Uuid,
    operation: Uuid,
) -> Result<connections::Receipt> {
    let mut tx = c.begin().await?;
    scope(&mut tx, tenant).await?;
    let value =
        connections::operation_receipt(&mut tx, TenantId::parse(&tenant.to_string())?, operation)
            .await?;
    tx.rollback().await?;
    Ok(value)
}
#[tokio::test]
#[ignore = "MODULE=installation.storage_reconcile: failed windows rotate fairly and expired cached qualification does not block peers"]
async fn failed_candidates_and_expired_evidence_do_not_block_later_work() -> Result<()> {
    let config =
        crate::test_support::identity::config(crate::test_support::runtime::case_tenant())?;
    let protection = config.native_protector()?;
    let fixture: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_S3_FIXTURE")?)?)?;
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let input = input(&root, &config, &fixture)?;
    let options = sqlx::postgres::PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut c = PgConnection::connect_with(&options).await?;
    let mut tenants = [
        Uuid::parse_str(crate::test_support::runtime::case_tenant())?,
        Uuid::parse_str(crate::test_support::case::peer())?,
    ];
    tenants.sort();
    let [tenant, peer] = tenants;
    let mut missing = Vec::new();
    for revision in 0..8 {
        missing.push(
            reserve(
                &mut c,
                tenant,
                revision,
                "missing",
                connections::Source::Generate,
                &protection,
            )
            .await?,
        );
    }
    let valid = reserve(
        &mut c,
        tenant,
        8,
        "valid",
        connections::Source::Generate,
        &protection,
    )
    .await?;
    let mut tx = c.begin().await?;
    scope(&mut tx, tenant).await?;
    let pending = connections::pending(
        &mut tx,
        TenantId::parse(&tenant.to_string())?,
        valid,
        &protection,
    )
    .await?;
    tx.rollback().await?;
    let mut material = Workload {
        create_identity: true,
        access: pending.credentials.access_key,
        secret: pending.credentials.secret_key,
        token: None,
    };
    storage::prepare(&root, &input.storage_profiles[0], tenant, valid, &material).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut c)
            .await?;
    let expired = reserve(
        &mut c,
        tenant,
        9,
        "valid",
        connections::Source::Import {
            access_key: material.access.clone(),
            secret_key: material.secret.clone(),
            session_token: None,
            expires_at: Some(now + 10),
        },
        &protection,
    )
    .await?;
    material.create_identity = false;
    // Cache genuine import qualification, then cross the real credential deadline before domain commit.
    storage::prepare(
        &root,
        &input.storage_profiles[0],
        tenant,
        expired,
        &material,
    )
    .await?;
    tokio::time::sleep(std::time::Duration::from_secs(11)).await;
    storage(&input, &config, &mut c).await?;
    ensure!(receipt(&mut c, tenant, valid).await?.state == "pending");
    let peer_valid = reserve(
        &mut c,
        peer,
        0,
        "valid",
        connections::Source::Generate,
        &protection,
    )
    .await?;
    storage(&input, &config, &mut c).await?;
    ensure!(receipt(&mut c, tenant, valid).await?.state == "qualified");
    let rejected = receipt(&mut c, tenant, expired).await?;
    ensure!(
        rejected.state == "rejected"
            && rejected.failure_reason.as_deref() == Some("credentials_expired")
    );
    ensure!(receipt(&mut c, peer, peer_valid).await?.state == "qualified");
    storage(&input, &config, &mut c).await?;
    ensure!(receipt(&mut c, tenant, expired).await?.state == "rejected");
    for operation in missing {
        ensure!(
            receipt(&mut c, tenant, operation)
                .await?
                .failure_reason
                .as_deref()
                == Some("profile_unavailable")
        );
    }
    c.close().await?;
    Ok(())
}
