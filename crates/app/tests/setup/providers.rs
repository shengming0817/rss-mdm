use super::*;

#[test]
fn equivalent_policy_order_is_stable_but_broader_scope_is_rejected() {
    let expected = policy("content", "content/tenant");
    let mut reordered = expected.clone();
    reordered["Statement"].as_array_mut().unwrap().reverse();
    assert_eq!(
        canonical_policy(expected.clone()),
        canonical_policy(reordered.clone())
    );
    reordered["Statement"][0]["Resource"] = json!(["arn:aws:s3:::content/content/*"]);
    assert_ne!(canonical_policy(expected), canonical_policy(reordered));
}

fn secret(root: &std::path::Path, name: &str, value: &str) -> PathBuf {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let path = root.join(name);
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(value.as_bytes()).unwrap();
    file.sync_all().unwrap();
    path
}

#[tokio::test]
#[ignore = "MODULE=installation.providers: actual RustFS identity, versioned I/O, cross-prefix denial and replay"]
async fn real_storage_creation_replay_and_broad_import_rejection() -> anyhow::Result<()> {
    let fixture: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_S3_FIXTURE")?)?)?;
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().canonicalize()?;
    let root = directory.as_path();
    let profile = Profile {
        id: "controlled".into(),
        endpoint: fixture["endpoint"].as_str().unwrap().into(),
        region: fixture["region"].as_str().unwrap().into(),
        bucket: fixture["bucket"].as_str().unwrap().into(),
        namespace: fixture["namespace"].as_str().unwrap().into(),
        ca_file: PathBuf::from(fixture["ca"].as_str().unwrap()),
        rustfs_administrator: Some(Administrator {
            access_key_file: secret(
                root,
                "admin-access",
                fixture["rootAccessKey"].as_str().unwrap(),
            ),
            secret_key_file: secret(
                root,
                "admin-secret",
                fixture["rootSecretKey"].as_str().unwrap(),
            ),
            session_token_file: None,
        }),
        boundary_verifier: None,
    };
    let tenant = uuid::Uuid::new_v4();
    let operation = uuid::Uuid::new_v4();
    let material = Workload {
        create_identity: true,
        access: format!("rss{}", tenant.simple()).into(),
        secret: format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        )
        .into(),
        token: None,
    };
    let first = prepare(root, &profile, tenant, operation, &material).await?;
    anyhow::ensure!(
        first.qualified && first.namespace == format!("{}/{tenant}", profile.namespace)
    );
    let replay = prepare(root, &profile, tenant, operation, &material).await?;
    anyhow::ensure!(serde_json::to_value(first)? == serde_json::to_value(replay)?);
    let mut changed = material;
    changed.secret = uuid::Uuid::new_v4().to_string().into();
    anyhow::ensure!(matches!(
        prepare(root, &profile, tenant, operation, &changed).await,
        Err(Error::Conflict)
    ));
    let broad = Workload {
        create_identity: false,
        access: fixture["accessKey"].as_str().unwrap().to_owned().into(),
        secret: fixture["secretKey"].as_str().unwrap().to_owned().into(),
        token: None,
    };
    anyhow::ensure!(
        prepare(root, &profile, tenant, uuid::Uuid::new_v4(), &broad)
            .await
            .is_err()
    );
    Ok(())
}
