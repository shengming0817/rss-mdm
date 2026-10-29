//! Real PostgreSQL plus the shared TLS S3 provider; product admission and HTTP are exercised.
use super::content_pg as pg;
use crate::test_support::software::Fixture;
use crate::test_support::{runtime::*, *};
use anyhow::Context;
use rss_mdm_content_service::{Binding, Purpose, ResourceBinding, StorageClass};

#[tokio::test]
#[ignore = "MODULE=content.storage: durable credential replay, provider authority and expiry fences"]
async fn connection_operations_bind_actor_material_and_provider_authority() -> Result<()> {
    use rss_mdm_content_service::connections as c;
    use sqlx::Connection;
    let config = crate::test_support::identity::config(case_tenant())?;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let protection = config.native_protector()?;
    let mut connection = sqlx::PgConnection::connect_with(&config.access_options()?).await?;
    let mut tx = connection.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    let operation = Uuid::new_v4();
    let mut input = c::Request {
        expected_revision: 0,
        profile: "rustfs".into(),
        source: c::Source::Generate,
    };
    let first = c::prepare(
        &mut tx,
        tenant,
        operation,
        &input,
        "operator-a",
        &protection,
    )
    .await?;
    let original = c::pending(&mut tx, tenant, operation, &protection).await?;
    let replay = c::prepare(
        &mut tx,
        tenant,
        operation,
        &input,
        "operator-a",
        &protection,
    )
    .await?;
    ensure!(serde_json::to_value(&first)? == serde_json::to_value(replay)?);
    ensure!(
        c::pending(&mut tx, tenant, operation, &protection)
            .await?
            .credentials
            .secret_key
            == original.credentials.secret_key
    );
    ensure!(
        c::prepare(
            &mut tx,
            tenant,
            operation,
            &input,
            "operator-b",
            &protection
        )
        .await
        .is_err()
    );
    input.profile = "other".into();
    ensure!(
        c::prepare(
            &mut tx,
            tenant,
            operation,
            &input,
            "operator-a",
            &protection
        )
        .await
        .is_err()
    );
    ensure!(c::load(&mut tx, tenant, 1, &protection).await.is_err());
    let metadata = c::Metadata {
        endpoint: "https://storage.example.test".into(),
        region: "us-east-1".into(),
        bucket: "content".into(),
        namespace: "content".into(),
        private_ca: vec![],
    };
    ensure!(
        c::qualify(&mut tx, tenant, operation, &metadata, 1)
            .await
            .is_err()
    );
    ensure!(
        c::bind_metadata(&mut tx, tenant, operation, &metadata)
            .await
            .is_err()
    );
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await?;
    ensure!(
        c::operation_receipt(&mut tx, tenant, operation)
            .await
            .is_err()
    );
    tx.rollback().await?;
    connection.close().await?;
    Ok(())
}
fn binding(bytes: &[u8], class: StorageClass) -> Binding {
    Binding {
        purpose: Purpose::Resource(ResourceBinding {
            inspection: None,
            storage_class: class,
            resource: "storage-fixture".into(),
            version: "1".into(),
            variant: "default".into(),
            platform: rss_mdm_resource::Platform::Windows,
            architecture: rss_mdm_resource::Architecture::X86_64,
            resource_digest: [1; 32],
            source: None,
            origin: None,
        }),
        reference: "fixture".into(),
        length: bytes.len() as u64,
        sha256: rss_mdm_resource::Digest::of(bytes).bytes(),
        actor: "storage-fixture".into(),
    }
}

#[tokio::test]
#[ignore = "MODULE=content.storage: interrupted encryption rotation preserves credentials and request replay"]
async fn interrupted_connection_rewrap_keeps_identity_and_resumes() -> Result<()> {
    use rss_mdm_content_service::connections as c;
    use sqlx::Connection;
    use std::str::FromStr;
    let config = crate::test_support::identity::config(case_tenant())?;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let old = config.native_protector()?;
    let original = crate::config::read(&config.native_protection.active_file, 32, true)?;
    let fingerprint = crate::config::read(&config.native_protection.fingerprint_file, 32, true)?;
    let next = rss_mdm_native_protection::Protector::with_fingerprint(
        &[72; 32],
        &[original.as_slice()],
        &fingerprint,
    )?;
    let options = sqlx::postgres::PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut connection = sqlx::PgConnection::connect_with(&options).await?;
    let operation = Uuid::new_v4();
    let input = c::Request {
        expected_revision: 0,
        profile: "rewrap-fixture".into(),
        source: c::Source::Generate,
    };
    let mut tx = connection.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    let receipt = c::prepare(&mut tx, tenant, operation, &input, "operator", &old).await?;
    let secret = c::pending(&mut tx, tenant, operation, &old)
        .await?
        .credentials
        .secret_key;
    tx.commit().await?;
    let mut tx = connection.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    ensure!(c::rewrap(&mut tx, tenant, &next).await? == 1);
    tx.rollback().await?;
    let mut tx = connection.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    ensure!(
        c::pending(&mut tx, tenant, operation, &old)
            .await?
            .credentials
            .secret_key
            == secret
    );
    ensure!(c::rewrap(&mut tx, tenant, &next).await? == 1);
    ensure!(c::rewrap(&mut tx, tenant, &next).await? == 0);
    tx.commit().await?;
    let mut tx = connection.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    ensure!(
        c::pending(&mut tx, tenant, operation, &next)
            .await?
            .credentials
            .secret_key
            == secret
    );
    ensure!(c::pending(&mut tx, tenant, operation, &old).await.is_err());
    ensure!(
        serde_json::to_value(
            c::prepare(&mut tx, tenant, operation, &input, "operator", &next).await?
        )? == serde_json::to_value(receipt)?
    );
    tx.rollback().await?;
    connection.close().await?;
    Ok(())
}
fn s3_storage() -> Result<(tempfile::TempDir, Value)> {
    let provider: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_S3_FIXTURE")?)?)?;
    let private = tempfile::tempdir()?;
    for (name, key) in [("access", "accessKey"), ("secret", "secretKey")] {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(private.path().join(name))?
            .write_all(provider[key].as_str().unwrap().as_bytes())?;
    }
    let example: Value = serde_json::from_str(include_str!(
        "../../../../fixtures/mdm-content-s3.example.json"
    ))?;
    let _: rss_mdm_content_service::Config = serde_json::from_value(example.clone())?;
    let mut storage = example["storage"].clone();
    storage["revision"] = json!(1);
    storage["max_concurrent"] = json!(4);
    Ok((private, storage))
}
async fn stores(
    storage: Option<Value>,
    transfer_seconds: u64,
) -> Result<(
    Resources,
    Arc<rss_mdm_content_service::Store>,
    Arc<rss_mdm_content_service::Store>,
)> {
    let mut config: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    if let Some(storage) = storage {
        config["content"]["storage"] = storage;
    }
    config["content"]["transfer_seconds"] = json!(transfer_seconds);
    config["content"]["max_artifact_bytes"] = json!(160 * 1024 * 1024);
    config["content"]["max_temporary_bytes"] = json!(512 * 1024 * 1024);
    let config: crate::config::Config = serde_json::from_value(config)?;
    crate::test_support::storage::seed(&config).await?;
    let (resources, (first, second)) = Resources::build(|resources| {
        Box::pin(async move {
            let first =
                crate::execution_assembly::open_content(&config, config.native_protector()?)
                    .await?
                    .unwrap();
            resources.resource(crate::execution_assembly::ContentResource(first.clone()));
            let second =
                crate::execution_assembly::open_content(&config, config.native_protector()?)
                    .await?
                    .unwrap();
            resources.resource(crate::execution_assembly::ContentResource(second.clone()));
            Ok((first, second))
        })
    })
    .await?;
    Ok((resources, first, second))
}

#[tokio::test]
#[ignore = "MODULE=content.storage: real volume migration followed by product publication and S3 HTTP range consumption"]
async fn s3_product_http_contract() -> Result<()> {
    // Keep the original HTTP composition alive through the actual maintenance command.
    let mut fixture = Fixture::open(false).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources
        .finish(async {
            let bytes = vec![0x71; 1024 * 1024 + 1];
            let definition = publication_support::private_definition(fixture.registered["snapshot"].clone(), &bytes);
            let (resource, _) = crate::test_support::software::seed_software_version(&fixture.runtime, definition).await?;
            let mut user = fixture.user.clone();
            let cookie = user.cookies.iter().map(|(k,v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
            let operation = Uuid::new_v4();
            let response = fixture.client.post(format!("{}/api/v1/resources/{resource}/content?version=v1&variant=default&platform=windows&architecture=x86_64&operation={operation}",fixture.origin))
                .header("host","mdm.example.test").header("origin","https://mdm.example.test").header("x-identity-request","1")
                .header("x-csrf-token",user.csrf.as_ref().unwrap()).header("cookie",&cookie).header("content-type","application/octet-stream").body(bytes.clone()).send().await?;
            ensure!(response.status()==StatusCode::CREATED, "S3 upload: {}", response.text().await?);
            migrate_uploaded_fixture(&mut fixture).await?;
            let path = format!("/api/v1/software/resources/{resource}/versions/v1");
            let enabled = user.call(&fixture.router, Method::POST, &path, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"enable"}}))).await?;
            ensure!(enabled.0==StatusCode::OK,"S3 enable: {enabled:?}");
            let response = fixture.client.get(format!("{}{path}/content?platform=windows&architecture=x86_64&variant=default",fixture.origin))
                .header("host","mdm.example.test").header("cookie",cookie).header("range",format!("bytes={}-",bytes.len()-3)).send().await?;
            ensure!(response.status()==StatusCode::PARTIAL_CONTENT);
            ensure!(response.bytes().await?.as_ref()==&bytes[bytes.len()-3..]);
            Ok(())
        })
        .await
}
#[tokio::test]
#[ignore = "MODULE=content.storage: durable PG control, real S3 fixed chunks and native snapshots"]
async fn s3_artifact_cross_chunk_frontier() -> Result<()> {
    let (_secrets, storage) = s3_storage()?;
    // The fixed 128 MiB seam is not a throughput assertion in a debug provider build.
    let (resources, store, second) = stores(Some(storage), 180).await?;
    resources.finish(async {
    let now = crate::windows::test_support::now();
    let bytes = vec![0x67; 128 * 1024 * 1024 + 3];
    let b = binding(&bytes, StorageClass::Artifact);
    let id = Uuid::new_v4();
    let actor = &b.actor;
    let artifact = b.artifact()?;
    store.begin(id, b.clone(), now, store.upload_budget()?, ).await?;
    ensure!(store.append(actor, id, 0, now, &bytes[..3], store.upload_budget()?, ).await?.offset == 3);
    ensure!(
        store
            .append(actor, id, 3, now, &bytes[3..65539], store.upload_budget()?, )
            .await?
            .offset
            == 65539
    );

    ensure!(second.status(actor, id, now).await?.offset == 65539);
    second
        .append(actor, id, 65539, now, &bytes[65539..], second.upload_budget()?, )
        .await.context("append large S3 frontier")?;
    second.finish(actor, id, now, second.upload_budget()?, ).await.context("finish S3 frontier")?;
    let digest = b
        .sha256
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    ensure!(pg(&format!("SELECT jsonb_array_length(document->'value'->'pieces') FROM mdm_content.manifests WHERE tenant_id='{}' AND class='artifact' AND encode(sha256,'hex')='{}'",case_tenant(),digest))?.trim()=="2");
    let mut stream = store
        .verify(&artifact)
        .await.context("verify S3 frontier")?
        .stream(128 * 1024 * 1024 - 2, artifact.length())
        .await.context("open cross-chunk S3 range")?;
    use futures::StreamExt;
    let mut tail = Vec::new();
    while let Some(part) = stream.next().await {
        tail.extend_from_slice(&part.context("consume cross-chunk S3 range")?);
    }
    ensure!(tail == vec![0x67; 5]);
    Ok(())
    }).await
}
#[tokio::test]
#[ignore = "MODULE=content.storage: real PG multi-instance epoch and failed-body frontier"]
async fn volume_fences_a_stale_writer_and_keeps_failed_body_frontier() -> Result<()> {
    let (resources, store, second) = stores(None, 60).await?;
    resources.finish(async {
    let bytes = b"epoch-frontier-bytes";
    let b = binding(bytes, StorageClass::Artifact);
    let id = Uuid::new_v4();
    let now = crate::windows::test_support::now();
    store.begin(id, b.clone(), now, store.upload_budget()?, ).await?;
    let (mut producer, body) = tokio::io::duplex(128);
    use tokio::io::AsyncWriteExt;
    producer.write_all(&bytes[..3]).await?;
    let stale = store.clone();
    let actor = b.actor.clone();
    let writer = tokio::spawn(async move { stale.append(&actor, id, 0, now - 30, body, stale.upload_budget()?, ).await });
    // Wait on the durable claim rather than relying on a scheduler delay.
    tokio::time::timeout(Duration::from_secs(5),async{loop{
  if pg(&format!("SELECT count(*) FROM mdm_content.uploads WHERE tenant_id='{}' AND document->'value'->'upload'->>'id'='{}' AND epoch IS NOT NULL",case_tenant(),id))?.trim()=="1"{break Ok::<_,anyhow::Error>(())}tokio::time::sleep(Duration::from_millis(10)).await;
 }}).await??;
    let minimum_expiry = now + store.config.transfer_seconds as i64 - 5;
    ensure!(pg(&format!("SELECT held_until >= {minimum_expiry} FROM mdm_content.uploads WHERE tenant_id='{}' AND document->'value'->'upload'->>'id'='{id}'",case_tenant()))?.trim()=="t", "lease must cover the absolute budget even when caller wall time is stale");
    pg(&format!(
        "UPDATE mdm_content.uploads SET held_until=0 WHERE tenant_id='{}' AND document->'value'->'upload'->>'id'='{}'",
        case_tenant(),
        id
    ))?;

    second
        .append(&b.actor, id, 0, now, bytes.as_slice(), second.upload_budget()?, )
        .await?;
    drop(producer);
    ensure!(matches!(
        writer.await?,
        Err(rss_mdm_content_service::Error::Conflict)
    ));
    ensure!(store.status(&b.actor, id, now).await?.offset == bytes.len() as u64);
    store.finish(&b.actor, id, now, store.upload_budget()?, ).await?;
    ensure!(
        &*store
            .verify(&b.artifact()?)
            .await?
            .read_plaintext(bytes.len())?
            == bytes
    );
    let bad = Uuid::new_v4();
    store.begin(bad, b.clone(), now, store.upload_budget()?, ).await?;
    let body = futures::stream::iter([
        Ok(axum::body::Bytes::from_static(b"epo")),
        Err(std::io::Error::other("interrupted fixture body")),
    ]);
    let reader = tokio_util::io::StreamReader::new(body);
    ensure!(matches!(
        store.append(&b.actor, bad, 0, now, reader, store.upload_budget()?, ).await,
        Err(rss_mdm_content_service::Error::Storage)
    ));
    ensure!(store.status(&b.actor, bad, now).await?.offset == 0);
    // Dropping a request must release its exact persisted claim, not wait for retention expiry.
    let cancelled = Uuid::new_v4();
    store.begin(cancelled, b.clone(), now, store.upload_budget()?).await?;
    let (producer, body) = tokio::io::duplex(128);
    let pending = store.clone(); let actor = b.actor.clone();
    let writer = tokio::spawn(async move {
        pending.append(&actor, cancelled, 0, now, body, pending.upload_budget()?).await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if pg(&format!("SELECT count(*) FROM mdm_content.uploads WHERE tenant_id='{}' AND document->'value'->'upload'->>'id'='{cancelled}' AND epoch IS NOT NULL",case_tenant()))?.trim()=="1" {break Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    writer.abort(); ensure!(matches!(writer.await, Err(error) if error.is_cancelled())); drop(producer);
    tokio::time::timeout(Duration::from_secs(7), async {
        loop {
            if pg(&format!("SELECT count(*) FROM mdm_content.uploads WHERE tenant_id='{}' AND document->'value'->'upload'->>'id'='{cancelled}' AND epoch IS NULL AND held_until=0",case_tenant()))?.trim()=="1" {break Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    second.append(&b.actor, cancelled, 0, now, bytes.as_slice(), second.upload_budget()?).await?;

    Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=content.storage: physical S3 snapshot survives failed PG frontier commit"]
async fn s3_failed_frontier_commit_preserves_acknowledged_native_prefix() -> Result<()> {
    let (_secrets, storage) = s3_storage()?;
    let (resources, store, second) = stores(Some(storage), 60).await?;
    resources.finish(async {

    let bytes = b"confirmed-prefix-and-retry";
    let b = binding(bytes, StorageClass::NativeConfiguration);
    let id = Uuid::new_v4();
    let now = crate::windows::test_support::now();
    store.begin(id, b.clone(), now, store.upload_budget()?, ).await?;
    store.append(&b.actor, id, 0, now, &bytes[..3], store.upload_budget()?, ).await?;
    // A deferred constraint trigger rejects COMMIT, after the provider object and
    // ready coordinate have committed. Claim/release do not change the document.
    pg(&format!(
        r#"
CREATE FUNCTION public.content_frontier_fault() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF NEW.tenant_id='{}'::uuid THEN RAISE EXCEPTION 'fixture frontier commit failure'; END IF; RETURN NEW; END $$;
CREATE CONSTRAINT TRIGGER content_frontier_fault AFTER UPDATE ON mdm_content.uploads
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (OLD.document IS DISTINCT FROM NEW.document)
EXECUTE FUNCTION public.content_frontier_fault();"#,
        case_tenant()
    ))?;
    let observed = async {
    ensure!(matches!(
        store.append(&b.actor, id, 3, now, &bytes[3..], store.upload_budget()?, ).await,
        Err(rss_mdm_content_service::Error::CommitUnknown)
    ));
    ensure!(second.status(&b.actor, id, now).await?.offset == 3);
    ensure!(pg(&format!("SELECT count(*) FROM mdm_content.objects o JOIN mdm_content.uploads u ON u.id=o.owner AND u.tenant_id=o.tenant_id WHERE u.tenant_id='{}' AND u.document->'value'->'upload'->>'id'='{}' AND o.state='ready' AND o.location->'value'->'coordinate'<>'null'::jsonb",case_tenant(),id))?.trim()=="2");
    Ok::<_, anyhow::Error>(())
    }.await;
    pg(
        "DROP TRIGGER content_frontier_fault ON mdm_content.uploads; DROP FUNCTION public.content_frontier_fault()",
    )?;
    observed?;
    second.append(&b.actor, id, 3, now, &bytes[3..], second.upload_budget()?, ).await?;
    second.finish(&b.actor, id, now, second.upload_budget()?, ).await?;
    ensure!(
        &*store
            .verify_class(&b.artifact()?, StorageClass::NativeConfiguration, second.upload_budget()?.operation_deadline())
            .await?
            .read_plaintext(bytes.len())?
            == bytes
    );
    Ok(())
    }).await
}

// A dedicated workload identity keeps this permission fault isolated from parallel S3 cases.
async fn s3_admin(provider: &Value, path: &str, body: Value) -> Result<()> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "10",
            "--cacert",
        ])
        .arg(provider["ca"].as_str().unwrap())
        .args(["--aws-sigv4", "aws:amz:us-east-1:s3", "--user"])
        .arg(format!(
            "{}:{}",
            provider["rootAccessKey"].as_str().unwrap(),
            provider["rootSecretKey"].as_str().unwrap()
        ))
        .args([
            "--request",
            if path.starts_with("remove-") {
                "DELETE"
            } else {
                "PUT"
            },
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
        ])
        .arg(format!(
            "{}/rustfs/admin/v3/{path}",
            provider["endpoint"].as_str().unwrap()
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&body)?)
        .await?;
    ensure!(
        child.wait().await?.success(),
        "isolated S3 permission fixture setup failed"
    );
    Ok(())
}
async fn s3_workload_policy(provider: &Value, access: &str, write: bool) -> Result<()> {
    let mut actions = vec![
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:DeleteObjectVersion",
    ];
    if write {
        actions.push("s3:PutObject");
    }
    let policy = json!({"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":["s3:GetBucketVersioning"],"Resource":["arn:aws:s3:::content"]},
        {"Effect":"Allow","Action":actions,"Resource":[format!("arn:aws:s3:::content/content/{}/*",case_tenant())]}
    ]});
    s3_admin(
        provider,
        &format!("add-canned-policy?name={access}"),
        policy,
    )
    .await
}
#[tokio::test]
#[ignore = "MODULE=content.storage: actual S3 PUT rejection releases only known non-writes"]
async fn s3_rejected_writes_release_quota_after_permission_recovery_and_expiry() -> Result<()> {
    let provider: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_S3_FIXTURE")?)?)?;
    let (_secrets, storage) = s3_storage()?;
    let access = format!("quota-{}", case_tenant());
    let secret = Uuid::new_v4().to_string();
    use futures::FutureExt;
    let outcome = std::panic::AssertUnwindSafe(async {
    s3_workload_policy(&provider, &access, true).await?;
    s3_admin(
        &provider,
        &format!("add-user?accessKey={access}"),
        json!({"secretKey":secret,"status":"enabled"}),
    )
    .await?;
    s3_admin(
        &provider,
        &format!("set-user-or-group-policy?policyName={access}&userOrGroup={access}&isGroup=false"),
        json!({}),
    )
    .await?;
    // 在持久权威中建立本测试的受限凭据，再构造实际运行消费者。
    let mut cfg: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    cfg["content"]["storage"] = storage;
    cfg["content"]["max_artifact_bytes"] = json!(4096);
    cfg["content"]["max_temporary_bytes"] = json!(8192);

    let cfg: crate::config::Config = serde_json::from_value(cfg)?;
    let mut scoped_provider=provider.clone();
    scoped_provider["accessKey"]=json!(access);
    scoped_provider["secretKey"]=json!(secret);
    crate::test_support::storage::seed_provider(&cfg,&scoped_provider).await?;
    let (resources, store) = Resources::build(|resources| {
        Box::pin(async move {
            let store = crate::execution_assembly::open_content(&cfg, cfg.native_protector()?)
                .await?
                .unwrap();
            resources.resource(crate::execution_assembly::ContentResource(store.clone()));
            Ok(store)
        })
    })
    .await?;
    resources.finish(async {
    s3_workload_policy(&provider, &access, false).await?;
    let bytes = vec![0x67; 4096];
    let b = binding(&bytes, StorageClass::Artifact);
    let now = crate::windows::test_support::now();
    let id = Uuid::new_v4();
    store.begin(id, b.clone(), now, store.upload_budget()?, ).await?;
    for _ in 0..4 {
        ensure!(
            matches!(
                store.append(&b.actor, id, 0, now, bytes.as_slice(), store.upload_budget()?, ).await,
                Err(rss_mdm_content_service::Error::Configuration)
            ),
            "provider must clearly reject PUT rather than exhaust quota"
        );
        ensure!(store.status(&b.actor, id, now).await?.offset == 0);
    }
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_content.objects WHERE tenant_id='{}' AND state<>'deleted'",
            case_tenant()
        ))?
        .trim()
            == "0"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_content.objects WHERE tenant_id='{}' AND state='deleted' AND location->'value'->'coordinate'='null'::jsonb",case_tenant()))?.trim()=="4");
    s3_workload_policy(&provider, &access, true).await?;
    // Expire the original reservation and prove ordinary GC can remove it without
    // inventing physical absence from a recovery HEAD response.
    pg(&format!(
        "UPDATE mdm_content.uploads SET expires=0,held_until=0 WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    ensure!(store.garbage(now).await?.is_empty());
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_content.uploads WHERE tenant_id='{}'",
            case_tenant()
        ))?
        .trim()
            == "0"
    );
    let recovered = Uuid::new_v4();
    store.begin(recovered, b.clone(), now, store.upload_budget()?, ).await?;
    store
        .append(&b.actor, recovered, 0, now, bytes.as_slice(), store.upload_budget()?, )
        .await?;
    store.finish(&b.actor, recovered, now, store.upload_budget()?, ).await?;
    ensure!(
        &*store
            .verify(&b.artifact()?)
            .await?
            .read_plaintext(bytes.len())?
            == &bytes
    );
    Ok(())
    }).await
    }).catch_unwind().await;
    let user_cleanup = s3_admin(
        &provider,
        &format!("remove-user?accessKey={access}"),
        json!({}),
    )
    .await;
    let policy_cleanup = s3_admin(
        &provider,
        &format!("remove-canned-policy?name={access}"),
        json!({}),
    )
    .await;
    match outcome {
        Ok(Ok(())) => {
            user_cleanup?;
            policy_cleanup
        }
        Ok(Err(error)) => Err(error.context(format!(
            "S3 cleanup: user={user_cleanup:?}, policy={policy_cleanup:?}"
        ))),
        Err(panic) => {
            if user_cleanup.is_err() || policy_cleanup.is_err() {
                eprintln!("S3 cleanup failed: user={user_cleanup:?}, policy={policy_cleanup:?}");
            }
            std::panic::resume_unwind(panic)
        }
    }
}

#[tokio::test]
#[ignore = "MODULE=content.storage: exact S3 version restore preserves native ciphertext, logical identity and upload frontier"]
async fn restored_provider_version_rebinds_atomically_without_reissuing_content() -> Result<()> {
    use anyhow::Context as _;
    use futures::StreamExt;
    use sqlx::Connection;
    use std::str::FromStr;
    let (_private, storage) = s3_storage()?;
    let (resources, store, _) = stores(Some(storage), 60).await?;
    resources
        .finish(async {
            let now = crate::windows::test_support::now();
            let bytes: &[u8] = b"native-ciphertext-restore-fixture";
            let binding = binding(bytes, StorageClass::NativeConfiguration);
            let artifact = binding.artifact()?;
            let operation = Uuid::new_v4();
            store
                .begin(operation, binding.clone(), now, store.upload_budget()?)
                .await?;
            store
                .append(
                    &binding.actor,
                    operation,
                    0,
                    now,
                    bytes,
                    store.upload_budget()?,
                )
                .await?;
            store
                .finish(&binding.actor, operation, now, store.upload_budget()?)
                .await?;
            let config = crate::test_support::identity::config(case_tenant())?;
            let tenant = rss_request_context::TenantId::parse(case_tenant())?;
            let protection = config.native_protector()?;
            let options =
                sqlx::postgres::PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
                    .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
                    .ssl_root_cert(std::env::var("PG_CA_FILE")?);
            let mut c = sqlx::PgConnection::connect_with(&options).await?;
            let mut tx = c.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(case_tenant())
                .execute(&mut *tx)
                .await?;
            rss_mdm_content_service::backup::validate_catalog(&mut tx, tenant, &protection)
                .await
                .context("initial catalog before restore")?;
            let generation: Uuid = sqlx::query_scalar(
                "SELECT active_generation FROM mdm_content.settings WHERE tenant_id=$1::uuid",
            )
            .bind(case_tenant())
            .fetch_one(&mut *tx)
            .await?;
            let records = rss_mdm_content_service::backup::s3_page(
                &mut tx,
                tenant,
                generation,
                &protection,
                None,
            )
            .await
            .context("original physical object directory")?;
            ensure!(records.len() == 1 && records[0].required);
            let record = records[0].clone();
            let loaded = std::sync::Arc::new(
                rss_mdm_content_service::connections::load(&mut tx, tenant, 1, &protection).await?,
            );
            tx.rollback().await?;
            let budget = || {
                rss_mdm_content_s3::Budget::new(
                    std::sync::Arc::new(crate::lifecycle::RuntimeTimer),
                    Duration::from_secs(20),
                    Duration::from_secs(5),
                    1024 * 1024,
                    16,
                )
            };
            let metadata = &loaded.metadata;
            let provider = rss_mdm_content_s3::Store::connect(
                rss_mdm_content_s3::Config {
                    endpoint: metadata.endpoint.clone(),
                    region: metadata.region.clone(),
                    bucket: metadata.bucket.clone(),
                    namespace: format!("{}/{}", metadata.namespace, case_tenant()),
                    credentials_reference: "content-connection".into(),
                    private_ca_pem: Some(metadata.private_ca.clone()),
                    max_concurrent: 1,
                    connect_timeout: Duration::from_secs(5),
                },
                loaded.clone(),
                std::sync::Arc::new(crate::lifecycle::RuntimeTimer),
                budget()?,
            )
            .await?;
            let original = record.object.as_ref().unwrap();
            let verified = provider
                .verify(original, record.content, budget()?)
                .await
                .context("verify original S3 version")?;
            let mut encrypted = Vec::new();
            let mut stream = provider
                .read(&verified, 0, record.content.length, budget()?)
                .await?;
            while let Some(chunk) = stream.next().await {
                encrypted.extend_from_slice(&chunk?);
            }
            ensure!(encrypted != bytes && encrypted.len() > bytes.len());
            ensure!(matches!(
                provider.delete(original, budget()?).await?,
                rss_mdm_content_s3::Mutation::Confirmed(())
            ));
            ensure!(matches!(
                provider.inspect(original, budget()?).await,
                Err(rss_mdm_content_s3::Error::Missing)
            ));
            let body = axum::body::Bytes::from(encrypted);
            let put = provider
                .put(
                    &record.write,
                    Box::pin(futures::stream::once(async move { Ok(body) })),
                    budget()?,
                )
                .await?;
            let rss_mdm_content_s3::Mutation::Confirmed(rss_mdm_content_s3::Written::Verified(
                restored,
            )) = put
            else {
                anyhow::bail!("provider restore must be confirmed")
            };
            ensure!(restored.object().version() != original.version());
            let mut tx = c.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(case_tenant())
                .execute(&mut *tx)
                .await?;
            ensure!(
                rss_mdm_content_service::backup::rebind(
                    &mut tx,
                    tenant,
                    &record,
                    original,
                    &restored,
                    &protection
                )
                .await
                .context("rebind signed object and upload catalogs")?
            );
            tx.rollback().await?;
            let mut tx = c.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(case_tenant())
                .execute(&mut *tx)
                .await?;
            ensure!(
                rss_mdm_content_service::backup::rebind(
                    &mut tx,
                    tenant,
                    &record,
                    original,
                    &restored,
                    &protection
                )
                .await
                .context("rebind signed object and upload catalogs")?
            );
            ensure!(
                !rss_mdm_content_service::backup::rebind(
                    &mut tx,
                    tenant,
                    &record,
                    original,
                    &restored,
                    &protection
                )
                .await
                .context("rebind signed object and upload catalogs")?
            );
            rss_mdm_content_service::backup::validate_catalog(&mut tx, tenant, &protection)
                .await
                .context("catalog after version rebind")?;
            tx.commit().await?;
            // Exercise the shared installation/transfer archive owner after the domain rebind proof.
            let archive_root = tempfile::tempdir()?;
            let archive = archive_root.path().canonicalize()?.join("snapshot");
            let host = Uuid::new_v4();
            let mut runtime: Value =
                serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
            runtime["identity"]["tenant_id"] = json!(case_tenant());
            runtime["content"]["storage"] = s3_storage()?.1;
            crate::setup::content_snapshot_fixture(&mut c, &archive, host, &runtime, false).await?;
            ensure!(matches!(
                provider.delete(restored.object(), budget()?).await?,
                rss_mdm_content_s3::Mutation::Confirmed(())
            ));
            crate::setup::content_snapshot_fixture(&mut c, &archive, host, &runtime, true).await?;
            crate::setup::content_snapshot_fixture(&mut c, &archive, host, &runtime, true).await?;
            let mut tx = c.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(case_tenant())
                .execute(&mut *tx)
                .await?;
            let final_records = rss_mdm_content_service::backup::s3_page(
                &mut tx,
                tenant,
                generation,
                &protection,
                None,
            )
            .await?;
            ensure!(final_records.len() == 1 && final_records[0].content == record.content);
            ensure!(
                final_records[0].object.as_ref().unwrap().version() != restored.object().version()
            );
            tx.rollback().await?;
            let mut output = store
                .verify_class(
                    &artifact,
                    StorageClass::NativeConfiguration,
                    store.upload_budget()?.operation_deadline(),
                )
                .await?
                .stream(0, artifact.length())
                .await?;
            let mut plain = Vec::new();
            while let Some(chunk) = output.next().await {
                plain.extend_from_slice(&chunk?);
            }
            ensure!(plain == bytes);
            let status = store.status(&binding.actor, operation, now).await?;
            ensure!(status.complete && status.offset == bytes.len() as u64);
            c.close().await?;
            Ok(())
        })
        .await
}

#[tokio::test]
#[ignore = "MODULE=content.storage: auxiliary spool quota does not block completed integrity; explicit parse persists once"]
async fn auxiliary_inspection_quota_is_optional_and_explicit_result_is_persistent() -> Result<()> {
    let (resources, store, second) = stores(None, 60).await?;
    resources.finish(async {
        let now = crate::windows::test_support::now();
        let bytes = vec![0x67; 128 * 1024 * 1024 + 3];
        let mut b = binding(&bytes, StorageClass::Artifact);
        b.purpose = Purpose::Software { resource: "quota-package".into(), filename: "package.pkg".into() };
        let id = Uuid::new_v4();
        let actor = b.actor.clone();
        store.begin(id, b.clone(), now, store.upload_budget()?).await?;
        store.append(&actor, id, 0, now, bytes.as_slice(), store.upload_budget()?).await?;
        // Leave less than three bytes of temporary quota; the extra spool would exceed it.
        let mut pending = binding(b"reserved", StorageClass::Artifact);
        pending.length = 128 * 1024 * 1024 - 2;
        pending.sha256 = [8; 32];
        let pending_id = Uuid::new_v4();
        store.begin(pending_id, pending, now, store.upload_budget()?).await?;
        let completed = store.finish(&actor, id, now, store.upload_budget()?).await?;
        ensure!(completed.complete);
        let digest = b.sha256.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let query = format!("SELECT document->'value'->'inspections'->'pkg'->>'status' FROM mdm_content.manifests WHERE tenant_id='{}' AND sha256=decode('{digest}','hex') AND class='artifact'",case_tenant());
        ensure!(pg(&query)?.trim().is_empty(), "quota failure must not pretend to have parsed");
        // Prepare a live-file owner at expired lease/retention boundaries. Retry and GC
        // below use the real public Store paths; the blocking guard itself has a T1 proof.
        let row = format!("tenant_id='{}' AND document->'value'->'upload'->>'id'='{id}'", case_tenant());
        let baseline: u64 = pg(&format!("SELECT reserved FROM mdm_content.uploads WHERE {row}"))?.trim().parse()?;
        pg(&format!("UPDATE mdm_content.uploads SET expires=0 WHERE tenant_id='{}' AND document->'value'->'upload'->>'id'='{pending_id}'", case_tenant()))?;
        let small_id = Uuid::new_v4();
        let mut small = binding(b"p", StorageClass::Artifact);
        small.purpose = Purpose::Software { resource: small_id.to_string(), filename: "small.pkg".into() };
        store.begin(small_id, small.clone(), now, store.upload_budget()?).await?;
        store.append(&small.actor, small_id, 0, now, &b"p"[..], store.upload_budget()?).await?;
        let small_row = format!("tenant_id='{}' AND document->'value'->'upload'->>'id'='{small_id}'", case_tenant());
        let epoch = Uuid::new_v4();
        let length = b.length;
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, stopped) = std::sync::mpsc::channel();
        let work = tokio::task::spawn_blocking(move || {
            let file = tempfile::tempfile()?;
            file.set_len(length)?;
            let small_file = tempfile::tempfile()?;
            small_file.set_len(1)?;
            entered.send(()).map_err(|_| std::io::Error::other("file owner abandoned"))?;
            let _ = stopped.recv();
            drop((file, small_file));
            Ok::<_, std::io::Error>(())
        });
        started.await?;
        pg(&format!("UPDATE mdm_content.uploads SET epoch='{epoch}',held_until=0,reserved={length} WHERE {row}"))?;
        pg(&format!("UPDATE mdm_content.uploads SET epoch='{epoch}',held_until=0 WHERE {small_row}"))?;
        let mut contender = (*second).clone();
        // Old+new large copies would fit; a Conflict must come from owner fencing.
        contender.config.max_temporary_bytes = length * 2 + 2;
        ensure!(matches!(contender.parse_upload(&actor, id, now).await, Err(rss_mdm_content_service::Error::Conflict)));
        ensure!(matches!(contender.finish(&small.actor, small_id, now, contender.upload_budget()?).await, Err(rss_mdm_content_service::Error::Conflict)));
        ensure!(pg(&format!("SELECT epoch::text||':'||reserved::text FROM mdm_content.uploads WHERE {row}"))?.trim() == format!("{epoch}:{length}"));
        pg(&format!("UPDATE mdm_content.uploads SET expires=0 WHERE {row} OR {small_row}"))?;
        pg(&format!("UPDATE mdm_content.objects SET expires=0 WHERE tenant_id='{}' AND owner=(SELECT id FROM mdm_content.uploads WHERE {small_row})", case_tenant()))?;
        contender.begin(Uuid::new_v4(), binding(b"x", StorageClass::Artifact), now, contender.upload_budget()?).await?;
        ensure!(pg(&format!("SELECT count(*) FROM mdm_content.uploads WHERE ({row} OR {small_row}) AND epoch='{epoch}'"))?.trim() == "2", "GC must not discard live file reservations after retention expiry");
        ensure!(pg(&format!("SELECT reserved FROM mdm_content.uploads WHERE {row}"))?.trim() == length.to_string());
        release.send(())?;
        work.await??;
        // Confirmation is supplied only after the fixture owner has closed both files.
        pg(&format!("UPDATE mdm_content.uploads SET epoch=NULL,held_until=0,reserved={baseline},expires={} WHERE {row}", completed.expires))?;
        pg(&format!("UPDATE mdm_content.uploads SET epoch=NULL,held_until=0 WHERE {small_row}"))?;
        contender.begin(Uuid::new_v4(), binding(b"x", StorageClass::Artifact), now, contender.upload_budget()?).await?;
        ensure!(pg(&format!("SELECT count(*) FROM mdm_content.uploads WHERE {small_row}"))?.trim() == "0", "confirmed expired owners are reclaimable");
        second.parse_upload(&actor, id, now).await?;
        ensure!(pg(&query)?.trim() == "rejected", "malformed metadata must be recorded");
        let no_parse_budget = store.clone();
        no_parse_budget.parse_upload(&actor, id, now).await?;
        ensure!(second.status(&actor, id, now).await?.complete);
        Ok(())
    }).await
}

async fn migrate_uploaded_fixture(fixture: &mut Fixture) -> Result<()> {
    let config = crate::test_support::identity::config(case_tenant())?;
    let provider: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_S3_FIXTURE")?)?)?;
    crate::test_support::storage::seed_provider(&config, &provider).await?;
    let path = "/api/v1/storage/migrations";
    let operation = Uuid::new_v4();
    fixture.user.operation = Some(operation);
    let input = json!({"expectedStorageRevision":1,"targetRevision":1});
    let first = fixture
        .user
        .call(&fixture.router, Method::POST, path, Some(input.clone()))
        .await?;
    ensure!(
        first.0 == StatusCode::ACCEPTED,
        "migration request: {first:?}"
    );
    ensure!(first.1["phase"] == "requested");
    let replay = fixture
        .user
        .call(&fixture.router, Method::POST, path, Some(input))
        .await?;
    ensure!(replay == first);
    let conflict = fixture
        .user
        .call(
            &fixture.router,
            Method::POST,
            path,
            Some(json!({"expectedStorageRevision":1,"targetRevision":2})),
        )
        .await?;
    ensure!(conflict.0 == StatusCode::CONFLICT);
    fixture.user.operation = None;
    let receipt_path = format!("{path}/operations/{operation}");
    let receipt = fixture
        .user
        .call(&fixture.router, Method::GET, &receipt_path, None)
        .await?;
    ensure!(receipt.0 == StatusCode::OK && receipt.1 == first.1);
    ensure!(
        pg(&format!(
            "SELECT maintenance FROM mdm_content.settings WHERE tenant_id='{}'",
            case_tenant()
        ))?
        .trim()
            == "normal",
        "HTTP registration must not freeze content"
    );
    ensure!(
        maintain_migration(operation).await?.phase
            == rss_mdm_content_service::migration::Phase::Committed
    );
    let before = pg(&format!(
        "SELECT count(*) FROM rss_audit.records WHERE tenant_id='{}' AND source_id='mdm.business'",
        case_tenant()
    ))?;
    let applied = fixture
        .user
        .call(
            &fixture.router,
            Method::GET,
            "/api/v1/storage/connections",
            None,
        )
        .await?;
    ensure!(
        applied.0 == StatusCode::OK
            && applied.1["activeRevision"] == 1
            && applied.1["applied"]["revision"] == 1,
        "actual binding observation: {applied:?}"
    );
    ensure!(applied.1["current"].get("selected").is_none());
    let directory = fixture
        .user
        .call(&fixture.router, Method::GET, path, None)
        .await?;
    ensure!(directory.0 == StatusCode::OK);
    ensure!(
        before
            == pg(&format!(
                "SELECT count(*) FROM rss_audit.records WHERE tenant_id='{}' AND source_id='mdm.business'",
                case_tenant()
            ))?,
        "status queries must not append management audit"
    );
    Ok(())
}

// Exercise the deployment entry point with its restricted audit transaction, not an owner-only CAS.
async fn maintain_migration(
    operation_id: Uuid,
) -> Result<rss_mdm_content_service::migration::Receipt> {
    use std::io::Write;
    let mut runtime: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    runtime["identity"]["tenant_id"] = json!(case_tenant());
    let mut runtime_file = tempfile::NamedTempFile::new()?;
    runtime_file.write_all(&serde_json::to_vec(&runtime)?)?;
    let owner = url::Url::parse(&std::env::var("MDM_OWNER_URL")?)?;
    let mut password_file = tempfile::NamedTempFile::new()?;
    password_file.write_all(
        owner
            .password()
            .context("owner fixture password")?
            .as_bytes(),
    )?;
    crate::setup::content_storage::maintain(crate::setup::content_storage::Input {
        runtime_file: runtime_file.path().to_owned(),
        owner_database: crate::config::Database {
            host: owner.host_str().context("owner fixture host")?.into(),
            port: owner.port().context("owner fixture port")?,
            name: owner.path().trim_start_matches('/').into(),
            user: owner.username().into(),
            password_file: password_file.path().to_owned(),
            ca_file: std::env::var("PG_CA_FILE")?.into(),
        },
        operation_id,
    })
    .await
    .map_err(Into::into)
}

fn read_fences() -> Result<u64> {
    pg(&format!("SELECT count(DISTINCT pid) FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND locktype='advisory' AND mode='ShareLock' AND granted AND objsubid=1 AND classid::bigint=((hashtextextended('{}',30040)>>32)&4294967295) AND objid::bigint=(hashtextextended('{}',30040)&4294967295)",case_tenant(),case_tenant()))?.trim().parse().map_err(Into::into)
}

#[tokio::test]
#[ignore = "MODULE=content.storage: batch pins share one fence; admission sessions remain bounded independently of journal SQL"]
async fn batch_pins_keep_database_connections_bounded() -> Result<()> {
    let (resources, store, _) = stores(None, 60).await?;
    resources
        .finish(async {
            let bytes = b"bounded-pin-material";
            let b = binding(bytes, StorageClass::Artifact);
            let id = Uuid::new_v4();
            let now = crate::windows::test_support::now();
            store
                .begin(id, b.clone(), now, store.upload_budget()?)
                .await?;
            store
                .append(
                    &b.actor,
                    id,
                    0,
                    now,
                    bytes.as_slice(),
                    store.upload_budget()?,
                )
                .await?;
            store
                .finish(&b.actor, id, now, store.upload_budget()?)
                .await?;
            let mut pins = store
                .pin_materials(&vec![(b.artifact()?, StorageClass::Artifact); 128])
                .await?;
            ensure!(
                pins.len() == 128 && read_fences()? == 1,
                "batch must use one physical session"
            );
            pins.truncate(1);
            ensure!(read_fences()? == 1, "last pin retains the batch fence");
            for _ in 0..8 {
                pins.extend(
                    store
                        .pin_materials(&[(b.artifact()?, StorageClass::Artifact)])
                        .await?,
                );
                pins.push(
                    store
                        .pin_ready(&b.artifact()?, StorageClass::Artifact)
                        .await?,
                );
            }
            ensure!(
                read_fences()? == 1,
                "independent resource batches must share the generation fence"
            );
            tokio::time::timeout(
                Duration::from_secs(2),
                store.begin(Uuid::new_v4(), b.clone(), now, store.upload_budget()?),
            )
            .await??;
            ensure!(
                store
                    .verify(&b.artifact()?)
                    .await?
                    .read_plaintext(bytes.len())?
                    .as_slice()
                    == bytes,
                "nested content reads must not self-wait behind retained pins"
            );
            ensure!(read_fences()? == 1);
            ensure!(
                store.status(&b.actor, id, now).await?.complete,
                "journal SQL must remain available while the publication pins are held"
            );
            drop(pins);
            Ok(())
        })
        .await
}

async fn cancelled_unwritten_target_backup(
    store: &rss_mdm_content_service::Store,
    config: &crate::config::Config,
    pool: &sqlx::PgPool,
) -> Result<()> {
    use rss_mdm_content_service::migration;
    use sqlx::Connection;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let protection = config.native_protector()?;
    let mut c = pool.acquire().await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    let operation = Uuid::new_v4();
    let request = migration::request_on(
        &mut tx,
        tenant,
        operation,
        &migration::Request {
            expected_storage_revision: 1,
            target_revision: 1,
        },
        "backup-cancel-fixture",
        &protection,
    )
    .await?;
    tx.commit().await?;
    let relative = pg(&format!(
        "SELECT location->'value'->'coordinate'->>'id' FROM mdm_content.objects WHERE tenant_id='{}' AND generation='{}' AND state='ready' LIMIT 1",
        case_tenant(),
        request.source_generation
    ))?;
    let original = store
        .config
        .storage
        .volume_directory()
        .unwrap()
        .join(case_tenant())
        .join(relative.trim());
    let unavailable = original.with_extension("temporarily-unavailable");
    std::fs::rename(&original, &unavailable)?;
    let owner = rss_mdm_content_service::Store::open(
        protection.clone(),
        &store.config,
        case_tenant(),
        Arc::new(crate::lifecycle::RuntimeTimer),
        pool.clone(),
    )
    .await?;
    let result = migration::prepare(&owner, operation).await;
    std::fs::rename(&unavailable, &original)?;
    let blocked = result?;
    ensure!(blocked.blocked_reason.as_deref() == Some("target_copy_unconfirmed"));
    let pending_sql = format!(
        "SELECT location::text FROM mdm_content.objects WHERE tenant_id='{}' AND generation='{}' AND state='pending'",
        case_tenant(),
        request.target_generation
    );
    let pending = pg(&pending_sql)?;
    ensure!(
        !pending.trim().is_empty(),
        "failure must occur after durable intent"
    );
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT mdm_content.cancel_migration($1)")
        .bind(operation)
        .execute(&mut *tx)
        .await?;
    let records = rss_mdm_content_service::backup::s3_page(
        &mut tx,
        tenant,
        request.target_generation,
        &protection,
        None,
    )
    .await?;
    ensure!(records.len() == 1 && !records[0].required && records[0].object.is_none());
    tx.commit().await?;
    let archive_root = tempfile::tempdir()?;
    let archive = archive_root
        .path()
        .canonicalize()?
        .join("cancelled-snapshot");
    let host = Uuid::new_v4();
    let mut runtime: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    runtime["identity"]["tenant_id"] = json!(case_tenant());
    crate::setup::content_snapshot_fixture(&mut c, &archive, host, &runtime, false).await?;
    crate::setup::content_snapshot_fixture(&mut c, &archive, host, &runtime, true).await?;
    ensure!(
        pg(&pending_sql)? == pending,
        "backup/restore must preserve unresolved target intent"
    );
    Ok(())
}

async fn volume_migration_scenario(populated: bool, initial_s3: bool, peer: bool) -> Result<()> {
    use rss_mdm_content_service::migration;
    use sqlx::Connection;
    use std::str::FromStr;
    let (_private, s3) = s3_storage()?;
    let (resources, store, second) = stores(if initial_s3 { Some(s3) } else { None }, 60).await?;
    resources.finish(async {
        let bytes=b"generation-migration-existing-content";
        let binding=binding(bytes,StorageClass::Artifact);
        let upload=Uuid::new_v4();
        let now=crate::windows::test_support::now();
            if populated {
        store.begin(upload,binding.clone(),now,store.upload_budget()?).await?;
        store.append(&binding.actor,upload,0,now,bytes.as_slice(),store.upload_budget()?).await?;
        store.finish(&binding.actor,upload,now,store.upload_budget()?).await?;
            }
        let before=pg(&format!("SELECT document::text FROM mdm_content.manifests WHERE tenant_id='{}' ORDER BY class,sha256",case_tenant()))?;
        let config=crate::test_support::identity::config(case_tenant())?;
        let provider:Value=serde_json::from_slice(&std::fs::read(std::env::var("MDM_S3_FIXTURE")?)?)?;
        crate::test_support::storage::seed_provider(&config,&provider).await?;
        let provider=if peer {serde_json::from_slice::<Value>(&std::fs::read(std::env::var("MDM_S3_PEER_FIXTURE")?)?)?}else{provider};
        let tenant=rss_request_context::TenantId::parse(case_tenant())?;
        let protection=config.native_protector()?;
        let pool=sqlx::postgres::PgPoolOptions::new().max_connections(4).connect_with(
            sqlx::postgres::PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull).ssl_root_cert(std::env::var("PG_CA_FILE")?)
        ).await?;
        let result=async {
            if populated && !initial_s3 {cancelled_unwritten_target_backup(&store,&config,&pool).await?;}
            let mut access=sqlx::PgConnection::connect_with(&config.access_options()?).await?;
            let mut tx=access.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
            let target_revision=if initial_s3 {
                let connection_operation=Uuid::new_v4();
                let candidate=rss_mdm_content_service::connections::Request{expected_revision:1,profile:"migration-target".into(),source:rss_mdm_content_service::connections::Source::Import{
                    access_key:provider["accessKey"].as_str().unwrap().to_owned().into(),secret_key:provider["secretKey"].as_str().unwrap().to_owned().into(),session_token:None,expires_at:None,
                }};
                rss_mdm_content_service::connections::prepare(&mut tx,tenant,connection_operation,&candidate,"migration-fixture",&protection).await?;
                tx.commit().await?;
                let mut owner=pool.acquire().await?;
                let mut qualification=owner.begin().await?;
                sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *qualification).await?;
                rss_mdm_content_service::connections::qualify(&mut qualification,tenant,connection_operation,&rss_mdm_content_service::connections::Metadata{
                    endpoint:provider["endpoint"].as_str().unwrap().into(),region:provider["region"].as_str().unwrap().into(),bucket:provider["bucket"].as_str().unwrap().into(),namespace:format!("{}/migrated",provider["namespace"].as_str().unwrap()),private_ca:std::fs::read(provider["ca"].as_str().unwrap())?,
                },now).await?;
                qualification.commit().await?;
                tx=access.begin().await?;
                sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
                2
            }else{1};
            let operation=Uuid::new_v4();
            let request=migration::Request{expected_storage_revision:1,target_revision};
            let first=migration::request_on(&mut tx,tenant,operation,&request,"migration-fixture",&protection).await?;
            let replay=migration::request_on(&mut tx,tenant,operation,&request,"migration-fixture",&protection).await?;
            ensure!(first.target_generation==replay.target_generation);
            tx.commit().await?;
            access.close().await?;
            let owner=rss_mdm_content_service::Store::open(protection.clone(),&store.config,case_tenant(),Arc::new(crate::lifecycle::RuntimeTimer),pool.clone()).await?;
            let pinned=if populated{Some(store.pin_ready(&binding.artifact()?,StorageClass::Artifact).await?)}else{None};
            let unpolled=if populated {
                let deadline=rss_request_context::Deadline::from_timeout(&crate::lifecycle::RuntimeTimer,Duration::from_secs(8))?;
                Some(second.verify_class(&binding.artifact()?,StorageClass::Artifact,deadline).await?.stream(0,bytes.len() as u64).await?)
            }else{None};
            if populated && !initial_s3 {
                pg("CREATE SEQUENCE mdm_content.migration_fault; CREATE FUNCTION mdm_content.fail_target_location() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.generation<>(SELECT active_generation FROM mdm_content.settings WHERE tenant_id=NEW.tenant_id) AND nextval('mdm_content.migration_fault')=1 THEN RAISE EXCEPTION 'injected target settlement failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER migration_fault BEFORE UPDATE OF location ON mdm_content.objects FOR EACH ROW EXECUTE FUNCTION mdm_content.fail_target_location()")?;
                let blocked=migration::prepare(&owner,operation).await?;
                ensure!(blocked.phase==migration::Phase::Preparing && blocked.blocked_reason.as_deref()==Some("target_copy_unconfirmed"));
                ensure!(blocked.target_generation==first.target_generation);
                pg("DROP TRIGGER migration_fault ON mdm_content.objects; DROP FUNCTION mdm_content.fail_target_location(); DROP SEQUENCE mdm_content.migration_fault")?;
                let reopened=rss_mdm_content_service::Store::open(protection.clone(),&store.config,case_tenant(),Arc::new(crate::lifecycle::RuntimeTimer),pool.clone()).await?;
                let resumed=migration::prepare(&reopened,operation).await?;
                ensure!(resumed.phase==migration::Phase::Ready && resumed.target_generation==first.target_generation);
            }
            let ready=migration::prepare(&owner,operation).await?;
            ensure!(ready.phase==migration::Phase::Ready);
            ensure!(store.begin(Uuid::new_v4(),binding.clone(),now,store.upload_budget()?).await.is_err());
            let mut c=pool.acquire().await?;
            let mut tx=c.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
            if populated {ensure!(migration::cutover_on(&mut tx,tenant,operation).await.is_err(),"live source reader must block cutover");}
            tx.rollback().await?;
            drop(pinned);
            if populated {
                // Wait only for the independent pin session to close. The body is now the
                // sole read fence; its premature release must fail this proof.
                for _ in 0..100 {
                    if read_fences()?<=1 {break;}
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                ensure!(read_fences()?==1,"unpolled body alone must retain its read fence before expiry");
                let mut tx=c.begin().await?;
                sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
                ensure!(migration::cutover_on(&mut tx,tenant,operation).await.is_err(),"body alone must block cutover");
                tx.rollback().await?;
            }
            let mut committed=false;
            if !populated {
                let audit_count=||pg(&format!("SELECT count(*) FROM rss_audit.records WHERE tenant_id='{}' AND source_id='mdm.business'",case_tenant()))?.trim().parse::<u64>().map_err(anyhow::Error::from);
                let before=audit_count()?;
                ensure!(maintain_migration(operation).await?.phase==migration::Phase::Committed);
                ensure!(audit_count()?==before+1,"cutover must append its transaction audit");
                ensure!(maintain_migration(operation).await?.phase==migration::Phase::Committed);
                ensure!(audit_count()?==before+1,"committed replay must not duplicate audit");
                committed=true;
            }
            for _ in 0..500 {
                if committed {break;}
                let mut tx=c.begin().await?;
                sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
                if migration::cutover_on(&mut tx,tenant,operation).await.is_ok(){tx.commit().await?;committed=true;break;}
                tx.rollback().await?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            ensure!(committed,"unpolled expired body must not keep the read fence");
            drop(unpolled);
            let mut tx=c.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
            let (replayed,replay)=migration::cutover_on(&mut tx,tenant,operation).await?;
            ensure!(replay && replayed.target_generation==first.target_generation);
            let revision:i64=sqlx::query_scalar("SELECT revision FROM mdm_content.settings WHERE tenant_id=$1::uuid").bind(case_tenant()).fetch_one(&mut *tx).await?;
            ensure!(revision==2);
            tx.commit().await?;
            ensure!(second.active_s3_revision().await?==Some(target_revision));
            if populated {ensure!(&*second.verify(&binding.artifact()?).await?.read_plaintext(bytes.len())?==bytes);}
            ensure!(before==pg(&format!("SELECT document::text FROM mdm_content.manifests WHERE tenant_id='{}' ORDER BY class,sha256",case_tenant()))?);
            ensure!(pg(&format!("SELECT count(DISTINCT generation) FROM mdm_content.objects WHERE tenant_id='{}' AND state='ready'",case_tenant()))?.trim()==if populated {"2"}else{"0"});
            let next=Uuid::new_v4();
            second.begin(next,binding.clone(),now,second.upload_budget()?).await?;
            if !populated {
                let cancelled=Uuid::new_v4();
                let mut access=sqlx::PgConnection::connect_with(&config.access_options()?).await?;
                let mut tx=access.begin().await?;
                sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
                migration::request_on(&mut tx,tenant,cancelled,&migration::Request{expected_storage_revision:2,target_revision},"migration-fixture",&protection).await?;
                tx.commit().await?;
                let current=rss_mdm_content_service::Store::open(protection.clone(),&store.config,case_tenant(),Arc::new(crate::lifecycle::RuntimeTimer),pool.clone()).await?;
                ensure!(migration::prepare(&current,cancelled).await?.phase==migration::Phase::Ready);
                let mut tx=access.begin().await?;
                sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
                sqlx::query("SELECT mdm_content.cancel_migration($1)").bind(cancelled).execute(&mut *tx).await?;
                ensure!(migration::receipt(&mut tx,tenant,cancelled).await?.phase==migration::Phase::Cancelled);
                tx.commit().await?;
                access.close().await?;
                second.begin(Uuid::new_v4(),binding.clone(),now,second.upload_budget()?).await?;
            }

            Ok::<_,anyhow::Error>(())
        }.await;
        pool.close().await;
        result
    }).await
}

#[tokio::test]
#[ignore = "MODULE=content.storage: real volume to TLS S3, frozen writes and atomic generation cutover"]
async fn volume_migration_preserves_logical_manifest_and_refreshes_existing_stores() -> Result<()> {
    volume_migration_scenario(true, false, false).await
}
#[tokio::test]
#[ignore = "MODULE=content.storage: empty source still uses generation CAS and maintenance"]
async fn empty_volume_migration_uses_the_same_atomic_switch() -> Result<()> {
    volume_migration_scenario(false, false, false).await
}

#[tokio::test]
#[ignore = "MODULE=content.storage: S3 namespace migration preserves exact content and existing consumers"]
async fn s3_namespace_migration_preserves_logical_content() -> Result<()> {
    volume_migration_scenario(true, true, false).await
}

#[tokio::test]
#[ignore = "MODULE=content.storage: distinct real TLS endpoints and versioned buckets"]
async fn s3_endpoint_bucket_migration_preserves_content() -> Result<()> {
    volume_migration_scenario(true, true, true).await
}

#[tokio::test]
#[ignore = "MODULE=content.storage: backup recovers and restores a write whose location commit failed"]
async fn backup_restores_the_recovered_version_of_a_pending_write() -> Result<()> {
    use sqlx::Connection;
    use std::str::FromStr;
    let (_private, storage) = s3_storage()?;
    let (resources, store, _) = stores(Some(storage.clone()), 60).await?;
    resources.finish(async {
        let bytes=b"pending-object-backup-recovery";
        let binding=binding(bytes,StorageClass::Artifact);
        let id=Uuid::new_v4();let now=crate::windows::test_support::now();
        store.begin(id,binding.clone(),now,store.upload_budget()?).await?;
        pg("CREATE FUNCTION mdm_content.fail_location() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected location settlement failure'; END $$; CREATE TRIGGER fail_location BEFORE UPDATE OF location ON mdm_content.objects FOR EACH ROW EXECUTE FUNCTION mdm_content.fail_location()")?;
        ensure!(store.append(&binding.actor,id,0,now,bytes.as_slice(),store.upload_budget()?).await.is_err());
        pg("DROP TRIGGER fail_location ON mdm_content.objects; DROP FUNCTION mdm_content.fail_location()")?;
        let config=crate::test_support::identity::config(case_tenant())?;
        let protection=config.native_protector()?;
        let tenant=rss_request_context::TenantId::parse(case_tenant())?;
        let mut c=sqlx::PgConnection::connect_with(&sqlx::postgres::PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?.ssl_mode(sqlx::postgres::PgSslMode::VerifyFull).ssl_root_cert(std::env::var("PG_CA_FILE")?)).await?;
        let mut tx=c.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
        let generation:Uuid=sqlx::query_scalar("SELECT active_generation FROM mdm_content.settings WHERE tenant_id=$1::uuid").bind(case_tenant()).fetch_one(&mut *tx).await?;
        let records=rss_mdm_content_service::backup::s3_page(&mut tx,tenant,generation,&protection,None).await?;
        ensure!(records.len()==1 && records[0].object.is_none());
        let loaded=Arc::new(rss_mdm_content_service::connections::load(&mut tx,tenant,1,&protection).await?);
        tx.rollback().await?;
        let budget=||rss_mdm_content_s3::Budget::new(Arc::new(crate::lifecycle::RuntimeTimer),Duration::from_secs(20),Duration::from_secs(5),1024,16);
        let provider=rss_mdm_content_s3::Store::connect(rss_mdm_content_s3::Config{
            endpoint:loaded.metadata.endpoint.clone(),region:loaded.metadata.region.clone(),bucket:loaded.metadata.bucket.clone(),namespace:format!("{}/{}",loaded.metadata.namespace,tenant),credentials_reference:"content-connection".into(),private_ca_pem:Some(loaded.metadata.private_ca.clone()),max_concurrent:2,connect_timeout:Duration::from_secs(5),
        },loaded,Arc::new(crate::lifecycle::RuntimeTimer),budget()?).await?;
        let original=match provider.recover(&records[0].write,budget()?).await?{
            rss_mdm_content_s3::Recovery::Matched(rss_mdm_content_s3::Written::Verified(value))=>value,
            _=>anyhow::bail!("pending provider write was not recovered"),
        };
        let root=tempfile::tempdir()?;let archive=root.path().canonicalize()?.join("snapshot");let host=Uuid::new_v4();
        let mut runtime:Value=serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        runtime["identity"]["tenant_id"]=json!(case_tenant());runtime["content"]["storage"]=storage;
        crate::setup::content_snapshot_fixture(&mut c,&archive,host,&runtime,false).await?;
        ensure!(matches!(provider.delete(original.object(),budget()?).await?,rss_mdm_content_s3::Mutation::Confirmed(())));
        crate::setup::content_snapshot_fixture(&mut c,&archive,host,&runtime,true).await?;
        let mut tx=c.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
        let restored=rss_mdm_content_service::backup::s3_page(&mut tx,tenant,generation,&protection,None).await?;
        ensure!(restored.len()==1 && restored[0].object.is_some());
        let exact=restored[0].object.as_ref().unwrap();ensure!(exact.version()!=original.object().version());
        provider.verify(exact,restored[0].content,budget()?).await?;
        tx.rollback().await?;c.close().await?;
        Ok(())
    }).await
}
