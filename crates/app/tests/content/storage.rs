//! Real PostgreSQL plus the shared TLS S3 provider; product admission and HTTP are exercised.
use crate::test_support::software::Fixture;
use crate::test_support::*;
use rss_mdm_content_service::{Binding, Purpose, ResourceBinding, StorageClass};
fn binding(bytes: &[u8], class: StorageClass) -> Binding {
    Binding {
        purpose: Purpose::Resource(ResourceBinding {
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
    let actual = json!({"kind":"s3","endpoint":provider["endpoint"],"region":provider["region"],"bucket":provider["bucket"],"namespace":provider["namespace"],"credentials_reference":"content-test","access_key_file":private.path().join("access"),"secret_key_file":private.path().join("secret"),"private_ca_file":provider["ca"],"max_concurrent":4,"connect_seconds":5});
    for (key, value) in actual.as_object().unwrap() {
        storage[key] = value.clone();
    }
    Ok((private, storage))
}
#[tokio::test]
#[ignore = "MODULE=content.storage: real S3 product HTTP range, authorization and settlement"]
async fn s3_product_http_contract() -> Result<()> {
    let (_secrets, storage) = s3_storage()?;
    super::http::upload_contract(Fixture::with_storage(storage).await?).await
}
#[tokio::test]
#[ignore = "MODULE=content.storage: durable PG control, real S3 fixed chunks and native snapshots"]
async fn s3_chunk_frontier_and_native_restart() -> Result<()> {
    let (_secrets, storage) = s3_storage()?;
    let fixture = Fixture::with_storage(storage.clone()).await?;
    let store = fixture.content.as_ref().unwrap();
    let now = crate::windows::test_support::now();
    let bytes = vec![0x67; 128 * 1024 * 1024 + 3];
    let b = binding(&bytes, StorageClass::Artifact);
    let id = Uuid::new_v4();
    let actor = &b.actor;
    let artifact = b.artifact()?;
    store.begin(id, b.clone(), now).await?;
    ensure!(store.append(actor, id, 0, now, &bytes[..3]).await?.offset == 3);
    ensure!(
        store
            .append(actor, id, 3, now, &bytes[3..65539])
            .await?
            .offset
            == 65539
    );
    let config: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let mut config = config;
    config["content"]["storage"] = storage;
    config["content"]["max_artifact_bytes"] = json!(160 * 1024 * 1024);
    config["content"]["max_temporary_bytes"] = json!(512 * 1024 * 1024);
    let config: crate::config::Config = serde_json::from_value(config)?;
    let second = crate::execution_assembly::open_content(&config, config.native_protector()?)
        .await?
        .unwrap();
    ensure!(second.status(actor, id, now).await?.offset == 65539);
    second
        .append(actor, id, 65539, now, &bytes[65539..])
        .await?;
    second.finish(actor, id, now).await?;
    let digest = b
        .sha256
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    ensure!(pg(&format!("SELECT jsonb_array_length(document->'value'->'pieces') FROM mdm_content.manifests WHERE tenant_id='{}' AND class='artifact' AND encode(sha256,'hex')='{}'",case_tenant(),digest))?.trim()=="2");
    let mut stream = store
        .verify(&artifact)
        .await?
        .stream(128 * 1024 * 1024 - 2, artifact.length())
        .await?;
    use futures::StreamExt;
    let mut tail = Vec::new();
    while let Some(part) = stream.next().await {
        tail.extend_from_slice(&part?);
    }
    ensure!(tail == vec![0x67; 5]);
    let native = vec![0x42; 65539];
    let b = binding(&native, StorageClass::NativeConfiguration);
    let id = Uuid::new_v4();
    let a = b.artifact()?;
    store.begin(id, b.clone(), now).await?;
    store.append(&b.actor, id, 0, now, &native[..65537]).await?;
    ensure!(second.status(&b.actor, id, now).await?.offset == 65537);
    second
        .append(&b.actor, id, 65537, now, &native[65537..])
        .await?;
    second.finish(&b.actor, id, now).await?;
    ensure!(
        &*store
            .verify_class(&a, StorageClass::NativeConfiguration)
            .await?
            .read_plaintext(native.len())?
            == &native
    );
    ensure!(
        store
            .verify_class(&a, StorageClass::NativeDiagnostic)
            .await
            .is_err()
    );
    second.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=content.storage: real PG multi-instance epoch and failed-body frontier"]
async fn volume_fences_a_stale_writer_and_keeps_failed_body_frontier() -> Result<()> {
    let fixture = Fixture::open(false).await?;
    let store = fixture.content.as_ref().unwrap();
    let bytes = b"epoch-frontier-bytes";
    let b = binding(bytes, StorageClass::Artifact);
    let id = Uuid::new_v4();
    let now = crate::windows::test_support::now();
    store.begin(id, b.clone(), now).await?;
    let (mut producer, body) = tokio::io::duplex(128);
    use tokio::io::AsyncWriteExt;
    producer.write_all(&bytes[..3]).await?;
    let stale = store.clone();
    let actor = b.actor.clone();
    let writer = tokio::spawn(async move { stale.append(&actor, id, 0, now, body).await });
    // Wait on the durable claim rather than relying on a scheduler delay.
    tokio::time::timeout(Duration::from_secs(5),async{loop{
  if pg(&format!("SELECT count(*) FROM mdm_content.uploads WHERE tenant_id='{}' AND document->'value'->'upload'->>'id'='{}' AND epoch IS NOT NULL",case_tenant(),id))?.trim()=="1"{break Ok::<_,anyhow::Error>(())}tokio::task::yield_now().await;
 }}).await??;
    pg(&format!(
        "UPDATE mdm_content.uploads SET held_until=0 WHERE tenant_id='{}' AND document->'value'->'upload'->>'id'='{}'",
        case_tenant(),
        id
    ))?;
    let cfg: crate::config::Config =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let second = crate::execution_assembly::open_content(&cfg, cfg.native_protector()?)
        .await?
        .unwrap();
    second
        .append(&b.actor, id, 0, now, bytes.as_slice())
        .await?;
    drop(producer);
    ensure!(writer.await?.is_err());
    ensure!(store.status(&b.actor, id, now).await?.offset == bytes.len() as u64);
    store.finish(&b.actor, id, now).await?;
    ensure!(
        &*store
            .verify(&b.artifact()?)
            .await?
            .read_plaintext(bytes.len())?
            == bytes
    );
    let bad = Uuid::new_v4();
    store.begin(bad, b.clone(), now).await?;
    let body = futures::stream::iter([
        Ok(axum::body::Bytes::from_static(b"epo")),
        Err(std::io::Error::other("interrupted fixture body")),
    ]);
    let reader = tokio_util::io::StreamReader::new(body);
    ensure!(store.append(&b.actor, bad, 0, now, reader).await.is_err());
    ensure!(store.status(&b.actor, bad, now).await?.offset == 0);
    second.close().await;
    Ok(())
}
