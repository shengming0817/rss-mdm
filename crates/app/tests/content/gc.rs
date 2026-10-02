use crate::test_support::software::Fixture;
use crate::test_support::*;
async fn cleanup_preserves_resource_references(
    user: &mut Browser,
    router: &Router,
    store: &Arc<rss_mdm_content_service::Store>,
    directory: &std::path::Path,
    retained: &rss_mdm_resource::Artifact,
) -> Result<()> {
    let data = case::name("orphaned upload without resource reference").as_bytes();
    let upload = Uuid::new_v4();
    let binding = rss_mdm_content_service::Binding {
        storage_class: rss_mdm_content_service::StorageClass::Artifact,
        resource: "orphan".into(),
        version: "1".into(),
        variant: "default".into(),
        platform: rss_mdm_resource::Platform::Windows,
        architecture: rss_mdm_resource::Architecture::X86_64,
        resource_digest: [1; 32],
        source: None,
        origin: None,
        reference: "orphan".into(),
        length: data.len() as u64,
        sha256: rss_mdm_resource::Digest::of(data).bytes(),
        actor: "fixture".into(),
    };
    let artifact = binding.artifact()?;
    store.begin(upload, binding, 1).await?;
    store.append("fixture", upload, 0, 1, data).await?;
    store.finish("fixture", upload, 1).await?;
    let tenant_dir = directory.join(case_tenant());
    let metadata_path = super::upload_metadata(&tenant_dir, upload)?;
    let mut metadata: Value = serde_json::from_slice(&std::fs::read(&metadata_path)?)?;
    metadata["upload"]["expires"] = json!(0);
    std::fs::write(metadata_path, serde_json::to_vec(&metadata)?)?;
    for owned in [&artifact, retained] {
        let digest = owned
            .digest()
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        std::fs::File::options()
            .write(true)
            .open(tenant_dir.join(digest))?
            .set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))?;
    }
    let cleanup = user
        .call(
            router,
            Method::POST,
            "/api/v3/software/content/cleanup",
            None,
        )
        .await?;
    ensure!(
        cleanup.0 == StatusCode::OK,
        "cleanup retained references: {cleanup:?}"
    );
    ensure!(
        store.verify(&artifact).await.is_err(),
        "unreferenced object survived cleanup"
    );
    store.verify(retained).await?;
    Ok(())
}
async fn gc_reference_race(
    runtime: &Arc<rss_transactional_messaging_postgres::PgRuntime>,
    content: &Arc<rss_mdm_content_service::Store>,
) -> Result<()> {
    use rss_mdm_resource as r;
    use rss_mdm_resource_postgres as rp;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let resources = Arc::new(
        rp::ResourceStore::new(
            runtime.clone(),
            tenant,
            rss_mdm_flow_service::transaction::deadline(),
        )
        .await?,
    );
    let resource = r::Id::new(Uuid::new_v4().to_string())?;
    let data = case::name("gc-concurrent-reference").as_bytes();
    let artifact = r::Artifact::new(
        r::Id::new("gc-bytes")?,
        data.len() as u64,
        r::Digest::of(data),
    )?;
    let request = |revision, command| rp::Request {
        id: r::Id::new(Uuid::new_v4().to_string()).unwrap(),
        resource: resource.clone(),
        expected_storage_revision: revision,
        as_of: rss_contract::Timepoint::try_from(1i64).unwrap(),
        command,
    };
    resources
        .execute(
            &request(0, rp::Command::Create(r::Kind::Configuration)),
            rss_mdm_flow_service::transaction::deadline(),
        )
        .await?;
    let version = r::Version::new(
        tenant,
        resource.clone(),
        r::Id::new("v1")?,
        r::Kind::Configuration,
        vec![r::Variant::new(
            r::Platform::Windows,
            r::Architecture::X86_64,
            r::Id::new("default")?,
            r::Declaration::Configuration {
                artifact: artifact.clone(),
            },
        )],
    )?;
    let insert = request(1, rp::Command::Insert(version));
    let id = Uuid::new_v4();
    content
        .begin(
            id,
            rss_mdm_content_service::Binding {
                storage_class: rss_mdm_content_service::StorageClass::Artifact,
                resource: resource.as_str().into(),
                version: "v1".into(),
                variant: "default".into(),
                platform: r::Platform::Windows,
                architecture: r::Architecture::X86_64,
                resource_digest: [1; 32],
                source: None,
                origin: None,
                reference: artifact.reference().as_str().into(),
                length: artifact.length(),
                sha256: artifact.digest().bytes(),
                actor: "fixture".into(),
            },
            1,
        )
        .await?;
    content.append("fixture", id, 0, 1, data).await?;
    content.finish("fixture", id, 1).await?;
    let candidate = content
        .garbage(i64::MAX / 2)
        .await?
        .into_iter()
        .find(|c| c.digest == artifact.digest().bytes())
        .expect("aged candidate");
    let checked = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let gc_runtime = runtime.clone();
    let ready = checked.clone();
    let release = resume.clone();
    let gc = tokio::spawn(async move {
        rss_mdm_flow_service::transaction::inspect(
            &gc_runtime,
            tenant,
            (Some(candidate), ready, release),
            |ctx, tx| {
                Box::pin(async move {
                    let (candidate, ready, release) = ctx;
                    let digest = r::Digest::from_bytes(candidate.as_ref().unwrap().digest);
                    let referenced = rp::artifact_referenced_in(tx, digest).await?;
                    assert!(!referenced);
                    ready.notify_one();
                    release.notified().await;
                    assert!(
                        rss_mdm_content_service::service::reclaim_in(
                            tx,
                            candidate.take().unwrap(),
                            || Ok(())
                        )
                        .await
                        .map_err(rss_mdm_flow_service::Error::from)?
                    );
                    Ok(())
                })
            },
            rss_mdm_flow_service::transaction::TransactionOwner::ResourceCatalog,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), checked.notified()).await?;
    let mut writer = tokio::spawn(async move {
        resources
            .execute(&insert, rss_mdm_flow_service::transaction::deadline())
            .await
    });
    let early = tokio::time::timeout(Duration::from_millis(750), &mut writer).await;
    let raced = early.is_ok();
    resume.notify_one();
    gc.await??;
    match early {
        Ok(result) => {
            result??;
        }
        Err(_) => {
            writer.await??;
        }
    }
    ensure!(
        !raced,
        "Resource reference committed between GC inspection and file deletion"
    );
    ensure!(content.verify(&artifact).await.is_err());
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=content.gc: reference locking and real file reclamation"]
async fn reference_and_gc_are_serialized() -> Result<()> {
    let fixture = Fixture::open(false).await?;
    let retained = fixture
        .seed_content(case::name("retained resource").as_bytes())
        .await?;
    let store = fixture.content.as_ref().unwrap();
    gc_reference_race(&fixture.runtime, store).await?;
    cleanup_preserves_resource_references(
        &mut fixture.user.clone(),
        &fixture.router,
        store,
        fixture.directory.as_path(),
        &retained,
    )
    .await?;
    ensure!(
        store.verify(&retained).await.is_ok(),
        "referenced artifact was reclaimed"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=content.gc: executable inherited privilege is rejected"]
async fn inherited_delete_privilege_fails_admission() -> Result<()> {
    let fixture = Fixture::open(false).await?;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    pg(
        "CREATE ROLE mdm_content_drift; GRANT USAGE ON SCHEMA mdm_content TO mdm_content_drift; GRANT DELETE ON mdm_content.bindings TO mdm_content_drift; GRANT mdm_content_drift TO mdm_flow_runtime WITH INHERIT FALSE, SET TRUE",
    )?;
    let rejected = crate::flow::admit_storage(&fixture.runtime, tenant).await;
    pg(
        "REVOKE mdm_content_drift FROM mdm_flow_runtime; DROP OWNED BY mdm_content_drift; DROP ROLE mdm_content_drift",
    )?;
    ensure!(rejected.is_err());
    crate::flow::admit_storage(&fixture.runtime, tenant).await?;
    Ok(())
}
