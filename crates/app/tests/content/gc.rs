use crate::test_support::software::Fixture;
use crate::test_support::*;
fn assert_volume_removed(artifact: &rss_mdm_resource::Artifact) -> Result<()> {
    let digest = artifact
        .digest()
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let manifest: Value = serde_json::from_str(pg(&format!("SELECT jsonb_build_object('state',state,'pieces',document->'value'->'pieces') FROM mdm_content.manifests WHERE tenant_id='{}' AND class='artifact' AND sha256=decode('{digest}','hex') AND length={}", case_tenant(), artifact.length()))?.trim())?;
    ensure!(manifest["state"] == "deleted");
    let pieces = manifest["pieces"].as_array().unwrap();
    ensure!(!pieces.is_empty());
    let config: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let root = std::path::Path::new(config["content"]["storage"]["directory"].as_str().unwrap())
        .join(case_tenant());
    for piece in pieces {
        ensure!(piece["coordinate"]["kind"] == "volume");
        ensure!(
            !root
                .join(piece["coordinate"]["id"].as_str().unwrap())
                .try_exists()?
        );
    }
    Ok(())
}
async fn cleanup_preserves_resource_references(
    user: &mut Browser,
    router: &Router,
    store: &Arc<rss_mdm_content_service::Store>,
    _directory: &std::path::Path,
    retained: &rss_mdm_resource::Artifact,
) -> Result<()> {
    let data = case::name("orphaned upload without resource reference").as_bytes();
    let upload = Uuid::new_v4();
    let binding = rss_mdm_content_service::Binding {
        purpose: rss_mdm_content_service::Purpose::Resource(
            rss_mdm_content_service::ResourceBinding {
                storage_class: rss_mdm_content_service::StorageClass::Artifact,
                resource: "orphan".into(),
                version: "1".into(),
                variant: "default".into(),
                platform: rss_mdm_resource::Platform::Windows,
                architecture: rss_mdm_resource::Architecture::X86_64,
                resource_digest: [1; 32],
                source: None,
                origin: None,
            },
        ),
        reference: "orphan".into(),
        length: data.len() as u64,
        sha256: rss_mdm_resource::Digest::of(data).bytes(),
        actor: "fixture".into(),
    };
    let artifact = binding.artifact()?;
    store.begin(upload, binding, 1).await?;
    store.append("fixture", upload, 0, 1, data).await?;
    store.finish("fixture", upload, 1).await?;
    super::expire_upload(upload)?;
    pg(&format!(
        "UPDATE mdm_content.manifests SET expires=0 WHERE tenant_id='{}' AND sha256=decode('{}','hex')",
        case_tenant(),
        retained
            .digest()
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))?;
    let cleanup = user
        .call(
            router,
            Method::POST,
            "/api/v1/software/content/cleanup",
            None,
        )
        .await?;
    ensure!(
        cleanup.0 == StatusCode::OK,
        "cleanup retained references: {cleanup:?}"
    );
    assert_volume_removed(&artifact)?;
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
                purpose: rss_mdm_content_service::Purpose::Resource(
                    rss_mdm_content_service::ResourceBinding {
                        storage_class: rss_mdm_content_service::StorageClass::Artifact,
                        resource: resource.as_str().into(),
                        version: "v1".into(),
                        variant: "default".into(),
                        platform: r::Platform::Windows,
                        architecture: r::Architecture::X86_64,
                        resource_digest: [1; 32],
                        source: None,
                        origin: None,
                    },
                ),
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
    super::expire_upload(id)?;
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
    let deletion = candidate.clone();
    let gc = tokio::spawn(async move {
        gc_runtime
            .local_tx_with_context(
                tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    std::time::Duration::from_secs(6),
                ),
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
                                candidate.as_ref().unwrap(),
                                || Ok(())
                            )
                            .await
                            .map_err(|_| {
                                rss_transactional_messaging_postgres::PgError::from(
                                    sqlx::Error::Protocol("fixture content reclaim".into()),
                                )
                            })?
                        );
                        Ok(())
                    })
                },
            )
            .await
            .fold(Ok, Err, Err, Err, Err, Err)
    });
    tokio::time::timeout(Duration::from_secs(5), checked.notified()).await?;
    let digest = artifact
        .digest()
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let lock_key = format!("mdm_resource:{tenant}:artifact:{digest}");
    let writer = tokio::spawn(async move {
        resources
            .execute(&insert, rss_mdm_flow_service::transaction::deadline())
            .await
    });
    let waiting = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if writer.is_finished() { break Ok::<_, anyhow::Error>(false); }
            if pg(&format!("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND classid::bigint=((hashtextextended('{lock_key}',2388)>>32)&4294967295) AND objid::bigint=(hashtextextended('{lock_key}',2388)&4294967295))"))?.trim() == "t" { break Ok(true); }
            tokio::task::yield_now().await;
        }
    }).await;
    // Release GC even if the writer never reaches the expected lock.
    if !matches!(waiting, Ok(Ok(true))) {
        resume.notify_one();
    }
    ensure!(waiting??, "writer did not wait for the artifact lock");
    ensure!(
        !writer.is_finished(),
        "Resource crossed the held deletion barrier"
    );
    resume.notify_one();
    gc.await??;
    let rejected = writer.await?;
    ensure!(
        matches!(rejected, Err(rp::Error::RolledBack(ref error)) if error.kind() == rss_transactional_messaging::error::MessagingErrorKind::Transient),
        "writer did not observe deletion barrier: {rejected:?}"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_resource.artifact_refs WHERE tenant_id='{tenant}' AND owner='{}'", resource.as_str()))?.trim() == "0");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_resource.immutable WHERE tenant_id='{tenant}' AND owner='{}' AND kind='version'", resource.as_str()))?.trim() == "0");
    deletion.remove().await?;
    assert_volume_removed(&artifact)?;
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=content.gc: reference locking and real file reclamation"]
async fn reference_and_gc_are_serialized() -> Result<()> {
    let mut fixture = Fixture::open(false).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources
        .finish(async {
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
        })
        .await
}
#[tokio::test]
#[ignore = "MODULE=content.gc: executable inherited privilege is rejected"]
async fn switchable_delete_privilege_fails_admission() -> Result<()> {
    let config: crate::config::Config =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let storage = &config.flow.storage;
    let runtime = crate::identity::open_runtime(
        &storage.database,
        &storage.target,
        &storage.lineage,
        &[(tenant, storage.epoch)],
    )
    .await?;
    let result = async {
    pg(
        "CREATE ROLE mdm_content_drift; GRANT USAGE ON SCHEMA mdm_content TO mdm_content_drift; GRANT DELETE ON mdm_content.bindings TO mdm_content_drift; GRANT mdm_content_drift TO mdm_flow_runtime WITH INHERIT FALSE, SET TRUE",
    )?;
    let rejected = crate::flow::admit_storage(&runtime, tenant).await;
    pg(
        "REVOKE mdm_content_drift FROM mdm_flow_runtime; DROP OWNED BY mdm_content_drift; DROP ROLE mdm_content_drift",
    )?;
    ensure!(matches!(rejected, Err(crate::Error::Unavailable(crate::Failure::FlowAdmission))));
    crate::flow::admit_storage(&runtime, tenant).await?;
    Ok(())
    }.await;
    runtime.close().await;
    result
}

#[tokio::test]
#[ignore = "MODULE=content.gc: catalog evidence releases transfer capacity and retains deletion pins"]
async fn catalog_evidence_retains_pin_without_reserving_transfer() -> Result<()> {
    use rss_mdm_resource as r;
    use rss_mdm_software_service::catalog::ContentPort;
    let fixture = Fixture::with_peer_and_uploads(None, Some(1)).await?;
    let bytes = &[0x4e; 128 * 1024 + 3];
    let artifact = fixture.seed_content(bytes).await?;
    let store = fixture.content.as_ref().unwrap();
    let version = r::Version::new(
        rss_request_context::TenantId::parse(case_tenant())?,
        r::Id::new(Uuid::new_v4().to_string())?,
        r::Id::new("v1")?,
        r::Kind::Software,
        vec![r::Variant::new(
            r::Platform::Windows,
            r::Architecture::X86_64,
            r::Id::new("default")?,
            r::Declaration::Software {
                definition: serde_json::from_value(publication_support::private_definition(
                    fixture.registered["snapshot"].clone(),
                    bytes,
                ))?,
            },
        )],
    )?;
    let evidence = ContentPort::verify(store.as_ref(), &version).await?;
    ensure!(evidence.resource_digest() == version.digest().bytes());
    // A held catalog receipt must not self-compete with a subsequent download.
    use futures::StreamExt;
    let mut bounded = store.as_ref().clone();
    bounded.config.transfer_seconds = 1;
    let bounded = Arc::new(bounded);
    let download = bounded.verify(&artifact).await?;
    let mut body = download.stream(0, artifact.length()).await?;
    ensure!(body.next().await.transpose()?.is_some());
    ensure!(matches!(
        bounded.verify(&artifact).await,
        Err(rss_mdm_content_service::Error::Conflict)
    ));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let next = bounded.verify(&artifact).await?;
    ensure!(next.matches(&artifact));
    ensure!(
        body.next().await.transpose().is_err(),
        "expired stream resumed reading"
    );
    drop(body);
    drop(next);
    use crate::clock::Clock;
    let now = crate::clock::SystemClock.unix_seconds()?;
    let digest = artifact.digest().bytes();
    let hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    pg(&format!(
        "UPDATE mdm_content.manifests SET expires=0 WHERE tenant_id='{}' AND sha256=decode('{hex}','hex')",
        case_tenant()
    ))?;
    ensure!(
        store.garbage(now).await?.iter().all(|g| g.digest != digest),
        "catalog evidence lost its deletion pin"
    );
    drop(evidence);
    // Verified drop releases the PG pin asynchronously, without extending its deadline.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if store.garbage(now).await?.iter().any(|g| g.digest == digest) {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    Ok(())
}
