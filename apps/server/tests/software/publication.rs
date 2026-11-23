//! A held content read keeps one source in flight while an independent Git publication commits.
use super::*;
use rss_mdm_content_service as content;
use rss_mdm_resource as r;
use rss_mdm_software_service::{catalog, publication as p};
use rss_transactional_messaging::fence::ExecutionBinding;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

struct Gate {
    store: Arc<content::Store>,
    active: std::sync::atomic::AtomicBool,
    entered: CancellationToken,
    release: CancellationToken,
}
impl catalog::ContentPort for Gate {
    fn verify<'a>(
        &'a self,
        execution: ExecutionBinding,
        version: &'a r::Version,
    ) -> catalog::ContentFuture<'a> {
        Box::pin(async move {
            if self.active.load(std::sync::atomic::Ordering::Acquire) {
                if version.resource().as_str() == "held-winget" {
                    self.entered.cancel();
                    self.release.cancelled().await;
                } else {
                    self.entered.cancelled().await;
                }
            }
            catalog::ContentPort::verify(self.store.as_ref(), execution, version).await
        })
    }
}
fn cutoff() -> rss_request_context::Deadline {
    rss_request_context::Deadline::from_timeout(
        &crate::lifecycle::RuntimeTimer,
        Duration::from_secs(10),
    )
    .unwrap()
}
async fn upload(
    c: &Context,
    store: &content::Store,
    resource: &r::Version,
    bytes: &'static [u8],
    name: &str,
) -> Result<()> {
    let variant = &resource.variants()[0];
    let binding = content::Binding {
        purpose: content::Purpose::Resource(content::ResourceBinding {
            inspection: None,
            storage_class: content::StorageClass::Artifact,
            resource: resource.resource().as_str().into(),
            version: "1".into(),
            variant: variant.key().as_str().into(),
            platform: variant.platform(),
            architecture: variant.architecture(),
            resource_digest: resource.digest().bytes(),
            source: None,
            origin: None,
        }),
        reference: name.into(),
        length: bytes.len() as u64,
        sha256: r::Digest::of(bytes).bytes(),
        actor: "worker-proof".into(),
    };
    let id = Uuid::new_v4();
    Box::pin(store.begin(c.execution(), id, binding, now(), store.upload_budget()?)).await?;
    Box::pin(store.append(
        c.execution(),
        "worker-proof",
        id,
        0,
        now(),
        bytes,
        store.upload_budget()?,
    ))
    .await?;
    anyhow::ensure!(
        Box::pin(store.finish(
            c.execution(),
            "worker-proof",
            id,
            now(),
            store.upload_budget()?
        ))
        .await?
        .complete
    );
    Ok(())
}

#[tokio::test]
#[ignore = "T2: independent source commits real Brew Git and PostgreSQL receipts while same-tenant WinGet recovery is held"]
async fn independent_source_commits_before_slow_content_returns() -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    use rss_mdm_software_release as rel;
    use rss_mdm_software_service::management::publication::service::PublicationDirectory;
    use std::os::unix::fs::PermissionsExt;
    let c = Context::open("shared", &[]).await?;
    let workspace = tempfile::tempdir()?;
    let root = workspace.path();
    let mut config = crate::host_t2_support::configuration(
        &c.inputs,
        "shared",
        "127.0.0.1:10000".parse()?,
        Uuid::new_v4(),
    )
    .await?;
    let volume = root.join("content");
    std::fs::create_dir(&volume)?;
    config["content"] = json!({"storage":{"kind":"volume","directory":volume},"imports":{},"max_artifact_bytes":33554432,"max_temporary_bytes":67108864,"max_uploads":4,"transfer_seconds":60,"retention_seconds":3600,"max_bundle_entries":4096,"max_expansion_ratio":100});
    let config = serde_json::from_value(config)?;
    let store = crate::assembly::content::open(&config, material::protection(&c)?)
        .await?
        .unwrap();
    let gate = Arc::new(Gate {
        store: store.clone(),
        active: false.into(),
        entered: CancellationToken::new(),
        release: CancellationToken::new(),
    });
    let repo = root.join("source.git");
    anyhow::ensure!(
        tokio::process::Command::new("/usr/bin/git")
            .args(["init", "--bare", "--quiet"])
            .arg(&repo)
            .status()
            .await?
            .success()
    );
    let token = root.join("credential");
    std::fs::write(&token, Uuid::new_v4().simple().to_string())?;
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
    let fast = format!("brew-{}", c.tenant);
    let slow = format!("winget-{}", c.tenant);
    let brew = software_with_export(
        &c,
        "independent-brew",
        r::SoftwareExport::Brew {
            name: "Application".into(),
            description: "Controlled application".into(),
            homepage: "https://example.test/".into(),
            payload: r::BrewExport::Cask {
                path: "App.app".into(),
                receipts: vec![],
            },
        },
    )
    .await?;
    let winget = software_with_export(
        &c,
        "held-winget",
        r::SoftwareExport::Winget {
            locale: "en-US".into(),
            name: "Application".into(),
            publisher: "Acme".into(),
            description: "Controlled application".into(),
            license: "MIT".into(),
        },
    )
    .await?;
    upload(&c, &store, &brew, b"dmg", "app-dmg").await?;
    upload(&c, &store, &winget, b"msi", "app-msi").await?;
    let owner = planning::owner(&c, "mdm_software_driver").await?;
    let proof = c
        .authenticate(
            &c.account(&[
                Permission::ReleasePublish,
                Permission::SoftwareWrite,
                Permission::ReleaseWithdraw,
            ])
            .await?,
        )
        .await?;
    let access = p::ManagementAccess {
        proof: &proof,
        permission: Permission::ReleasePublish,
    };
    let mut services = std::collections::BTreeMap::new();
    let mut records = Vec::new();
    for (source, version) in [(&slow, &winget), (&fast, &brew)] {
        let base = format!("https://example.test/{{tenant}}/{source}/");
        let artifacts_base = format!("{base}artifacts/");
        let mut credentials = std::collections::BTreeMap::new();
        let target = if source == &fast {
            credentials.insert(
                Uuid::parse_str(&c.tenant.to_string())?,
                [("read".into(), token.clone())].into(),
            );
            p::SourceConfig::Brew(p::BrewConfig {
                base,
                artifacts_base,
                credential_reference: "read".into(),
                tap: "enterprise/software".into(),
                repository: repo.clone(),
            })
        } else {
            p::SourceConfig::Winget(p::WingetConfig {
                base,
                artifacts_base,
            })
        };
        let service = Arc::new(
            p::PublicationService::connect(
                rss_mdm_software_service::Host {
                    content: gate.clone(),
                    runtime: owner.runtime.clone(),
                    audit: owner.audit.clone(),
                    credentials: Arc::new(crate::source_credentials::SourceCredentials::load(
                        source,
                        &credentials,
                    )?),
                },
                c.execution(),
                source.clone(),
                target,
                "mdm-software-backend".into(),
                cutoff(),
            )
            .await?,
        );
        let operation = service.operation(c.execution())?;
        let record = rel::PublicationKey::new(c.tenant, Uuid::new_v4().to_string())?;
        let input = p::PublishInput {
            actor: rel::ActorId::new(c.tenant, proof.principal_id())?,
            record: record.clone(),
            request: rel::RequestId::new(c.tenant, Uuid::new_v4().to_string())?,
            resource: version.resource().clone(),
            version: version.label().clone(),
            expected_resource_revision: 2,
            resource_digest: version.digest().bytes(),
            target_digest: operation.target().digest,
            as_of: rss_contract::Timepoint::try_from(now())?,
        };
        Box::pin(operation.submit(&input, &access, cutoff())).await?;
        let attempt = operation
            .record(&record, cutoff())
            .await?
            .unwrap()
            .snapshot()
            .attempt
            .clone();
        records.push((record, attempt));
        services.insert(source.clone(), service);
    }
    let directory = Arc::new(PublicationDirectory {
        storage: c.execution().storage(),
        discovery_pool: c.database.archive_pool(),
        cursor: rss_mdm_query::cursor::CursorCodec::new(&[1; 32])?,
        services,
        runtime: owner.runtime.clone(),
        audit_store: owner.audit.clone(),
        clock: Arc::new(crate::clock::ContentClock(Arc::new(
            crate::clock::SystemClock,
        ))),
    });
    gate.active
        .store(true, std::sync::atomic::Ordering::Release);
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(16))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    launch.stage_deferred_task_with_token(
        directory
            .clone()
            .registration(
                rss_mdm_work_page::external::Limits::new(8.try_into()?, 7.try_into()?).unwrap(),
            )
            .critical(),
    );
    launch.finish();
    let fast_op = directory.services[&fast].operation(c.execution())?;
    let slow_op = directory.services[&slow].operation(c.execution())?;
    let probe=tokio::time::timeout(Duration::from_secs(5),async {
        gate.entered.cancelled().await;
        let id=records[1].1.id().digest().bytes();
        loop {
            let applied:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_software_composition.projections WHERE tenant_id=$1::uuid AND publication=$2)").bind(c.tenant.to_string()).bind(id.as_slice()).fetch_one(&c.operator).await?;
            if applied {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        anyhow::ensure!(matches!(fast_op.record(&records[1].0,cutoff()).await?.unwrap().snapshot().attempt.outcome,rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))));
        anyhow::ensure!(!matches!(slow_op.record(&records[0].0,cutoff()).await?.unwrap().snapshot().attempt.outcome,rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))));
        let git=tokio::process::Command::new("/usr/bin/git").arg("--git-dir").arg(&repo).args(["rev-parse","--verify",&format!("refs/heads/tenants/{}",c.tenant)]).output().await?;
        anyhow::ensure!(git.status.success());
        Ok::<_,anyhow::Error>(())
    }).await;
    gate.release.cancel();
    anyhow::ensure!(stack.shutdown().join().await?.is_clean());
    probe??;
    let snapshot = fast_op.record(&records[1].0, cutoff()).await?.unwrap();
    let request = p::ServiceRequest {
        actor: rel::ActorId::new(c.tenant, proof.principal_id())?,
        id: rel::RequestId::new(c.tenant, Uuid::new_v4().to_string())?,
        expected_revision: snapshot.snapshot().revision,
        as_of: rss_contract::Timepoint::try_from(now())?,
    };
    let access = p::ManagementAccess {
        proof: &proof,
        permission: Permission::ReleaseWithdraw,
    };
    let withdrawn = Box::pin(fast_op.withdraw(&records[1].0, &request, &access, cutoff())).await?;
    anyhow::ensure!(withdrawn.outcome == p::Withdrawal::Complete);
    anyhow::ensure!(
        fast_op
            .reconcile_withdrawal(records[1].1.id(), records[1].1.attempt, cutoff())
            .await?
            == p::Withdrawal::Complete
    );
    store.close().await;
    owner.runtime.close().await;
    c.close().await;
    Ok(())
}
