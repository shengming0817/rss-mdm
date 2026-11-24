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
    slow_active: std::sync::atomic::AtomicUsize,
    slow_peak: std::sync::atomic::AtomicUsize,
    active: std::sync::atomic::AtomicBool,
    arrivals: tokio::sync::mpsc::UnboundedSender<(String, tokio::sync::oneshot::Sender<()>)>,
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
                let (release, wait) = tokio::sync::oneshot::channel();
                let _ = self
                    .arrivals
                    .send((version.resource().as_str().to_owned(), release));
                tokio::select! { _ = wait => {}, () = self.release.cancelled() => {} }
            }
            let slow = version.resource().as_str().starts_with("held-winget-");
            if slow {
                let active = self
                    .slow_active
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    + 1;
                self.slow_peak
                    .fetch_max(active, std::sync::atomic::Ordering::SeqCst);
            }
            let result =
                catalog::ContentPort::verify(self.store.as_ref(), execution, version).await;
            if slow {
                self.slow_active
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
            result
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
    let (arrivals, mut observed) = tokio::sync::mpsc::unbounded_channel();
    let gate = Arc::new(Gate {
        store: store.clone(),
        active: false.into(),
        arrivals,
        slow_active: 0.into(),
        slow_peak: 0.into(),
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
    let mut slow_versions = Vec::new();
    for n in 0..9 {
        let version = software_package(
            &c,
            &format!("held-winget-{n}"),
            r::SoftwareExport::Winget {
                locale: "en-US".into(),
                name: "Application".into(),
                publisher: "Acme".into(),
                description: "Controlled application".into(),
                license: "MIT".into(),
            },
            &format!("Acme.Capacity{n}"),
        )
        .await?;
        upload(&c, &store, &version, b"msi", "app-msi").await?;
        slow_versions.push(version);
    }
    upload(&c, &store, &brew, b"dmg", "app-dmg").await?;
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
    for source in [&slow, &fast] {
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
        services.insert(source.clone(), service);
    }
    let submit = async |operation: &p::PublicationOperation<'_>, version: &r::Version| {
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
        Ok::<_, anyhow::Error>((record, attempt))
    };
    let slow_op = services[&slow].operation(c.execution())?;
    let mut slow_records = std::collections::BTreeMap::new();
    for version in &slow_versions {
        slow_records.insert(
            version.resource().as_str().to_owned(),
            submit(&slow_op, version).await?,
        );
    }
    // One real discovery query at a time. Park its first continuation until B exists.
    // Expire the periodic scan deadline before starting A's six-second provider budgets.
    let first_page = CancellationToken::new();
    let scan_again = CancellationToken::new();
    let consumed = CancellationToken::new();
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let checkouts = std::sync::atomic::AtomicUsize::new(0);
    let discovery = sqlx::postgres::PgPoolOptions::new()
        .min_connections(1)
        .max_connections(1)
        .before_acquire({
            let (first_page, scan_again, consumed) =
                (first_page.clone(), scan_again.clone(), consumed.clone());
            let armed = armed.clone();
            move |_, _| {
                if !armed.load(std::sync::atomic::Ordering::SeqCst) {
                    return Box::pin(async { Ok(true) });
                }
                let n = checkouts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (first_page, scan_again, consumed) =
                    (first_page.clone(), scan_again.clone(), consumed.clone());
                Box::pin(async move {
                    match n {
                        0 => tokio::time::sleep(Duration::from_millis(5100)).await,
                        1 => {
                            first_page.cancel();
                            scan_again.cancelled().await;
                        }
                        3 => consumed.cancel(),
                        _ => {}
                    }
                    Ok(true)
                })
            }
        })
        .acquire_timeout(Duration::from_secs(15))
        .connect_with(c.inputs.options("shared", "mdm_access")?)
        .await?;
    let directory = Arc::new(PublicationDirectory {
        storage: c.execution().storage(),
        discovery_pool: discovery.clone(),
        cursor: rss_mdm_query::cursor::CursorCodec::new(&[1; 32])?,
        services,
        runtime: owner.runtime.clone(),
        audit_store: owner.audit.clone(),
        clock: Arc::new(crate::clock::ContentClock(Arc::new(
            crate::clock::SystemClock,
        ))),
    });
    armed.store(true, std::sync::atomic::Ordering::SeqCst);
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
                rss_mdm_work_page::external::Limits::new(8.try_into()?, 8.try_into()?).unwrap(),
            )
            .critical(),
    );
    launch.finish();
    let fast_op = directory.services[&fast].operation(c.execution())?;
    let slow_op = directory.services[&slow].operation(c.execution())?;
    let mut held = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), async {
        first_page.cancelled().await;
        for _ in 0..8 {
            let (id, release) = observed.recv().await.unwrap();
            anyhow::ensure!(slow_records.contains_key(&id));
            held.push((id, release));
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "software discovery or initial eight held requests timed out (observed {})",
            held.len()
        )
    })??;
    // Submit also verifies content. Allow this admission read, keeping all worker reads held.
    let (fast_record, ()) = tokio::join!(submit(&fast_op, &brew), async {
        let (id, release) = observed.recv().await.unwrap();
        assert_eq!(id, brew.resource().as_str());
        release.send(()).unwrap();
    });
    let records = [slow_records.remove(&held[0].0).unwrap(), fast_record?];
    let visible: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_software_composition.work_scopes(NULL,NULL,NULL) WHERE tenant_id=$1::uuid AND id='p:'||encode($2,'hex')||':'||$3::text)")
        .bind(c.tenant.to_string()).bind(records[1].1.id().digest().bytes().as_slice()).bind(records[1].1.attempt.to_string())
        .fetch_one(&c.operator).await?;
    anyhow::ensure!(visible, "B must be on the next fresh discovery page");
    scan_again.cancel();
    let probe=tokio::time::timeout(Duration::from_secs(5),async {
        consumed.cancelled().await;
        held.pop().unwrap().1.send(()).unwrap();
        let (name, release) = observed.recv().await.unwrap();
        anyhow::ensure!(name == brew.resource().as_str(), "slow source refilled before Brew");
        release.send(()).unwrap();
        let id=records[1].1.id().digest().bytes();
        loop {
            let applied:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_software_composition.projections WHERE tenant_id=$1::uuid AND publication=$2)").bind(c.tenant.to_string()).bind(id.as_slice()).fetch_one(&c.operator).await?;
            if applied {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        anyhow::ensure!(matches!(fast_op.record(&records[1].0,cutoff()).await?.unwrap().snapshot().attempt.outcome,rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))));
        anyhow::ensure!(!matches!(slow_op.record(&records[0].0,cutoff()).await?.unwrap().snapshot().attempt.outcome,rel::PublicationOutcome::Reported(rel::PublicationResult::Applied(_))));
        anyhow::ensure!(held.iter().all(|(_,release)| !release.is_closed()), "the other seven software reads must still be in flight");
        // The management withdrawal races the in-flight worker at the same publication slot.
        let held_record=slow_op.record(&records[0].0,cutoff()).await?.unwrap();
        let cancel=p::ServiceRequest{actor:rel::ActorId::new(c.tenant,proof.principal_id())?,id:rel::RequestId::new(c.tenant,Uuid::new_v4().to_string())?,expected_revision:held_record.snapshot().revision,as_of:rss_contract::Timepoint::try_from(now())?};
        let withdraw=p::ManagementAccess{proof:&proof,permission:Permission::ReleaseWithdraw};
        Box::pin(slow_op.withdraw(&records[0].0,&cancel,&withdraw,cutoff())).await?;
        let git=tokio::process::Command::new("/usr/bin/git").arg("--git-dir").arg(&repo).args(["rev-parse","--verify",&format!("refs/heads/tenants/{}",c.tenant)]).output().await?;
        anyhow::ensure!(git.status.success());
        Ok::<_,anyhow::Error>(())
    }).await;
    let drain = stack.shutdown();
    gate.active
        .store(false, std::sync::atomic::Ordering::Release);
    gate.release.cancel();
    anyhow::ensure!(drain.join().await?.is_clean());

    probe.map_err(|_| {
        anyhow::anyhow!("timed out waiting for the discovered software peer receipt")
    })??;
    anyhow::ensure!(matches!(
        slow_op
            .record(&records[0].0, cutoff())
            .await?
            .unwrap()
            .snapshot()
            .attempt
            .outcome,
        rel::PublicationOutcome::Reported(rel::PublicationResult::NotApplied(_))
    ));
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
    let commit:String=sqlx::query_scalar("SELECT convert_from(document,'UTF8')::jsonb->>'snapshot' FROM mdm_software_composition.targets WHERE tenant_id=$1::uuid AND record=$2 AND left(id,2)='p:'")
        .bind(c.tenant.to_string()).bind(records[1].0.value()).fetch_one(&c.operator).await?;
    let reference = format!("refs/namespaces/{}-{commit}/refs/heads/main", c.tenant);
    let lock = repo.join(format!("{reference}.lock"));
    std::fs::File::create_new(&lock)?;
    let withdrawn = Box::pin(fast_op.withdraw(&records[1].0, &request, &access, cutoff())).await?;
    anyhow::ensure!(
        withdrawn.outcome == p::Withdrawal::AwaitingConfirmation,
        "{:?}",
        withdrawn.outcome
    );
    std::fs::remove_file(lock)?;
    // Complete the retained immutable Git mutation without a database acknowledgement.
    let deleted = tokio::process::Command::new("/usr/bin/git")
        .arg("--git-dir")
        .arg(&repo)
        .args(["update-ref", "--no-deref", "-d", &reference, &commit])
        .output()
        .await?;
    anyhow::ensure!(deleted.status.success());
    let complete = || {
        sqlx::query_scalar::<_,bool>("SELECT complete FROM mdm_software_composition.withdrawals WHERE tenant_id=$1::uuid AND record=$2").bind(c.tenant.to_string()).bind(records[1].0.value()).fetch_one(&c.operator)
    };
    anyhow::ensure!(!complete().await?);
    let mut limited_ids = Vec::new();
    for n in 9..12 {
        let version = software_package(
            &c,
            &format!("held-winget-{n}"),
            r::SoftwareExport::Winget {
                locale: "en-US".into(),
                name: "Application".into(),
                publisher: "Acme".into(),
                description: "Controlled application".into(),
                license: "MIT".into(),
            },
            &format!("Acme.Capacity{n}"),
        )
        .await?;
        upload(&c, &store, &version, b"msi", "app-msi").await?;
        limited_ids.push(
            submit(&slow_op, &version)
                .await?
                .1
                .id()
                .digest()
                .bytes()
                .to_vec(),
        );
    }
    gate.slow_peak.store(0, std::sync::atomic::Ordering::SeqCst);
    let mut restart = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(16))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = restart.startup()?.commit();
    launch.stage_deferred_task_with_token(
        directory
            .clone()
            .registration(
                rss_mdm_work_page::external::Limits::new(8.try_into()?, 1.try_into()?).unwrap(),
            )
            .critical(),
    );
    launch.finish();
    let observed = tokio::time::timeout(Duration::from_secs(10), async {
        while !complete().await? || sqlx::query_scalar::<_,i64>("SELECT count(*) FROM mdm_software_composition.projections WHERE tenant_id=$1::uuid AND publication=ANY($2)")
            .bind(c.tenant.to_string()).bind(&limited_ids).fetch_one(&c.operator).await? != 3 {
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    anyhow::ensure!(restart.shutdown().join().await?.is_clean());
    observed??;
    anyhow::ensure!(gate.slow_peak.load(std::sync::atomic::Ordering::SeqCst) == 1);
    anyhow::ensure!(
        fast_op
            .reconcile_withdrawal(records[1].1.id(), records[1].1.attempt, cutoff())
            .await?
            == p::Withdrawal::Complete
    );
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_software_composition.withdrawals WHERE tenant_id=$1::uuid AND record=$2")
        .bind(c.tenant.to_string()).bind(records[1].0.value()).fetch_one(&c.operator).await?;
    anyhow::ensure!(count == 1);
    discovery.close().await;
    store.close().await;
    owner.runtime.close().await;
    c.close().await;
    Ok(())
}
