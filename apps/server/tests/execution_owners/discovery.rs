//! Real discovery pools stay separate from available claim/settlement pools.
use super::*;
use rss_mdm_recovery_observation::{Phase, Scan};

fn phase(value: Option<Scan>) -> Phase {
    match value {
        None => Phase::Unobserved,
        Some(Scan {
            failure: Some(kind),
            ..
        }) => Phase::Failed(kind),
        Some(_) => Phase::Healthy,
    }
}
type Probe = Box<dyn Fn() -> Phase + Send + Sync>;

#[tokio::test]
#[ignore = "T2: every independent discovery loop survives its read pool outage with the claim pool still usable"]
async fn registered_owners_recover_discovery_without_restart() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect_with(c.inputs.options("shared", "mdm_access")?)
        .await?;
    let fixture = Fixture::with_discovery(&c, pool.clone()).await?;
    let store = fixture.resources.storage.reconcile.clone();
    let credentials = crate::assembly::credential_execution::assemble(
        pool.clone(),
        &fixture.resources.config,
        &fixture.resources.background,
        fixture.resources.storage.runtime.clone(),
        c.execution(),
        fixture.resources.storage.audit.clone(),
        fixture.resources.protection.clone(),
        crate::assembly::credential_owners_t2::protection(&c, "old")?,
        fixture.resources.source.clone(),
        store.clone(),
        fixture.resources.storage.worker_budget.clone(),
    )
    .await?;
    let owners =
        crate::assembly::owner_boundaries_t2::Owners::with_discovery(&c, pool.clone()).await?;
    let scopes = crate::scope_t2::with_discovery(&c, pool.clone()).await?;
    let assets =
        crate::assembly::software_assets_t2::fixture::Fixture::with_discovery(&c, pool.clone())
            .await?;
    let policy_owner = planning::owner(&c, "mdm_policy_runtime").await?;
    let app = crate::assembly::policy::application(
        &fixture.resources.background,
        &policy_owner,
        c.execution(),
        &[7; 32],
        Arc::new(crate::clock::SystemClock),
        fixture.resources.protection.clone(),
        None,
    )
    .await?;
    let events = crate::assembly::policy::events(
        c.execution(),
        app.clone(),
        Arc::new(crate::assembly::policy::EventInputs {
            source: fixture.resources.source.clone(),
            protection: fixture.resources.protection.clone(),
            instance: fixture.resources.config.identity.instance_id.clone(),
        }),
        fixture.software.materials.clone(),
        fixture.registration.materials.clone(),
        credentials.materials.clone(),
    )
    .await?;
    let automation = rss_mdm_policy_service::worker::Automation::new(
        rss_mdm_policy_service::worker::PolicyWork::new(
            pool.clone(),
            c.execution().storage(),
            app.clone(),
            events,
            store.clone(),
        ),
    );
    let associations = Arc::new(rss_mdm_device_service::Associations::new(
        c.audit.clone(),
        &[7; 32],
    )?);
    let devices = Arc::new(
        rss_mdm_device_service::worker::DeviceWork::new(
            pool.clone(),
            c.execution(),
            associations.clone(),
            c.runtime.clone(),
            store.clone(),
            script::transaction::deadline(),
        )
        .await?,
    );
    let held = pool.acquire().await?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    let mut probes: Vec<(&str, rss_runtime::TaskStatus, Probe)> = Vec::new();
    macro_rules! register {
        ($name:expr, $registration:expr, $probe:expr) => {{
            let status = launch.stage_deferred_task_with_token($registration.critical());
            probes.push(($name, status, Box::new($probe)));
        }};
    }
    macro_rules! task {
        ($name:expr, $owner:expr) => {{
            let owner = $owner.clone();
            register!(
                $name,
                owner.clone().registration(
                    policy()?,
                    Duration::from_secs(20),
                    Arc::new(tokio::sync::Notify::new())
                ),
                move || owner.health().discovery
            );
        }};
    }
    task!("script", fixture.script_work);
    task!("collection", fixture.collection_work);
    task!("enrollment", fixture.registration.worker);
    task!("access", fixture.access_execution.worker);
    for worker in &credentials.worker {
        task!("credentials", worker);
    }
    macro_rules! native {
        ($name:expr, $owner:expr, $signals:ty) => {{
            let owner = $owner.clone();
            register!(
                $name,
                owner.clone().registration(
                    policy()?,
                    Duration::from_secs(20),
                    Arc::new(<$signals>::default())
                ),
                move || owner.health().discovery
            );
        }};
    }
    native!(
        "device control",
        fixture.service,
        rss_mdm_device_service::control::worker_wake::Signals
    );
    native!(
        "software",
        fixture.software.service,
        rss_mdm_software_service::deployment::worker_wake::Signals
    );
    native!(
        "installation",
        fixture.registration.native,
        rss_mdm_registration_service::installation::worker_wake::Signals
    );
    native!(
        "native credentials",
        credentials.native,
        rss_mdm_recovery_credentials::native::worker_wake::Signals
    );
    let groups = owners.groups.clone();
    register!(
        "group",
        Arc::new(rss_mdm_group_service::runtime::GroupWork::new(
            groups.clone(),
            store.clone()
        ))
        .registration(policy()?, Duration::from_secs(20), Arc::default()),
        move || phase(groups.runner_health().discovery)
    );
    let compliance = owners.compliance.clone();
    register!(
        "compliance",
        Arc::new(rss_mdm_compliance_service::runtime::ComplianceWork::new(
            compliance.clone(),
            store.clone()
        ))
        .registration(policy()?, Duration::from_secs(20), Arc::default()),
        move || phase(compliance.worker_status().discovery)
    );
    register!(
        "scope",
        Arc::new(rss_mdm_scope_service::runtime::ScopeWork::new(
            scopes.clone(),
            store.clone()
        ))
        .registration(policy()?, Duration::from_secs(20), Arc::default()),
        move || phase(scopes.runner_health().discovery)
    );
    let assets = assets.assets;
    register!(
        "asset query",
        Arc::new(rss_mdm_inventory_service::assets::runtime::QueryWork::new(
            assets.clone(),
            store.clone()
        ))
        .registration(policy()?, Duration::from_secs(20), Arc::default()),
        move || phase(assets.worker_status().discovery)
    );
    register!(
        "policy domains",
        automation.registration(
            policy()?,
            policy()?,
            Duration::from_secs(20),
            Arc::default()
        ),
        move || {
            match app.automation_health().discovery {
                None => Phase::Unobserved,
                Some(v) if v.failure.is_some() => {
                    Phase::Failed(rss_reconcile::ErrorKind::Transient)
                }
                Some(_) => Phase::Healthy,
            }
        }
    );
    register!(
        "associations",
        devices.registration(policy()?, Duration::from_secs(20), Arc::default()),
        move || associations.worker_health().discovery
    );
    launch.finish();
    let observation: Result<()> = async {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if probes
                    .iter()
                    .all(|(_, _, probe)| matches!(probe(), Phase::Failed(_)))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        for (name, status, _) in &probes {
            anyhow::ensure!(
                status.current() == rss_runtime::TaskState::Running,
                "{name} stopped on discovery outage"
            );
        }
        let timer = rss_mdm_device_service::control::recovery::Timer::new();
        let cancel = CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(5), &cancel);
        let empty = rss_reconcile::Scope::new(c.tenant, "test.discovery.available")?;
        anyhow::ensure!(
            store
                .claim_due(&empty, 1, 1, Duration::from_secs(30), &control)
                .await?
                .claims
                .is_empty()
        );
        Ok(())
    }
    .await;
    drop(held);
    let recovery: Result<()> = async {
        observation?;
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                if probes.iter().all(|(_, _, probe)| probe() == Phase::Healthy) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        for (name, status, _) in &probes {
            anyhow::ensure!(
                status.current() == rss_runtime::TaskState::Running,
                "{name} was restarted or stopped"
            );
        }
        Ok(())
    }
    .await;
    let shutdown = stack.shutdown().join().await?;
    drop(probes);
    drop(credentials);
    owners.storage.runtime.close().await;
    policy_owner.runtime.close().await;
    fixture.close().await?;
    pool.close().await;
    c.close().await;
    anyhow::ensure!(shutdown.is_clean(), "worker shutdown failed");
    recovery
}

#[tokio::test]
#[ignore = "T2: one critical Script registration recovers discovery, visits 34 tenants and wraps to new work"]
async fn discovery_recovery_preserves_the_lifecycle_and_tenant_pages() -> Result<()> {
    use rss_request_context::TenantId;
    let mut tenants = (0..34)
        .map(|_| TenantId::parse(&Uuid::new_v4().to_string()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    tenants.sort_by_key(ToString::to_string);
    let c = Context::open("shared", &tenants).await?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect_with(c.inputs.options("shared", "mdm_access")?)
        .await?;
    let fixture = Fixture::with_discovery(&c, pool.clone()).await?;
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(90), &cancel);
    use sha2::{Digest, Sha256};
    let policy_id = Uuid::new_v4();
    let version = Uuid::new_v4();
    // Archived policy cleanup may retain a historical Scope without executing devices.
    let definition: rss_mdm_policy::Definition = serde_json::from_value(json!({
        "scope": Uuid::new_v4(), "action": {"kind":"unmanage_device", "runLifetimeSeconds":300}
    }))?;
    definition.validate()?;
    let rss_mdm_policy::Action::UnmanageDevice {
        schedule,
        run_lifetime_seconds,
    } = &definition.action
    else {
        unreachable!()
    };
    for tenant in &tenants {
        let actor = rss_mdm_authorization_service::Actor::ApiKey {
            instance: fixture.resources.config.identity.instance_id.clone(),
            tenant: tenant.to_string(),
            id: Uuid::new_v4(),
        };
        let frozen = serde_json::to_value(
            rss_mdm_device_service::control::frozen::Frozen::UnmanageDevice {
                schedule: schedule.clone(),
                run_lifetime_seconds: *run_lifetime_seconds,
                actor: actor.clone(),
            },
        )?;
        let mut tx = c.operator.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,1,$3,1,'archived',$4,$5,0)")
            .bind(tenant.to_string()).bind(policy_id).bind(version).bind(serde_json::to_value(&definition)?)
            .bind(serde_json::to_value(actor)?).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,frozen,fingerprint) VALUES($1::uuid,$2,$3,1,'unmanage_device',$4,$5)")
            .bind(tenant.to_string()).bind(version).bind(policy_id).bind(&frozen)
            .bind(Sha256::digest(serde_json::to_vec(&frozen)?).to_vec()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_script.policy_recovery(tenant_id,expected_epoch,policy) VALUES($1::uuid,1,$2)")
            .bind(tenant.to_string()).bind(policy_id).execute(&mut *tx).await?;
        tx.commit().await?;
        fixture
            .resources
            .storage
            .reconcile
            .wake(
                &rss_reconcile::Target::new(
                    script::wake::scope(*tenant),
                    format!("policy:{policy_id}"),
                )?,
                &rss_reconcile::ResourceSet::empty(*tenant),
                &control,
            )
            .await?;
    }
    let held = pool.acquire().await?;
    let worker = fixture.script_work.clone();
    let registered_worker = worker.clone();
    let notify = Arc::new(tokio::sync::Notify::new());
    let signal = notify.clone();
    let (status_send, status_receive) = tokio::sync::oneshot::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut lifecycle = rss_runtime::LifecycleScope::<(), anyhow::Error, anyhow::Error>::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(25))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let result = {
        let drive = lifecycle.drive(
            move |startup| {
                Box::pin(async move {
                    let mut launch = startup.commit();
                    let status = launch.stage_deferred_task_with_token(
                        registered_worker
                            .registration(policy()?, Duration::from_secs(20), signal)
                            .critical(),
                    );
                    launch.finish();
                    let _ = status_send.send(status);
                    std::future::pending().await
                })
            },
            async {
                stopped.await?;
                Ok(())
            },
        );
        tokio::pin!(drive);
        let check = async {
            let status = status_receive.await?;
            tokio::time::timeout(Duration::from_secs(10), async {
                while !matches!(worker.health().discovery, Phase::Failed(_)) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await?;
            anyhow::ensure!(status.current() == rss_runtime::TaskState::Running);
            drop(held);
            let tenant_ids = tenants
                .iter()
                .map(|tenant| Uuid::parse_str(&tenant.to_string()))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            wait_consumed(&c.operator, &tenant_ids, policy_id, 1).await?;
            anyhow::ensure!(worker.health().discovery == Phase::Healthy);
            anyhow::ensure!(status.current() == rss_runtime::TaskState::Running);
            // Both ends of the page range receive another wake, including the earlier tenant after wrap.
            for tenant in [tenants[0], tenants[33]] {
                let mut tx = c.operator.begin().await?;
                sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                    .bind(tenant.to_string())
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("UPDATE mdm_script.policy_recovery SET input_revision=2 WHERE tenant_id=$1::uuid AND policy=$2")
                    .bind(tenant.to_string()).bind(policy_id).execute(&mut *tx).await?;
                tx.commit().await?;
                fixture
                    .resources
                    .storage
                    .reconcile
                    .wake(
                        &rss_reconcile::Target::new(
                            script::wake::scope(tenant),
                            format!("policy:{policy_id}"),
                        )?,
                        &rss_reconcile::ResourceSet::empty(tenant),
                        &control,
                    )
                    .await?;
            }
            notify.notify_one();
            wait_consumed(&c.operator, &[tenant_ids[0], tenant_ids[33]], policy_id, 2).await?;
            let epochs: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT expected_epoch FROM mdm_script.policy_recovery WHERE tenant_id=ANY($1) AND policy=$2")
                .bind(&tenant_ids).bind(policy_id).fetch_all(&c.operator).await?;
            anyhow::ensure!(epochs == [1], "recovery retagged original work");
            Ok::<(), anyhow::Error>(())
        };
        let result = tokio::select! {
            outcome = &mut drive => { outcome?; Err(anyhow::anyhow!("critical lifecycle exited during recoverable discovery")) },
            result = check => result,
        };
        let _ = stop.send(());
        if result.is_ok() {
            let outcome = drive.await?;
            anyhow::ensure!(matches!(
                outcome.exit(),
                rss_runtime::ScopeExit::StopRequested(Ok(()))
            ));
            anyhow::ensure!(
                outcome
                    .shutdown()
                    .as_ref()
                    .is_ok_and(|receipt| receipt.is_clean())
            );
        }
        result
    };
    // A failed assertion also joins the scope's cleanup, rather than abandoning registrations.
    let _ = lifecycle.wait().await?;
    drop(worker);
    fixture.close().await?;
    pool.close().await;
    c.close().await;
    result
}

async fn wait_consumed(
    pool: &sqlx::PgPool,
    tenants: &[Uuid],
    policy: Uuid,
    revision: i64,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_script.policy_recovery WHERE tenant_id=ANY($1) AND policy=$2 AND input_consumed=$3 AND runs_done")
                .bind(tenants).bind(policy).bind(revision).fetch_one(pool).await?;
            if count == tenants.len() as i64 { return Ok::<_, anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await??;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: a blocked real discovery query times out, recovers, and remains cancellable during retry"]
async fn discovery_query_deadline_and_retry_cancellation() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect_with(c.inputs.options("shared", "mdm_access")?)
        .await?;
    let fixture = Fixture::with_discovery(&c, pool.clone()).await?;
    let worker = fixture.script_work.clone();
    let mut lock = c.operator.begin().await?;
    sqlx::query("LOCK TABLE mdm_script.policy_recovery IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(25))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    let notify = Arc::new(tokio::sync::Notify::new());
    let status = launch.stage_deferred_task_with_token(
        worker
            .clone()
            .registration(policy()?, Duration::from_secs(20), notify.clone())
            .critical(),
    );
    launch.finish();
    let deadline = tokio::time::timeout(Duration::from_secs(12), async {
        while worker.health().discovery != Phase::Failed(rss_reconcile::ErrorKind::Deadline) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    lock.rollback().await?;
    let mut held = None;
    let recovery: Result<()> = async {
        deadline?;
        anyhow::ensure!(status.current() == rss_runtime::TaskState::Running);
        tokio::time::timeout(Duration::from_secs(15), async {
            while worker.health().discovery != Phase::Healthy {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        // Exhaust only discovery after recovery; cancellation must interrupt its retry wait.
        held = Some(pool.acquire().await?);
        notify.notify_one();
        tokio::time::timeout(Duration::from_secs(8), async {
            while !matches!(worker.health().discovery, Phase::Failed(_)) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        Ok(())
    }
    .await;
    let shutdown = tokio::time::timeout(Duration::from_secs(2), stack.shutdown().join()).await;
    drop(held);
    let stopped = status.current();
    drop(worker);
    fixture.close().await?;
    pool.close().await;
    c.close().await;
    recovery?;
    anyhow::ensure!(shutdown??.is_clean());
    anyhow::ensure!(stopped == rss_runtime::TaskState::Stopped(rss_runtime::TaskExit::Cancelled));
    Ok(())
}

#[tokio::test]
#[ignore = "T2: a closed discovery pool remains fatal and the critical lifecycle observes the original exit"]
async fn fatal_discovery_still_terminates_the_critical_scope() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let pool = c.inputs.pool("shared", "mdm_access").await?;
    let fixture = Fixture::with_discovery(&c, pool.clone()).await?;
    let worker = fixture.script_work.clone();
    pool.close().await;
    let registration = worker
        .clone()
        .registration(policy()?, Duration::from_secs(20), Arc::default())
        .critical();
    let mut scope = rss_runtime::LifecycleScope::<(), anyhow::Error, anyhow::Error>::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(25))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        scope.drive(
            move |startup| {
                Box::pin(async move {
                    let mut launch = startup.commit();
                    launch.stage_deferred_task_with_token(registration);
                    launch.finish();
                    std::future::pending().await
                })
            },
            std::future::pending(),
        ),
    )
    .await??;
    anyhow::ensure!(matches!(
        outcome.exit(),
        rss_runtime::ScopeExit::CriticalTaskExited(_)
    ));
    anyhow::ensure!(
        worker.health().discovery == Phase::Failed(rss_reconcile::ErrorKind::StorageContract)
    );
    drop(worker);
    fixture.close().await?;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: four actual owner claim wrappers retain tenant A failure across empty tenant B scans"]
async fn owner_claim_wrappers_recover_only_the_failed_scope() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let other = Context::open("shared", &[]).await?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect_with(c.inputs.options("shared", "mdm_scheduler_runtime")?)
        .await?;
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(30), &cancel);
    let store = rss_mdm_work_page::scheduler::Scheduler::new(pool.clone(), &control).await?;
    let owners = crate::assembly::owner_boundaries_t2::Owners::open(&c).await?;
    let scopes = crate::scope_t2::open(&c).await?;
    let assets = crate::assembly::software_assets_t2::fixture::Fixture::open(&c).await?;
    let result: Result<()> = async {
        macro_rules! check {
            ($work:expr, $domain:expr, $health:expr) => {{
                let work = $work;
                let a = rss_reconcile::Scope::new(c.tenant, $domain)?;
                let b = rss_reconcile::Scope::new(other.tenant, $domain)?;
                let held = pool.acquire().await?;
                anyhow::ensure!(
                    work.claim_due(&a, 1, 1, Duration::from_secs(30), &control)
                        .await
                        .is_err()
                );
                drop(held);
                anyhow::ensure!($health.scan.is_some_and(|scan| scan.failure.is_some()));
                anyhow::ensure!(
                    work.claim_due(&b, 1, 1, Duration::from_secs(30), &control)
                        .await?
                        .claims
                        .is_empty()
                );
                anyhow::ensure!(
                    $health.scan.is_some_and(|scan| scan.failure.is_some()),
                    "other tenant erased failure"
                );
                anyhow::ensure!($health.unresolved_attempts == 0);
                anyhow::ensure!(
                    work.claim_due(&a, 1, 1, Duration::from_secs(30), &control)
                        .await?
                        .claims
                        .is_empty()
                );
                anyhow::ensure!($health.scan.is_some_and(|scan| scan.failure.is_none()));
            }};
        }
        check!(
            rss_mdm_group_service::runtime::GroupWork::new(owners.groups.clone(), store.clone()),
            "mdm.groups",
            owners.groups.runner_health()
        );
        check!(
            rss_mdm_compliance_service::runtime::ComplianceWork::new(
                owners.compliance.clone(),
                store.clone()
            ),
            "mdm.compliance",
            owners.compliance.worker_status()
        );
        check!(
            rss_mdm_scope_service::runtime::ScopeWork::new(scopes.clone(), store.clone()),
            "mdm.scopes",
            scopes.runner_health()
        );
        check!(
            rss_mdm_inventory_service::assets::runtime::QueryWork::new(
                assets.assets.clone(),
                store.clone()
            ),
            "mdm.asset-queries",
            assets.assets.worker_status()
        );
        Ok(())
    }
    .await;
    owners.storage.runtime.close().await;
    scopes.runtime.close().await;
    drop(assets);
    pool.close().await;
    c.close().await;
    other.close().await;
    result
}
