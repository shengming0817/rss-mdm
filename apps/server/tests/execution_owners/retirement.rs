use super::*;
use rss_mdm_inventory_service::collection::execution as collection;
use rss_reconcile::{DurableStore, ReconcileStep, Reconciler};
use std::time::Duration;
async fn accept(
    h: &Harness,
    object: &rss_mdm_inventory_service::objects::DeviceObject,
) -> Result<Uuid> {
    let definition: rss_mdm_policy::Definition = serde_json::from_value(
        json!({"scope":h.scope,"action":{"kind":"unmanage_device","schedule":super::mixed::manual(),"runLifetimeSeconds":300}}),
    )?;
    definition.validate()?;
    let actor = rss_mdm_authorization_service::Actor::Account {
        user: h.c.user(Uuid::new_v4()),
    };
    let frozen = rss_mdm_execution_service::frozen::Frozen::UnmanageDevice {
        schedule: super::mixed::manual(),
        run_lifetime_seconds: 300,
        actor: actor.clone(),
    };
    let policy = Uuid::new_v4();
    let version =
        super::mixed::publish(h, policy, 1, definition, serde_json::to_value(frozen)?).await?;
    let id = Uuid::new_v4();
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("INSERT INTO mdm_devices.retirements(tenant_id,id,policy,version,object,occurrence,target,authority,delivery_seconds,created_at,origin) VALUES($1::uuid,$2,$3,$4,$5,'manual',$6,$7,300,$8,'\"policy\"')").bind(h.c.tenant.to_string()).bind(id).bind(policy).bind(version).bind(object.object.key()).bind(serde_json::to_value(object)?).bind(serde_json::to_value(actor)?).bind(now()).execute(&mut *tx).await?;
    for member in &object.members {
        sqlx::query("INSERT INTO mdm_devices.retirement_channels(tenant_id,operation,device,channel,registration,generation,stage,effect) VALUES($1::uuid,$2,$3,$4,$5,$6,'cleanup','pending')").bind(h.c.tenant.to_string()).bind(id).bind(&member.device).bind(match member.channel {rss_mdm_inventory::Channel::Mdm=>"mdm",rss_mdm_inventory::Channel::Agent=>"agent"}).bind(member.registration_id).bind(member.generation).execute(&mut *tx).await?;
        sqlx::query(
            "UPDATE mdm_access.devices SET retirement=$3 WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(h.c.tenant.to_string())
        .bind(&member.device)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(id)
}
async fn step(h: &Harness, id: Uuid) -> Result<()> {
    let timer = rss_mdm_execution_service::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(10), &cancel);
    let scope = rss_mdm_execution_service::recovery_scope(h.c.tenant);
    let target = rss_reconcile::Target::new(scope.clone(), format!("retirement:{id}"))?;
    let store = h.a.service.recovery_store();
    store
        .wake(
            &target,
            &rss_reconcile::ResourceSet::empty(h.c.tenant),
            &control,
        )
        .await?;
    let batch = store
        .claim_due(&scope, 64, Duration::from_secs(30), &control)
        .await?;
    let mut seen = false;
    for claim in batch.claims {
        if claim.target() == &target {
            let ReconcileStep::Ready(diff) = h.a.service.observe(&claim, &control).await? else {
                anyhow::bail!("retirement observation deferred")
            };
            h.a.service.apply(&claim, diff, &control).await?;
            seen = true;
        }
        store.release(&claim, &control).await?;
    }
    anyhow::ensure!(seen, "retirement not claimed");
    Ok(())
}
async fn state(h: &Harness, id: Uuid) -> Result<(String, String, Option<Uuid>)> {
    Ok(sqlx::query_as("SELECT stage,effect,blocking_execution FROM mdm_devices.retirement_channels WHERE tenant_id=$1::uuid AND operation=$2").bind(h.c.tenant.to_string()).bind(id).fetch_one(&h.c.operator).await?)
}
#[tokio::test]
#[ignore = "T2: cleanup cancels both owners and waits for Running and Unknown evidence before unenrollment"]
async fn cleanup_waits_for_script_and_agent_collection() -> Result<()> {
    let h = Harness::open().await?;
    let (_, v) = h.policy("retiring").await?;
    let script = h.run(v, "retiring", now() + 300).await?;
    let (d, f, _) = super::mixed::agent(&h)?;
    let v = super::mixed::publish(&h, Uuid::new_v4(), 1, d, f).await?;
    let collection = super::mixed::run(&h, v, now()).await?;
    let at = now();
    let attempt = Uuid::new_v4();
    let mut running = rss_mdm_task_state::RunState::new(at + 300, at)?;
    running.claim(attempt, at)?;
    running.received(attempt, at)?;
    running.start(attempt, at)?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_script.runs SET state=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string())
        .bind(script)
        .bind(serde_json::to_value(&running)?)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let credential = credential_run(&h, &running).await?;
    let retirement = accept(&h, &h.object).await?;
    step(&h, retirement).await?;
    assert_eq!(state(&h, retirement).await?.0, "cleanup");
    assert_eq!(h.state(script).await?["cancellation"], "requested");
    let cancelled:String=sqlx::query_scalar("SELECT agent_state->>'cancellation' FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2").bind(h.c.tenant.to_string()).bind(collection).fetch_one(&h.c.operator).await?;
    assert_eq!(cancelled, "confirmed");
    running.expire(at + 301);
    running.cancel();
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_script.runs SET state=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string())
        .bind(script)
        .bind(serde_json::to_value(&running)?)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    step(&h, retirement).await?;
    assert_eq!(
        state(&h, retirement).await?,
        ("cleanup".into(), "unknown".into(), Some(script))
    );
    running.result(attempt, true)?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_script.runs SET state=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string())
        .bind(script)
        .bind(serde_json::to_value(&running)?)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    step(&h, retirement).await?;
    // Other owners are settled: this credential is the sole remaining cleanup barrier.
    assert_eq!(state(&h, retirement).await?.0, "cleanup");
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_recovery_tasks.runs SET state=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string())
        .bind(credential)
        .bind(serde_json::to_value(&running)?)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    step(&h, retirement).await?;
    assert_eq!(state(&h, retirement).await?.0, "unenroll");
    h.close().await
}
pub(super) async fn native(
    h: &Harness,
    reason: Option<&str>,
) -> Result<(Uuid, Uuid, rss_mdm_inventory_service::objects::DeviceObject)> {
    use rss_mdm_inventory::*;
    let object = planning::endpoint(&h.c).await?;
    let target = &object.members[0];
    let blueprint = rss_mdm_resource::blueprints::get("windows.identity", "1").unwrap();
    let rss_mdm_resource::blueprints::Definition::NativeCollection { template } =
        blueprint.definition
    else {
        unreachable!()
    };
    let fields = builtin::fields()
        .into_iter()
        .filter(|f| template.spec().mappings.contains_key(f.key.as_str()))
        .map(|definition| CollectionField {
            definition,
            scope: CollectionScope::Device,
        })
        .collect();
    let definition = CollectionDefinition::new("cleanup-native", 1, Source::MdmWindows, fields)?;
    let progress = if reason.is_none() {
        CollectionProgress::new(definition.clone())
    } else {
        CollectionProgress::native(
            definition.clone(),
            definition
                .fields()
                .map(|f| (f.key, NativeValue::Failed))
                .collect(),
            now(),
        )?
    };
    let frozen = collection::frozen::Published::NativeCollection {
        action: Box::new(collection::frozen::FrozenNative {
            input: collection::frozen::CollectionInput {
                platform: rss_mdm_policy::Platform::Windows,
                architecture: rss_mdm_policy::Architecture::X86_64,
                schedule: super::mixed::interval(),
                run_lifetime_seconds: 300,
            },
            definition: template.clone(),
            collection: definition,
            resource_digest: [7; 32],
            permissions: rss_mdm_windows_channel::collection_plan::permissions(&template)?,
        }),
        frequency: rss_mdm_policy::Frequency::EveryTrigger,
    };
    let definition: rss_mdm_policy::Definition = serde_json::from_value(
        json!({"scope":h.scope,"action":{"kind":"native_collection","resource":{"id":"windows.identity","version":"1","variant":"default","platform":"windows","architecture":"x86_64"},"schedule":super::mixed::interval(),"frequency":"every_trigger","runLifetimeSeconds":300}}),
    )?;
    definition.validate()?;
    let policy = Uuid::new_v4();
    let version =
        super::mixed::publish(h, policy, 1, definition, serde_json::to_value(frozen)?).await?;
    let task = Uuid::new_v4();
    let report = Uuid::new_v4();
    let at = now();
    let mut tx = command::seed_transaction(&h.c).await?;
    let epoch:Uuid=sqlx::query_scalar("SELECT epoch FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND source='mdm.windows'").bind(h.c.tenant.to_string()).bind(target.registration_id).fetch_one(&mut *tx).await?;
    let scope = rss_mdm_registration_service::device::scope_dataset(
        h.c.tenant,
        target.registration_id,
        "mdm.windows",
        epoch,
        "cleanup-native",
    )?;
    rss_mdm_inventory_postgres::register_collection_in(&mut tx, h.c.tenant, progress.definition())
        .await?;
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,evidence,result,reason,sealed_at,deadline) VALUES($1::uuid,$2,$3,'mdm.windows',$4,$5,0,$6,$7,$8,$9,$10,$11,to_timestamp($6+300))").bind(h.c.tenant.to_string()).bind(report).bind(target.registration_id).bind(epoch).bind(scope.encode()?).bind(at).bind(serde_json::to_string(&progress)?).bind(json!({"nativeTemplate":template})).bind(if reason.is_some() {"failed"} else {"pending"}).bind(reason).bind(reason.map(|_|at)).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_inventory.collection_tasks(tenant_id,id,policy_version,channel,origin,source_objects,device,registration,generation,occurrence,created_at,available_at,deadline,native_delivery,collection_run,started_at,dispatch_fingerprint,gateway_accepted) VALUES($1::uuid,$2,$3,'mdm','\"policy\"',$4,$5,$6,1,$7,$8,$8,$8+300,'sent',$9,$8,$10,true)").bind(h.c.tenant.to_string()).bind(task).bind(version).bind(json!([object])).bind(&target.device).bind(target.registration_id).bind(task.to_string()).bind(at).bind(report).bind(vec![0u8;32]).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((policy, task, object))
}
#[tokio::test]
#[ignore = "T2: native cleanup derives sent task certainty from Inventory reports without a second terminal state"]
async fn native_cleanup_distinguishes_complete_failure_from_unconfirmed_report() -> Result<()> {
    for reason in ["complete", "timeout", "revoked"] {
        let h = Harness::open().await?;
        let (_, task, object) = native(&h, Some(reason)).await?;
        let retirement = accept(&h, &object).await?;
        step(&h, retirement).await?;
        let state = state(&h, retirement).await?;
        if reason == "complete" {
            assert_eq!(state.0, "unenroll");
        } else {
            assert_eq!(state, ("cleanup".into(), "unknown".into(), Some(task)));
        }
        h.close().await?;
    }
    Ok(())
}
#[tokio::test]
#[ignore = "T2: native metadata detail needs InventoryRead while Agent raw detail retains sensitive authorization"]
async fn native_detail_does_not_require_raw_evidence_permission() -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    use rss_mdm_management_http::execution::task_reads::Reads;
    let h = Harness::open().await?;
    let (policy, task, _) = native(&h, Some("complete")).await?;
    let account =
        h.c.account(&[
            Permission::PolicyRead,
            Permission::OperationRead,
            Permission::InventoryRead,
        ])
        .await?;
    let proof = h.c.authenticate(&account).await?;
    let detail = Reads::run(
        h.a.task_reads.as_ref(),
        &proof,
        &h.c.request(&proof)?,
        policy,
        task,
    )
    .await?;
    let detail = serde_json::to_value(detail)?;
    assert_eq!(detail["channel"], "mdm");
    assert_eq!(detail["report"]["reason"], "complete");
    assert!(detail.get("native").is_none());
    let (d, f, _) = super::mixed::agent(&h)?;
    let policy = Uuid::new_v4();
    let v = super::mixed::publish(&h, policy, 1, d, f).await?;
    let task = super::mixed::run(&h, v, now()).await?;
    assert!(matches!(
        Reads::run(
            h.a.task_reads.as_ref(),
            &proof,
            &h.c.request(&proof)?,
            policy,
            task
        )
        .await,
        Err(rss_mdm_management_http::Error::Forbidden)
    ));
    h.close().await
}

async fn credential_run(h: &Harness, state: &rss_mdm_task_state::RunState) -> Result<Uuid> {
    use rss_mdm_recovery_credentials::tasks::{
        credential_tasks::FrozenCredential,
        policy::{ExecutionInput, Frozen},
    };
    let operation = rss_mdm_policy::CredentialOperation::CollectBitlocker;
    let schedule = super::mixed::manual();
    let definition = rss_mdm_policy::Definition {
        alias: None,
        custom_event: None,
        self_service: None,
        scope: h.scope,
        action: rss_mdm_policy::Action::Credential {
            operation: operation.clone(),
            architecture: rss_mdm_policy::Architecture::X86_64,
            schedule: schedule.clone(),
            frequency: rss_mdm_policy::Frequency::EveryTrigger,
            run_lifetime_seconds: 300,
        },
    };
    definition.validate()?;
    let frozen = Frozen::Credential {
        action: Box::new(FrozenCredential {
            operation,
            input: ExecutionInput {
                platform: rss_mdm_policy::Platform::Windows,
                architecture: rss_mdm_policy::Architecture::X86_64,
                schedule,
                run_lifetime_seconds: 300,
            },
        }),
        frequency: rss_mdm_policy::Frequency::EveryTrigger,
    };
    let version = super::mixed::publish(
        h,
        Uuid::new_v4(),
        1,
        definition,
        serde_json::to_value(frozen)?,
    )
    .await?;
    let id = Uuid::new_v4();
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("INSERT INTO mdm_recovery_tasks.runs(tenant_id,id,policy_version,origin,source_objects,device,registration,generation,occurrence,created_at,available_at,deadline,state,dispatch_fingerprint,gateway_accepted) VALUES($1::uuid,$2,$3,'\"policy\"',$4,$5,$6,$7,$8,$9,$9,$10,$11,$12,true)")
        .bind(h.c.tenant.to_string()).bind(id).bind(version).bind(json!([h.object])).bind(h.p.device()).bind(h.p.registration()).bind(h.p.generation()).bind(id.to_string()).bind(now()).bind(now()+300).bind(serde_json::to_value(state)?).bind(vec![0u8;32]).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(id)
}
