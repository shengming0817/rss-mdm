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
    let frozen = rss_mdm_device_service::control::frozen::Frozen::UnmanageDevice {
        schedule: super::mixed::manual(),
        run_lifetime_seconds: 300,
        actor: actor.clone(),
    };
    let policy = Uuid::new_v4();
    let version =
        super::mixed::publish(h, policy, 1, definition, serde_json::to_value(frozen)?).await?;
    let mut tx = command::seed_transaction(&h.c).await?;
    let (id, replay) = rss_mdm_device_service::lifecycle::accept_in(
        &mut tx,
        h.c.tenant,
        &rss_mdm_device_service::planning::PlanningObjects,
        &rss_mdm_device_service::lifecycle::Acceptance {
            origin: rss_mdm_audit_integration::activity::ActivityOrigin::Policy,
            policy,
            version,
            occurrence: "manual",
            target: object,
            actor: &actor,
            delivery_seconds: 300,
            now: now(),
        },
    )
    .await?;
    assert!(!replay);
    tx.commit().await?;
    Ok(id)
}
async fn step(h: &Harness, id: Uuid) -> Result<()> {
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(10), &cancel);
    let scope = rss_mdm_device_service::control::recovery_scope(h.c.tenant);
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
// The issuance fixture already contains a verified real certificate. Seed its
// retained PKI mapping so retirement must enqueue physical revocation, not an empty set.
async fn certificate(h: &Harness) -> Result<()> {
    let (leaf, metadata): (Vec<u8>, Value) = sqlx::query_as("SELECT decode(i.certificate_chain ->> 0, 'base64'), i.metadata FROM mdm_access.certificate_issuances AS i INNER JOIN mdm_access.credentials AS k ON (k.tenant_id, k.id) = (i.tenant_id, i.credential) WHERE k.tenant_id = CAST($1 AS uuid) AND k.device = $2")
        .bind(h.c.tenant.to_string()).bind(h.p.device()).fetch_one(&h.c.operator).await?;
    let issuer: Vec<u8> = serde_json::from_value(metadata["issuer"].clone())?;
    let serial: Vec<u8> = serde_json::from_value(metadata["serial"].clone())?;
    let root = crate::native_identity_t2_support::der(
        "x509",
        &h.c.inputs.directory.join("task-trust-ca/ca.pem"),
    )
    .await?;
    let issuer = issuer
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("INSERT INTO mdm_pki.issuers(tenant_id,purpose,digest,revision,state,chain,provider,not_after) VALUES($1::uuid,'agent',$2,1,'active',$3,'step_ca',$4)")
        .bind(h.c.tenant.to_string()).bind(&issuer).bind(root)
        .bind(metadata["not_after"].as_i64().unwrap()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_pki.certificates (tenant_id, purpose, fingerprint, issuer, serial, device, not_after, certificate, verification_version, verification_trust) VALUES (CAST($1 AS uuid), 'agent', sha256($2), $3, $4, $5, $6, $2, 1, sha256($2))")
        .bind(h.c.tenant.to_string()).bind(leaf)
        .bind(issuer)
        .bind(rss_mdm_device_trust::serial(&serial)).bind(h.p.device())
        .bind(metadata["not_after"].as_i64().unwrap()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "T2: cleanup cancels both owners and waits for Running and Unknown evidence before unenrollment"]
async fn cleanup_waits_for_script_and_agent_collection() -> Result<()> {
    let mut h = Harness::open().await?;
    certificate(&h).await?;
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
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(30), &cancel);
    let scope = rss_mdm_device_service::control::recovery_scope(h.c.tenant);
    let target = rss_reconcile::Target::new(scope.clone(), format!("retirement:{retirement}"))?;
    let (old_claim, old_diff) = {
        let store = h.a.service.recovery_store();
        store
            .wake(
                &target,
                &rss_reconcile::ResourceSet::empty(h.c.tenant),
                &control,
            )
            .await?;
        let mut batch = store
            .claim_due(&scope, 64, Duration::from_secs(30), &control)
            .await?;
        let index = batch
            .claims
            .iter()
            .position(|c| c.target() == &target)
            .unwrap();
        let claim = batch.claims.remove(index);
        let ReconcileStep::Ready(diff) = h.a.service.observe(&claim, &control).await? else {
            anyhow::bail!("retirement not observed")
        };
        store.release(&claim, &control).await?;
        for other in batch.claims {
            store.release(&other, &control).await?;
        }
        (claim, diff)
    };
    drop(h.delivery);
    drop(h.audit);
    Fixture::close(h.a).await?;
    h.a = Fixture::open(&h.c, true).await?;
    (h.audit, h.delivery) = delivery(&h.c, &h.a).await?;
    assert!(
        h.a.service
            .apply(&old_claim, old_diff, &control)
            .await
            .is_err()
    );
    step(&h, retirement).await?;
    assert_eq!(state(&h, retirement).await?.0, "unenroll");
    assert_eq!(h.a.service.relay_once().await?, 1);
    let offer = h.claim().await?;
    assert!(matches!(offer.payload, w::TaskPayload::Unmanage(_)));
    h.event(&offer, w::TaskEvent::Received).await?;
    h.event(&offer, w::TaskEvent::Start).await?;
    h.event(
        &offer,
        w::TaskEvent::UnmanageResult {
            outcome: w::UnmanageOutcome::Completed,
        },
    )
    .await?;
    step(&h, retirement).await?;
    assert_eq!(state(&h, retirement).await?.0, "complete");
    let revoked: (String, bool, bool, i64) = sqlx::query_as("SELECT r.state, NOT EXISTS (SELECT FROM mdm_access.credentials AS k WHERE k.tenant_id = r.tenant_id AND k.device = r.id AND k.state = 'active'), NOT EXISTS (SELECT FROM mdm_access.report_sources AS s WHERE s.tenant_id = r.tenant_id AND s.device = r.id AND s.enabled), (SELECT count(*) FROM mdm_pki.revocations AS v INNER JOIN mdm_pki.certificates AS k USING (tenant_id, purpose, issuer, serial) WHERE k.tenant_id = r.tenant_id AND k.device = r.id AND v.state = 'pending') FROM mdm_access.devices AS r WHERE r.tenant_id = CAST($1 AS uuid) AND r.id = $2")
        .bind(h.c.tenant.to_string()).bind(h.p.device()).fetch_one(&h.c.operator).await?;
    assert_eq!(revoked, ("revoked".into(), true, true, 1));
    let before: serde_json::Value = sqlx::query_scalar(
        "SELECT state FROM mdm_devices.unmanage_runs WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(h.c.tenant.to_string())
    .bind(offer.payload.task_id())
    .fetch_one(&h.c.operator)
    .await?;
    assert!(h.event(&offer, w::TaskEvent::Start).await.is_err());
    let _ = h
        .event(
            &offer,
            w::TaskEvent::UnmanageResult {
                outcome: w::UnmanageOutcome::Completed,
            },
        )
        .await;
    let after: serde_json::Value = sqlx::query_scalar(
        "SELECT state FROM mdm_devices.unmanage_runs WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(h.c.tenant.to_string())
    .bind(offer.payload.task_id())
    .fetch_one(&h.c.operator)
    .await?;
    assert_eq!(before, after);
    assert_eq!(state(&h, retirement).await?.0, "complete");
    // Completed retirement and late receipts must never restore ordinary work eligibility.
    let mut tx = command::seed_transaction(&h.c).await?;
    assert!(
        !rss_mdm_registration_service::lifecycle::work_allowed_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            &mut tx,
            &h.c.tenant.to_string(),
            h.p.device()
        )
        .await?
    );
    tx.rollback().await?;
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
    let epoch:Uuid=sqlx::query_scalar("SELECT epoch FROM mdm_access.report_sources WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND source = 'mdm.windows'").bind(h.c.tenant.to_string()).bind(target.device.clone()).fetch_one(&mut *tx).await?;
    let scope = rss_mdm_registration_service::device::scope_dataset(
        rss_mdm_install_support::StorageProfile::Mdm,
        h.c.tenant,
        &target.device,
        "mdm.windows",
        epoch,
        "cleanup-native",
    )?;
    rss_mdm_inventory_postgres::register_collection_in(&mut tx, h.c.tenant, progress.definition())
        .await?;
    sqlx::query("INSERT INTO mdm_access.collection_runs (tenant_id, id, device, source, epoch, scope, sequence, started_at, attempts, evidence, result, reason, sealed_at, deadline) VALUES (CAST($1 AS uuid), $2, $3, 'mdm.windows', $4, $5, 0, $6, $7, $8, $9, $10, $11, to_timestamp($6 + 300))").bind(h.c.tenant.to_string()).bind(report).bind(target.device.clone()).bind(epoch).bind(scope.encode()?).bind(at).bind(serde_json::to_string(&progress)?).bind(json!({"nativeTemplate":template})).bind(if reason.is_some() {"failed"} else {"pending"}).bind(reason).bind(reason.map(|_|at)).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_inventory.collection_tasks (tenant_id, id, policy_version, channel, origin, source_objects, device, occurrence, created_at, available_at, deadline, native_delivery, collection_run, started_at, dispatch_fingerprint, gateway_accepted) VALUES (CAST($1 AS uuid), $2, $3, 'mdm', '\"policy\"', $4, $5, $6, $7, $7, $7 + 300, 'sent', $8, $7, $9, TRUE)").bind(h.c.tenant.to_string()).bind(task).bind(version).bind(json!([object])).bind(&target.device).bind(task.to_string()).bind(at).bind(report).bind(vec![0u8;32]).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((policy, task, object))
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
    sqlx::query("INSERT INTO mdm_recovery_tasks.runs(tenant_id,id,policy_version,origin,source_objects,device,occurrence,created_at,available_at,deadline,state,dispatch_fingerprint,gateway_accepted) VALUES($1::uuid,$2,$3,'\"policy\"',$4,$5,$6,$7,$7,$8,$9,$10,true)")
        .bind(h.c.tenant.to_string()).bind(id).bind(version).bind(json!([h.object])).bind(h.p.device()).bind(id.to_string()).bind(now()).bind(now()+300).bind(serde_json::to_value(state)?).bind(vec![0u8;32]).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(id)
}

#[tokio::test]
#[ignore = "T2: retirement checkpoints one bounded history page per claim and preserves sent blockers after restart"]
async fn cleanup_history_is_bounded_and_resumes() -> Result<()> {
    let mut h = Harness::open().await?;
    let native = native_controls(&mut h, 65).await?;
    // Legal terminal history: cancellation alone does not confirm remote stop.
    let blocked = Uuid::from_u128(65);
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE rss_device_command.commands AS d SET status = 'cancelled', version = d.version + 1, terminal_at = d.queued_at + 1 FROM mdm_devices.control_operations AS o WHERE (o.tenant_id, CAST(o.id AS text)) = (d.tenant_id, d.command_id) AND o.tenant_id = CAST($1 AS uuid) AND o.device = $2")
        .bind(h.c.tenant.to_string()).bind(native.device.clone()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_windows.attempts (tenant_id, id, operation, device, ordinal, credential, session, message, phase, request, protocol_epoch) VALUES (CAST($1 AS uuid), $2, $3, $4, 1, $5, 1, 1, 'execute', $6, $7)")
        .bind(h.c.tenant.to_string()).bind(Uuid::new_v4()).bind(blocked).bind(native.device.clone()).bind(native.credential).bind(vec![0u8;68]).bind(native.epoch).execute(&mut *tx).await?;
    tx.commit().await?;
    let retirement = accept(&h, &h.object).await?;
    step(&h, retirement).await?;
    assert_eq!(state(&h, retirement).await?.0, "cleanup");
    let checkpoint: Option<Uuid> = sqlx::query_scalar(
        "SELECT cleanup_after FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(h.c.tenant.to_string())
    .bind(retirement)
    .fetch_one(&h.c.operator)
    .await?;
    assert_eq!(checkpoint, Some(Uuid::from_u128(64)));
    let replacement = Fixture::open(&h.c, true).await?;
    Fixture::close(std::mem::replace(&mut h.a, replacement)).await?;
    step(&h, retirement).await?;
    assert_eq!(
        state(&h, retirement).await?,
        ("cleanup".into(), "unknown".into(), Some(blocked))
    );
    let resumed: Option<Uuid> = sqlx::query_scalar(
        "SELECT cleanup_after FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(h.c.tenant.to_string())
    .bind(retirement)
    .fetch_one(&h.c.operator)
    .await?;
    assert_eq!(resumed, checkpoint);
    h.close().await
}

/// Legal native controls shared by the two independently bounded owner consumers.
pub(super) async fn native_controls(
    h: &mut Harness,
    count: u128,
) -> Result<crate::native_identity_t2_support::Native> {
    use rss_mdm_authorization_service::Permission;
    use rss_mdm_device_service::control::device_control::{Action, Input};
    let native = crate::native_identity_t2_support::seed(&h.c, "windows").await?;
    h.object = serde_json::from_value(
        json!({"object":{"kind":"endpoint","id":native.device},"associationVersion":null,"verified":true,"members":[{"device":native.device,"channel":"mdm"}]}),
    )?;
    h.scope = planning::published(&h.c, &h.object).await?.scope;
    let account = h.c.account(&[Permission::DeviceWipe]).await?;
    let proof = h.c.authenticate(&account).await?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("INSERT INTO mdm_windows.capabilities (tenant_id, device, protocol_epoch, os_version, edition, session, observed_at) VALUES (CAST($1 AS uuid), $2, $3, '10.0.22631.0', 4, 1, CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS bigint))")
        .bind(h.c.tenant.to_string()).bind(native.device.clone()).bind(native.epoch).execute(&mut *tx).await?;
    tx.commit().await?;
    for n in 1..=count {
        h.a.service
            .create_control(
                &proof,
                &native.device,
                &Input {
                    operation_id: Uuid::from_u128(n),
                    deadline: now() + 300,
                    action: Action::Wipe { confirmed: true },
                },
                &h.c.request(&proof)?,
            )
            .await?;
    }
    Ok(native)
}
