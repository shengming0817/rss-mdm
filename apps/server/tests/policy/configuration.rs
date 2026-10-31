use crate::{authority_t2_support::Context, planning_t2_support as fixture};
use anyhow::Result;
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_policy_service::{
    configuration::{Configuration, Owner, Protected, frozen::Frozen},
    transaction,
};
use rss_reconcile::{DurableStore, ReconcileStep, Reconciler};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
#[path = "query.rs"]
mod query;
async fn seed(
    c: &Context,
    scope: Uuid,
    object: &rss_mdm_inventory_service::objects::DeviceObject,
    key: &rss_mdm_native_protection::Protector,
) -> Result<Uuid> {
    let policy = Uuid::new_v4();
    let version = Uuid::new_v4();
    let native: Configuration = serde_json::from_value(
        json!({"target":{"kind":"device"},"apply":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana","instance":[],"operation":"delete","value":null}}},"remove":null}),
    )?;
    native.validate()?;
    let frozen = serde_json::to_value(Frozen::Configuration {
        native: Protected::seal(key, c.tenant, Owner::Policy { policy, version }, &native)?,
        platform: rss_mdm_policy::Platform::Windows,
        exit: rss_mdm_policy::Exit::Retain,
        resource_digest: [3; 32],
    })?;
    let definition: rss_mdm_policy::Definition = serde_json::from_value(
        json!({"scope":scope,"action":{"kind":"configuration","resource":{"id":"configuration-fixture","version":"v1","variant":"default","platform":"windows","architecture":"x86_64"}}}),
    )?;
    definition.validate()?;
    let actor = rss_mdm_authorization_service::Actor::Account {
        user: c.user(Uuid::new_v4()),
    };
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at) VALUES($1::uuid,$2,1,$3,1,'enabled',$4,$5,$6)").bind(c.tenant.to_string()).bind(policy).bind(version).bind(serde_json::to_value(definition)?).bind(serde_json::to_value(actor)?).bind(time::OffsetDateTime::now_utc().unix_timestamp()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,resource,resource_version,frozen,fingerprint) VALUES($1::uuid,$2,$3,1,'configuration','configuration-fixture','v1',$4,$5)").bind(c.tenant.to_string()).bind(version).bind(policy).bind(&frozen).bind(Sha256::digest(serde_json::to_vec(&frozen)?).to_vec()).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO mdm_planning.configuration_devices(tenant_id,device) VALUES($1::uuid,$2)",
    )
    .bind(c.tenant.to_string())
    .bind(&object.members[0].device)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(policy)
}
async fn counts(c: &Context, device: &str) -> Result<(i64, i64, i64, i64, i64, i64, i64, i64)> {
    Ok(sqlx::query_as("SELECT input_revision,observed_revision,(SELECT count(*) FROM mdm_planning.configuration_claims x WHERE x.tenant_id=d.tenant_id AND x.device=d.device),(SELECT count(*) FROM mdm_planning.configuration_objects x WHERE x.tenant_id=d.tenant_id AND x.device=d.device),(SELECT count(*) FROM mdm_planning.configuration_operations x WHERE x.tenant_id=d.tenant_id AND x.device=d.device),(SELECT count(*) FROM rss_device_command.commands x JOIN mdm_access.command_authorities a ON(a.tenant_id,a.command_device)=(x.tenant_id,x.device_id) WHERE a.tenant_id=d.tenant_id AND a.device=d.device),(SELECT count(*) FROM mdm_windows.native_commands x JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(x.tenant_id,x.registration) WHERE r.tenant_id=d.tenant_id AND r.device=d.device),(SELECT count(*) FROM mdm_planning.configuration_receipts r JOIN mdm_planning.configuration_operations o ON(o.tenant_id,o.id)=(r.tenant_id,r.id) WHERE o.tenant_id=d.tenant_id AND o.device=d.device) FROM mdm_planning.configuration_devices d WHERE tenant_id=$1::uuid AND device=$2").bind(c.tenant.to_string()).bind(device).fetch_one(&c.operator).await?)
}
async fn wake(app: &rss_mdm_policy_service::application::Application, device: &str) -> Result<()> {
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (app, vec![device.to_owned()]),
        |ctx, tx| Box::pin(async move { ctx.0.configuration.wake_devices_in(tx, &ctx.1).await }),
    )
    .await?;
    Ok(())
}
async fn step(
    worker: &rss_mdm_policy_service::worker::PolicyWork,
    tenant: rss_request_context::TenantId,
    device: &str,
) -> Result<()> {
    let timer = rss_mdm_policy_service::clock::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(10), &cancel);
    let scope = rss_reconcile::Scope::new(tenant, "mdm.policy")?;
    let expected = format!("configuration:{:x}", Sha256::digest(device.as_bytes()));
    let batch = worker
        .claim_due(&scope, 16, Duration::from_secs(30), &control)
        .await?;
    let mut applied = false;
    for claim in batch.claims {
        if claim.target().entity() == expected {
            let ReconcileStep::Ready(diff) = worker.observe(&claim, &control).await? else {
                anyhow::bail!("configuration observation deferred")
            };
            assert!(matches!(
                worker.apply(&claim, diff, &control).await?,
                ReconcileStep::Ready(())
            ));
            applied = true;
        }
        worker.release(&claim, &control).await?;
    }
    anyhow::ensure!(applied, "configuration target was not claimed");
    Ok(())
}
// A valid historical command on the same RSS device coordinate, already expired.
// This seeds owner facts only; recovery still runs through each real runtime role.
async fn expired_execution(
    c: &Context,
    object: &rss_mdm_inventory_service::objects::DeviceObject,
    key: &rss_mdm_native_protection::Protector,
) -> Result<Uuid> {
    #[derive(serde::Serialize)]
    struct Identity<'a> {
        operation: Uuid,
        device: &'a str,
        registration: Uuid,
        generation: i64,
    }
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Metadata<'a> {
        platform: &'a str,
        deadline: i64,
        input_version: &'a str,
        target: &'a serde_json::Value,
    }
    let device = &object.members[0].device;
    let (registration,generation):(Uuid,i64)=sqlx::query_as("SELECT registration,registration_generation FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND device=$2").bind(c.tenant.to_string()).bind(device).fetch_one(&c.operator).await?;
    let id = Uuid::new_v4();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let input = json!({"operationId":id,"inputVersion":"v1","target":{"kind":"device"},"deadline":now-60,"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/Reboot/RebootNow","instance":[],"operation":"exec","value":null}}}});
    let _: rss_mdm_execution_service::Create = serde_json::from_value(input.clone())?;
    let meta = Metadata {
        platform: "windows",
        deadline: now - 60,
        input_version: "v1",
        target: &input["target"],
    };
    let owner = serde_json::to_string(&Identity {
        operation: id,
        device,
        registration,
        generation,
    })?;
    let field = serde_json::to_string(&("native.operation.input/v1", &meta))?;
    let sealed = key.seal_bytes(
        &serde_json::to_vec(&input)?,
        &rss_mdm_native_protection::ProtectionContext::new(c.tenant, &owner, &field, 1)?.derive(),
    )?;
    let authority = rss_mdm_execution_service::authority::ExecutionAuthority::DeviceControl {
        action: rss_mdm_execution_service::device_control::Kind::Restart,
        confirmation: None,
        required: vec![rss_mdm_authorization_service::Permission::DeviceControl],
        actor: rss_mdm_authorization_service::Actor::Account {
            user: c.user(Uuid::new_v4()),
        },
    };
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO rss_device_command.commands(tenant_id,command_id,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,outbox_message_id,outbox_fingerprint,status,published_at,version) SELECT tenant_id,$3,command_device,generation,epoch,$4,$5,$6,'mdm.commands.v1',$7,$4,'published',$6,2 FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND device=$2").bind(c.tenant.to_string()).bind(device).bind(id.to_string()).bind(vec![9u8;32]).bind((now-60)*1_000_000).bind((now-120)*1_000_000).bind(format!("dispatch.{id}")).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_windows.native_commands(tenant_id,id,registration,registration_generation) VALUES($1::uuid,$2,$3,$4)").bind(c.tenant.to_string()).bind(id).bind(registration).bind(generation).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_commands.operations(tenant_id,id,device,request,input_context,fingerprint,registration,registration_generation,generation,epoch,authority,dispatch_fingerprint,gateway_accepted,observed_command_version) SELECT tenant_id,$3,device,$4,$5,$6,registration,registration_generation,generation,epoch,$7,$6,true,2 FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND device=$2").bind(c.tenant.to_string()).bind(device).bind(id).bind(sealed).bind(serde_json::to_value(meta)?).bind(vec![9u8;32]).bind(serde_json::to_value(authority)?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_commands.agent_install_inputs(tenant_id,device,input_revision,observed_revision) VALUES($1::uuid,$2,1,1)").bind(c.tenant.to_string()).bind(device).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(id)
}
async fn execution_observation(c: &Context, id: Uuid) -> Result<(String, i64, i64)> {
    Ok(sqlx::query_as("SELECT c.status,c.version,o.observed_command_version FROM mdm_commands.operations o JOIN rss_device_command.commands c ON(c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.id=$2").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?)
}
async fn downstream(c: &Context, device: &str) -> Result<(i64, i64)> {
    Ok(sqlx::query_as("SELECT input_revision,coalesce((SELECT wake_version FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler='mdm.commands.v1' AND entity=$3),0) FROM mdm_commands.agent_install_inputs WHERE tenant_id=$1::uuid AND device=$2").bind(c.tenant.to_string()).bind(device).bind(format!("agent-install:{:x}",Sha256::digest(device.as_bytes()))).fetch_one(&c.operator).await?)
}
async fn execution_step(
    service: &rss_mdm_execution_service::ExecutionService,
    tenant: rss_request_context::TenantId,
    device: &str,
    expected: rss_reconcile::ConvergeAction,
) -> Result<()> {
    let timer = rss_mdm_execution_service::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(10), &cancel);
    let scope = rss_mdm_execution_service::recovery_scope(tenant);
    let target = rss_reconcile::Target::new(
        scope.clone(),
        format!("{:x}", Sha256::digest(device.as_bytes())),
    )?;
    let store = service.recovery_store();
    store
        .wake(
            &target,
            &rss_reconcile::ResourceSet::empty(tenant),
            &control,
        )
        .await?;
    let batch = store
        .claim_due(&scope, 16, Duration::from_secs(30), &control)
        .await?;
    let mut observed = false;
    for claim in batch.claims {
        if claim.target() == &target {
            let ReconcileStep::Ready(diff) = service.observe(&claim, &control).await? else {
                anyhow::bail!("execution observation deferred")
            };
            assert_eq!(diff.converge_action(), expected);
            if expected != rss_reconcile::ConvergeAction::Noop {
                assert!(matches!(
                    service.apply(&claim, diff, &control).await?,
                    ReconcileStep::Ready(())
                ));
            }
            observed = true;
        }
        store.release(&claim, &control).await?;
    }
    anyhow::ensure!(observed, "execution target was not claimed");
    Ok(())
}
#[tokio::test]
#[ignore = "T2: Policy configuration atomic command participation, rollback and restart"]
async fn configuration_claims_and_commands_share_commit_and_replay_identity() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let object = fixture::endpoint(&c).await?;
    let sentinel = fixture::endpoint(&c).await?;
    let published = fixture::published(&c, &object).await?;
    let key = crate::device_material_support::protection(&c)?;
    let policy = seed(&c, published.scope, &object, &key).await?;
    let device = &object.members[0].device;
    let command = crate::command_runtime_t2_support::open(&c, false).await?;
    let owner = fixture::owner(&c, "mdm_policy_runtime").await?;
    let app = crate::assembly::policy::application(
        &owner,
        c.tenant,
        &[7; 32],
        Arc::new(crate::clock::SystemClock),
        key.clone(),
        None,
    )
    .await?;
    let audit = RequestAudit::new(
        c.tenant.to_string(),
        "configuration_reconcile",
        AuditIntent::Management,
    );
    audit.identify_service("configuration-test");
    let before = counts(&c, device).await?;
    let rollback = transaction::run(
        &owner.audit,
        &owner.runtime,
        c.tenant,
        &audit,
        (&app, device, &audit),
        |ctx, tx| {
            Box::pin(async move {
                ctx.0.audit_store.prepare_in(tx, ctx.2, &[]).await?;
                ctx.0
                    .configuration
                    .wake_devices_in(tx, &[ctx.1.to_owned()])
                    .await?;
                ctx.0.configuration.reconcile_in(tx, ctx.1, ctx.2).await?;
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query("SELECT 1/0").execute(c).await?;
                        Ok(())
                    })
                })
                .await?;
                Ok(())
            })
        },
    )
    .await;
    assert!(rollback.is_err());
    assert_eq!(counts(&c, device).await?, before);
    let outbox:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain='mdm.policy.configuration.v1'").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(outbox, 0);
    let scheduler = crate::scheduler::SchedulerStorage::open(
        c.inputs
            .database("shared", "mdm_scheduler_runtime")
            .options()?,
    )
    .await?;
    let events = crate::assembly::policy::events(app.clone(), command.materials.clone()).await?;
    let worker = rss_mdm_policy_service::worker::PolicyWork::new(
        app.clone(),
        events,
        scheduler.store.clone(),
    );
    wake(&app, device).await?;
    step(&worker, c.tenant, device).await?;
    let committed = counts(&c, device).await?;
    assert_eq!(committed, (2, 2, 1, 1, 1, 1, 1, 1));
    let identity:(Uuid,serde_json::Value,String)=sqlx::query_as("SELECT o.id,o.authority,r.actor FROM mdm_planning.configuration_operations o JOIN mdm_planning.configuration_receipts r USING(tenant_id,id) WHERE o.tenant_id=$1::uuid AND o.device=$2").bind(c.tenant.to_string()).bind(device).fetch_one(&c.operator).await?;
    assert_eq!(identity.1["policy"], json!(policy));
    drop(worker);
    drop(app);
    drop(owner);
    let owner = fixture::owner(&c, "mdm_policy_runtime").await?;
    let app = crate::assembly::policy::application(
        &owner,
        c.tenant,
        &[7; 32],
        Arc::new(crate::clock::SystemClock),
        key.clone(),
        None,
    )
    .await?;
    let events = crate::assembly::policy::events(app.clone(), command.materials.clone()).await?;
    let worker = rss_mdm_policy_service::worker::PolicyWork::new(
        app.clone(),
        events,
        scheduler.store.clone(),
    );
    wake(&app, device).await?;
    step(&worker, c.tenant, device).await?;
    let replay = counts(&c, device).await?;
    assert_eq!(replay, (3, 3, 1, 1, 1, 1, 1, 1));
    let after:(Uuid,serde_json::Value,String)=sqlx::query_as("SELECT o.id,o.authority,r.actor FROM mdm_planning.configuration_operations o JOIN mdm_planning.configuration_receipts r USING(tenant_id,id) WHERE o.tenant_id=$1::uuid AND o.device=$2").bind(c.tenant.to_string()).bind(device).fetch_one(&c.operator).await?;
    assert_eq!(after, identity);
    let foreign:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid AND device=$2").bind(c.tenant.to_string()).bind(&sentinel.members[0].device).fetch_one(&c.operator).await?;
    assert_eq!(foreign, 0);
    let outbox:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain='mdm.policy.configuration.v1'").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(outbox, 1);
    // Policy can expire a foreign RSS command before Execution gets a turn.
    let expired = expired_execution(&c, &object, &key).await?;
    wake(&app, device).await?;
    step(&worker, c.tenant, device).await?;
    assert_eq!(
        execution_observation(&c, expired).await?,
        ("timed_out".into(), 3, 2)
    );
    assert_eq!(
        c.audit_count("mdm.business", &expired.to_string()).await?,
        0
    );
    let pending = downstream(&c, device).await?;
    execution_step(
        &command.service,
        c.tenant,
        device,
        rss_reconcile::ConvergeAction::Update,
    )
    .await?;
    assert_eq!(
        execution_observation(&c, expired).await?,
        ("timed_out".into(), 3, 3)
    );
    assert_eq!(
        c.audit_count("mdm.business", &expired.to_string()).await?,
        1
    );
    let observed = downstream(&c, device).await?;
    assert_eq!(observed, (pending.0 + 1, pending.1 + 1));
    execution_step(
        &command.service,
        c.tenant,
        device,
        rss_reconcile::ConvergeAction::Noop,
    )
    .await?;
    assert_eq!(
        c.audit_count("mdm.business", &expired.to_string()).await?,
        1
    );
    assert_eq!(downstream(&c, device).await?, observed);
    query::prove_batch(&c, &app, &command, &key, identity.0).await?;
    drop(worker);
    drop(app);
    drop(owner);
    use rss_runtime::ManagedResource;
    scheduler.shutdown().await?;
    crate::command_runtime_t2_support::close(command).await?;
    c.close().await;
    Ok(())
}
