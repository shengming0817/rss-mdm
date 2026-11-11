#[path = "fixture.rs"]
pub(crate) mod fixture;
use crate::{authority_t2_support::Context, planning_t2_support as planning};
use anyhow::Result;
use fixture::Fixture;
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_policy_service::{
    configuration::{Configuration, Owner, Protected, frozen::Frozen},
    transaction,
};
use rss_reconcile::{DurableStore, ReconcileStep};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
#[path = "query.rs"]
mod query;
pub(crate) async fn seed(
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
    Ok(sqlx::query_as("SELECT input_revision, observed_revision, (SELECT count(*) FROM mdm_planning.configuration_claims AS x WHERE x.tenant_id = d.tenant_id AND x.device = d.device), (SELECT count(*) FROM mdm_planning.configuration_objects AS x WHERE x.tenant_id = d.tenant_id AND x.device = d.device), (SELECT count(*) FROM mdm_planning.configuration_operations AS x WHERE x.tenant_id = d.tenant_id AND x.device = d.device), (SELECT count(*) FROM rss_device_command.commands AS x INNER JOIN mdm_access.command_authorities AS a ON (a.tenant_id, a.command_device) = (x.tenant_id, x.device_id) WHERE a.tenant_id = d.tenant_id AND a.device = d.device), (SELECT count(*) FROM mdm_windows.native_commands AS x INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.id) = (x.tenant_id, x.device) WHERE r.tenant_id = d.tenant_id AND r.id = d.device), (SELECT count(*) FROM mdm_planning.configuration_receipts AS r INNER JOIN mdm_planning.configuration_operations AS o ON (o.tenant_id, o.id) = (r.tenant_id, r.id) WHERE o.tenant_id = d.tenant_id AND o.device = d.device) FROM mdm_planning.configuration_devices AS d WHERE tenant_id = CAST($1 AS uuid) AND device = $2").bind(c.tenant.to_string()).bind(device).fetch_one(&c.operator).await?)
}
async fn wake(app: &rss_mdm_policy_service::application::Application, device: &str) -> Result<()> {
    transaction::inspect(
        &app.runtime,
        app.tenant,
        (app, vec![device.to_owned()]),
        |ctx, tx| {
            Box::pin(async move {
                ctx.0
                    .configuration
                    .as_ref()
                    .expect("MDM configuration")
                    .wake_devices_in(tx, &ctx.1)
                    .await
            })
        },
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

#[tokio::test]
#[ignore = "T2: Policy configuration atomic command participation, rollback and restart"]
async fn configuration_claims_and_commands_share_commit_and_replay_identity() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let object = planning::endpoint(&c).await?;
    let sentinel = planning::endpoint(&c).await?;
    let published = planning::published(&c, &object).await?;
    let key = crate::device_material_support::protection(&c)?;
    let policy = seed(&c, published.scope, &object, &key).await?;
    let device = &object.members[0].device;
    let command = Fixture::open(&c, false)
        .await
        .map_err(|error| anyhow::anyhow!("configuration command fixture: {error:?}"))?;
    let owner = planning::owner(&c, "mdm_policy_runtime")
        .await
        .map_err(|error| anyhow::anyhow!("configuration policy runtime: {error:?}"))?;
    let app = crate::assembly::policy::application(
        &owner,
        c.tenant,
        &[7; 32],
        Arc::new(crate::clock::SystemClock),
        key.clone(),
        None,
    )
    .await
    .map_err(|error| anyhow::anyhow!("configuration application: {error:?}"))?;
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_audit_integration::StorageProfile::Mdm,
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
                    .as_ref()
                    .expect("MDM configuration")
                    .wake_devices_in(tx, &[ctx.1.to_owned()])
                    .await?;
                ctx.0
                    .configuration
                    .as_ref()
                    .expect("MDM configuration")
                    .reconcile_in(tx, ctx.1, ctx.2)
                    .await?;
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
    let events = crate::assembly::policy::events(
        app.clone(),
        command.materials.clone(),
        command.software.materials.clone(),
        command.registration.materials.clone(),
        Vec::new(),
    )
    .await?;
    let worker = rss_mdm_policy_service::worker::PolicyWork::new(
        app.clone(),
        events,
        scheduler.store.clone(),
    );
    wake(&app, device).await?;
    step(&worker, c.tenant, device).await?;
    // The production Policy role owns this outbox relay, including claim and settlement.
    let timer = rss_mdm_policy_service::clock::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(10), &cancel);
    let configuration = app.configuration.as_ref().expect("MDM configuration");
    assert_eq!(configuration.relay_once(&control).await?, 1);
    assert_eq!(configuration.relay_once(&control).await?, 0);
    let committed = counts(&c, device).await?;
    assert_eq!(committed, (2, 2, 1, 1, 1, 1, 1, 1));
    let identity:(Uuid,serde_json::Value,String)=sqlx::query_as("SELECT o.id, o.authority, r.actor FROM mdm_planning.configuration_operations AS o INNER JOIN mdm_planning.configuration_receipts AS r USING (tenant_id, id) WHERE o.tenant_id = CAST($1 AS uuid) AND o.device = $2").bind(c.tenant.to_string()).bind(device).fetch_one(&c.operator).await?;
    assert_eq!(identity.1["policy"], json!(policy));
    drop(worker);
    drop(app);
    drop(owner);
    let owner = planning::owner(&c, "mdm_policy_runtime").await?;
    let app = crate::assembly::policy::application(
        &owner,
        c.tenant,
        &[7; 32],
        Arc::new(crate::clock::SystemClock),
        key.clone(),
        None,
    )
    .await?;
    let events = crate::assembly::policy::events(
        app.clone(),
        command.materials.clone(),
        command.software.materials.clone(),
        command.registration.materials.clone(),
        Vec::new(),
    )
    .await?;
    let worker = rss_mdm_policy_service::worker::PolicyWork::new(
        app.clone(),
        events,
        scheduler.store.clone(),
    );
    wake(&app, device).await?;
    step(&worker, c.tenant, device).await?;
    let replay = counts(&c, device).await?;
    assert_eq!(replay, (3, 3, 1, 1, 1, 1, 1, 1));
    let after:(Uuid,serde_json::Value,String)=sqlx::query_as("SELECT o.id, o.authority, r.actor FROM mdm_planning.configuration_operations AS o INNER JOIN mdm_planning.configuration_receipts AS r USING (tenant_id, id) WHERE o.tenant_id = CAST($1 AS uuid) AND o.device = $2").bind(c.tenant.to_string()).bind(device).fetch_one(&c.operator).await?;
    assert_eq!(after, identity);
    let foreign:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid AND device=$2").bind(c.tenant.to_string()).bind(&sentinel.members[0].device).fetch_one(&c.operator).await?;
    assert_eq!(foreign, 0);
    let outbox:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain='mdm.policy.configuration.v1'").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(outbox, 1);
    query::prove_batch(
        &c,
        &app,
        &command.resources.storage.read_pool,
        &key,
        identity.0,
    )
    .await?;
    // The fifth real owner shares the RSS command scope, but never repairs a foreign orphan.
    let original:serde_json::Value=sqlx::query_scalar("SELECT to_jsonb(c) FROM rss_device_command.commands c WHERE tenant_id=$1::uuid AND command_id=$2")
        .bind(c.tenant.to_string()).bind(identity.0.to_string()).fetch_one(&c.operator).await?;
    let mut foreign = original.clone();
    let foreign_id = format!("foreign:{}", Uuid::new_v4());
    foreign["command_id"] = json!(foreign_id);
    foreign["outbox_message_id"] = json!(foreign_id);
    foreign["outbox_domain"] = json!("another.owner.v1");
    foreign["status"] = json!("published");
    foreign["queued_at"] = json!(1000000);
    foreign["published_at"] = json!(1000000);
    foreign["deadline"] = json!(2000000);
    foreign["received_at"] = serde_json::Value::Null;
    foreign["terminal_at"] = serde_json::Value::Null;
    foreign["version"] = json!(2);
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("INSERT INTO rss_device_command.commands SELECT * FROM jsonb_populate_record(NULL::rss_device_command.commands,$1)").bind(&foreign).execute(&mut *tx).await?;
    tx.commit().await?;
    wake(&app, device).await?;
    step(&worker, c.tenant, device).await?;
    let unchanged:i64=sqlx::query_scalar("SELECT version FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2").bind(c.tenant.to_string()).bind(&foreign_id).fetch_one(&c.operator).await?;
    assert_eq!(unchanged, 2);
    // Bypass the FK in this injection transaction only, simulating a corrupt historical row.
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("SET LOCAL session_replication_role=replica")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(identity.0.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    wake(&app, device).await?;
    assert!(step(&worker, c.tenant, device).await.is_err());
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("INSERT INTO rss_device_command.commands SELECT * FROM jsonb_populate_record(NULL::rss_device_command.commands,$1)").bind(&original).execute(&mut *tx).await?;
    tx.commit().await?;
    drop(worker);
    drop(app);
    drop(owner);
    use rss_runtime::ManagedResource;
    scheduler.shutdown().await?;
    Fixture::close(command).await?;
    c.close().await;
    Ok(())
}

mod owned_scopes;
