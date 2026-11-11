//! Actual SQL publishers, local projection and independent owner workers.
use super::*;
use crate::{asset_inputs, local_delivery, worker_wake};
use rss_mdm_install_support::StorageProfile;
use rss_transactional_messaging::{message::*, policy::OperationDeadline};
use rss_transactional_messaging_postgres::{PgConsumerEffect, PgRuntime};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Duration};

async fn cut(c: &Context) -> Result<rss_mdm_inventory::AssetCut> {
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(6));
    Ok(rss_mdm_inventory_service::assets::cut::capture(&c.audit, c.tenant, &budget).await?)
}
async fn consumer(c: &Context) -> Result<Arc<PgRuntime>> {
    use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
    use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa};
    let db = c.inputs.database("shared", "mdm_asset_ingress_consumer");
    let pg = PgConfig::new(
        &db.host,
        db.port,
        &db.name,
        &db.user,
        PgPassword::new(crate::config::secret(&db.password_file)?.as_str()),
        PgPrivateCa::from_pem(crate::config::read(&db.ca_file, 1024 * 1024, false)?.to_vec())?,
    )
    .with_pool_limits(0, 2);
    Ok(Arc::new(
        PgRuntime::connect_consumer(
            pg,
            crate::lifecycle::RuntimeTimer,
            ExecutionBinding::new(
                StorageIdentity::new(c.inputs.installation.target, c.inputs.installation.lineage)?,
                vec![(c.tenant, Epoch::new(1)?)],
            )?,
        )
        .await?,
    ))
}
async fn message(c: &Context) -> Result<(MessageEnvelope<Vec<u8>>, Vec<u8>)> {
    let (wire, fingerprint): (serde_json::Value,Vec<u8>) = sqlx::query_as("SELECT envelope,fingerprint FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain='mdm-assets' AND envelope->>'route'='asset.changed' ORDER BY seq LIMIT 1")
        .bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    let envelope = MessageEnvelope::new(
        MessageId::parse(wire["id"].as_str().context("message ID")?)?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                c.tenant,
                rss_contract::Timepoint::try_from(
                    wire["occurred_at"].as_i64().context("occurred-at")?,
                )?,
                MessagingDomain::parse(asset_inputs::DOMAIN)?,
                MessageRoute::parse("asset.changed")?,
                ContractIdentity::new(
                    rss_contract::ContractId::parse("mdm.asset.changed")?,
                    rss_contract::ContractVersion::from_static_major(1),
                    rss_contract::SchemaDigest::parse(wire["schema"].as_str().context("schema")?)?,
                ),
            ),
            MessageMetadataExtensions::new(None, None, None, BTreeMap::new()),
        ),
        serde_json::from_value(wire["payload"].clone())?,
    );
    Ok((envelope, fingerprint))
}
async fn wait_sql(c: &Context, sql: &'static str, object: Uuid) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if sqlx::query_scalar::<_, bool>(sql)
                .bind(c.tenant.to_string())
                .bind(object)
                .fetch_one(&c.operator)
                .await?
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .context("durable owner failed to converge")??;
    Ok(())
}

// Delivery and scheduling are different barriers. Every owner must consume its
// wake and finish durable work, including Group publication received by Scope.
async fn settled(c: &Context) -> Result<()> {
    wait_sql(c, "SELECT $2::uuid IS NOT NULL AND NOT EXISTS(SELECT FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain IN('mdm-assets','mdm-group') AND status<>'published') AND NOT EXISTS(SELECT FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler IN('mdm.groups','mdm.scopes','mdm.compliance') AND next_run IS NOT NULL) AND NOT EXISTS(SELECT FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND NOT completed) AND NOT EXISTS(SELECT FROM mdm_scope.tasks WHERE tenant_id=$1::uuid AND NOT completed) AND NOT EXISTS(SELECT FROM mdm_scope.group_changes WHERE tenant_id=$1::uuid AND NOT completed) AND NOT EXISTS(SELECT FROM mdm_compliance.runs WHERE tenant_id=$1::uuid AND NOT completed)",Uuid::new_v4()).await
}

#[tokio::test]
#[ignore = "T2: one source transaction publishes canonical SQL wire bytes; partial multi-owner wake rolls back"]
async fn canonical_fact_and_atomic_multi_owner_wake() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let device = planning::endpoint(&c).await?;
    let (message, fingerprint) = message(&c).await?;
    assert_eq!(
        Sha256::digest(message.canonical_bytes()).as_slice(),
        fingerprint
    );
    let event: rss_mdm_inventory::AssetChanged = serde_json::from_slice(message.payload())?;
    event.validate()?;
    assert_eq!(
        event.identity.device.as_deref(),
        Some(device.members[0].device.as_str())
    );
    assert!(event.identity.registration_epoch.is_some());
    assert!(!String::from_utf8(message.payload().clone())?.contains("locator"));
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain='mdm-assets'").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(
        count, 3,
        "device, credential and source each publish exactly one fact"
    );
    let runtime = consumer(&c).await?;
    let receiver = asset_inputs::Receiver {
        messaging: rss_reconcile_postgres::PgMessagingStore::new(
            runtime.clone(),
            c.tenant,
            OperationDeadline::from_remaining(Duration::from_secs(6)),
        )
        .await?,
    };
    runtime
        .local_tx_with_context(
            c.tenant,
            OperationDeadline::from_remaining(Duration::from_secs(6)),
            (&receiver, &message),
            |(r, m), tx| {
                Box::pin(async move {
                    r.apply(
                        tx,
                        m,
                        OperationDeadline::from_remaining(Duration::from_secs(6)),
                    )
                    .await
                    .map_err(|_| {
                        rss_transactional_messaging_postgres::PgError::from(sqlx::Error::Protocol(
                            "input effect".into(),
                        ))
                    })?;
                    Ok(())
                })
            },
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    let before:Vec<(String,String,i64)>=sqlx::query_as("SELECT reconciler,entity,wake_version FROM rss_reconcile.targets WHERE tenant_id=$1::uuid ORDER BY reconciler,entity").bind(c.tenant.to_string()).fetch_all(&c.operator).await?;
    assert_eq!(before.len(), 4);
    let mut lock = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("SELECT 1 FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler='mdm.scopes' AND entity='inputs' FOR UPDATE").bind(c.tenant.to_string()).fetch_one(&mut *lock).await?;
    let attempt = runtime
        .local_tx_with_context(
            c.tenant,
            OperationDeadline::from_remaining(Duration::from_secs(1)),
            (&receiver, &message),
            |(r, m), tx| {
                Box::pin(async move {
                    r.apply(
                        tx,
                        m,
                        OperationDeadline::from_remaining(Duration::from_secs(1)),
                    )
                    .await
                    .map_err(|_| {
                        rss_transactional_messaging_postgres::PgError::from(sqlx::Error::Protocol(
                            "blocked third wake".into(),
                        ))
                    })?;
                    Ok(())
                })
            },
        )
        .await;
    assert!(attempt.fold(|_| Ok(()), Err, Err, Err, Err, Err).is_err());
    lock.rollback().await?;
    let after:Vec<(String,String,i64)>=sqlx::query_as("SELECT reconciler,entity,wake_version FROM rss_reconcile.targets WHERE tenant_id=$1::uuid ORDER BY reconciler,entity").bind(c.tenant.to_string()).fetch_all(&c.operator).await?;
    assert_eq!(
        after, before,
        "the first two wakes must not escape a failed third wake"
    );
    runtime.close().await;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: reverse commits, unrelated writers, rollback and 1001-event pages retain fixed-cut semantics"]
async fn late_commits_and_bounded_pages_do_not_use_sequence_as_commit_order() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let owners = Owners::open(&c).await?;
    let a = planning::endpoint(&c).await?;
    let b = planning::endpoint(&c).await?;
    let before = cut(&c).await?;
    let mut late = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query(
        "UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id=$1::uuid AND device=$2",
    )
    .bind(c.tenant.to_string())
    .bind(&a.members[0].device)
    .execute(&mut *late)
    .await?;
    let low: i64 =
        sqlx::query_scalar("SELECT max(revision) FROM mdm.asset_changes WHERE tenant_id=$1::uuid")
            .bind(c.tenant.to_string())
            .fetch_one(&mut *late)
            .await?;
    let mut early = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("SET LOCAL lock_timeout='1s'")
        .execute(&mut *early)
        .await?;
    sqlx::query(
        "UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id=$1::uuid AND device=$2",
    )
    .bind(c.tenant.to_string())
    .bind(&b.members[0].device)
    .execute(&mut *early)
    .await?;
    early.commit().await?;
    let middle = cut(&c).await?;
    late.commit().await?;
    let after = cut(&c).await?;
    let reader = rss_mdm_inventory_service::assets::planning::SnapshotReader::bind(
        StorageProfile::Mdm,
        owners.storage.runtime.clone(),
        c.tenant,
    );
    group::transaction::inspect(
        &owners.storage.runtime,
        c.tenant,
        (&reader, &before, &middle, &after),
        |ctx, tx| {
            Box::pin(async move {
                let first = ctx
                    .0
                    .changes_page_in(tx, Some(ctx.1), ctx.2, 0, None, 1000)
                    .await?;
                assert!(first.iter().all(|e| e.revision > low));
                assert_eq!(first.len(), 1);
                let second = ctx
                    .0
                    .changes_page_in(tx, Some(ctx.2), ctx.3, 0, None, 1000)
                    .await?;
                assert_eq!(
                    second.iter().map(|e| e.revision).collect::<Vec<_>>(),
                    vec![low]
                );
                Ok(())
            })
        },
    )
    .await?;
    let mut rolled = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query(
        "UPDATE mdm_access.report_sources SET enabled=true WHERE tenant_id=$1::uuid AND device=$2",
    )
    .bind(c.tenant.to_string())
    .bind(&a.members[0].device)
    .execute(&mut *rolled)
    .await?;
    let rolled_id: i64 =
        sqlx::query_scalar("SELECT max(revision) FROM mdm.asset_changes WHERE tenant_id=$1::uuid")
            .bind(c.tenant.to_string())
            .fetch_one(&mut *rolled)
            .await?;
    rolled.rollback().await?;
    let absent:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision=$2) AND NOT EXISTS(SELECT FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id LIKE '%:'||$2::text)").bind(c.tenant.to_string()).bind(rolled_id).fetch_one(&c.operator).await?;
    assert!(absent);
    let mut batch = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    // Legal owner transitions in one source transaction cross the real 1000-event boundary.
    for enabled in (0..1001).map(|n| n % 2 == 0) {
        sqlx::query("UPDATE mdm_access.report_sources SET enabled=$3 WHERE tenant_id=$1::uuid AND device=$2").bind(c.tenant.to_string()).bind(&a.members[0].device).bind(enabled).execute(&mut *batch).await?;
    }
    batch.commit().await?;
    let upper = cut(&c).await?;
    group::transaction::inspect(
        &owners.storage.runtime,
        c.tenant,
        (&reader, &after, &upper),
        |ctx, tx| {
            Box::pin(async move {
                let first = ctx
                    .0
                    .changes_page_in(tx, Some(ctx.1), ctx.2, 0, None, 1000)
                    .await?;
                assert_eq!(first.len(), 1000);
                let second = ctx
                    .0
                    .changes_page_in(
                        tx,
                        Some(ctx.1),
                        ctx.2,
                        first.last().unwrap().revision,
                        None,
                        1000,
                    )
                    .await?;
                assert_eq!(second.len(), 1);
                Ok(())
            })
        },
    )
    .await?;
    drop(owners);
    c.close().await;
    Ok(())
}

struct Workers {
    stack: rss_runtime::ShutdownStack,
    pool: sqlx::PgPool,
}
impl Workers {
    async fn start(
        c: &Context,
        owners: &Owners,
        scopes: Arc<rss_mdm_scope_service::Scopes>,
    ) -> Result<Self> {
        let config: crate::config::Config =
            serde_json::from_value(crate::host_t2_support::configuration(
                &c.inputs,
                "shared",
                c.tenant,
                "127.0.0.1:0".parse()?,
                Uuid::new_v4(),
            )?)?;
        let protection = crate::device_material_support::protection(c)?;
        let listener = worker_wake::Listener::new(config.access_options()?, c.tenant);
        let signals = listener.signals.clone();
        let assets = local_delivery::Delivery::open(
            &config,
            protection.clone(),
            Arc::default(),
            local_delivery::Lane {
                database: &config.asset_input_database,
                role: "mdm_asset_ingress_consumer",
                domain: asset_inputs::DOMAIN,
                consumer: asset_inputs::CONSUMER,
                name: "asset-input-test",
            },
            |_, tenant, messaging| {
                (
                    asset_inputs::Receiver { messaging },
                    asset_inputs::Validator { tenant },
                )
            },
        )
        .await?;
        let groups = local_delivery::Delivery::open(
            &config,
            protection,
            Arc::default(),
            local_delivery::Lane {
                database: &config.scope_group_database,
                role: "mdm_scope_group_consumer",
                domain: rss_mdm_scope_service::group_changes::DOMAIN,
                consumer: rss_mdm_scope_service::group_changes::CONSUMER,
                name: "group-input-test",
            },
            |runtime, tenant, messaging| {
                (
                    rss_mdm_scope_service::group_changes::Receiver::new(
                        StorageProfile::Mdm,
                        runtime,
                        tenant,
                        messaging,
                    ),
                    rss_mdm_scope_service::group_changes::Validator { tenant },
                )
            },
        )
        .await?;
        let pool = c.inputs.pool("shared", "mdm_scheduler_runtime").await?;
        let timer = rss_mdm_device_service::control::recovery::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        let schedule = rss_reconcile_postgres::PgStore::new(pool.clone(), &control).await?;
        let devices = Arc::new(
            rss_mdm_device_service::worker::DeviceWork::new(
                Arc::new(rss_mdm_device_service::Associations::new(
                    c.audit.clone(),
                    c.tenant,
                    &[7; 32],
                )?),
                c.runtime.clone(),
                schedule.clone(),
                2,
                OperationDeadline::from_remaining(Duration::from_secs(6)),
            )
            .await?,
        );
        let mut stack = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(25))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut startup = stack.startup()?;
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(listener.clone()));
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(
            local_delivery::Resource(assets.clone()),
        ));
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(
            local_delivery::Resource(groups.clone()),
        ));
        let mut launch = startup.commit();
        launch.stage_deferred_task_with_token(listener.registration().critical());
        launch.stage_deferred_task_with_token(
            devices
                .registration(signals.handle(worker_wake::Work::Devices))
                .critical(),
        );
        launch.stage_deferred_task_with_token(
            assets
                .registration(signals.handle(worker_wake::Work::AssetInputs))
                .critical(),
        );
        launch.stage_deferred_task_with_token(
            groups
                .registration(signals.handle(worker_wake::Work::GroupEvents))
                .critical(),
        );
        launch.stage_deferred_task_with_token(
            Arc::new(group::runtime::GroupWork::new(
                owners.groups.clone(),
                schedule.clone(),
            ))
            .registration(signals.handle(worker_wake::Work::Groups))
            .critical(),
        );
        launch.stage_deferred_task_with_token(
            Arc::new(compliance::runtime::ComplianceWork::new(
                owners.compliance.clone(),
                schedule.clone(),
            ))
            .registration(signals.handle(worker_wake::Work::Compliance))
            .critical(),
        );
        launch.stage_deferred_task_with_token(
            Arc::new(rss_mdm_scope_service::runtime::ScopeWork::new(
                scopes, schedule,
            ))
            .registration(signals.handle(worker_wake::Work::Scopes))
            .critical(),
        );
        launch.finish();
        Ok(Self { stack, pool })
    }
    async fn close(self) -> Result<()> {
        anyhow::ensure!(
            self.stack.shutdown().join().await?.is_clean(),
            "worker shutdown failed"
        );
        self.pool.close().await;
        Ok(())
    }
}

async fn definition(c: &Context) -> Result<rss_mdm_inventory::CollectionDefinition> {
    use rss_mdm_inventory::*;
    let field = FieldDefinition {
        time_series: None,
        key: FieldKey::parse("custom.asset.ready")?,
        version: 1,
        value_type: ValueType::Boolean,
        nullable: false,
        manual: false,
        sources: [(Source::MdmWindows, 0)].into(),
        platforms: [Platform::Windows].into(),
        sensitivity: Sensitivity::Standard,
        unit: None,
        searchable: true,
        item_key: None,
    };
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, &field).await?;
    let mut unrelated = field.clone();
    unrelated.key = FieldKey::parse("custom.asset.unrelated")?;
    rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, &unrelated).await?;
    let definition = CollectionDefinition::new(
        "asset-events",
        1,
        Source::MdmWindows,
        vec![
            CollectionField {
                definition: field,
                scope: CollectionScope::Device,
            },
            CollectionField {
                definition: unrelated,
                scope: CollectionScope::Device,
            },
        ],
    )?;
    rss_mdm_inventory_postgres::register_collection_in(&mut tx, c.tenant, &definition).await?;
    tx.commit().await?;
    Ok(definition)
}
async fn inventory(
    c: &Context,
    device: &str,
    definition: &rss_mdm_inventory::CollectionDefinition,
    value: bool,
) -> Result<()> {
    inventory_field(c, device, definition, "custom.asset.ready", value).await
}
async fn inventory_field(
    c: &Context,
    device: &str,
    definition: &rss_mdm_inventory::CollectionDefinition,
    field: &str,
    value: bool,
) -> Result<()> {
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    let epoch:Uuid=sqlx::query_scalar("SELECT epoch FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND device=$2 AND source='mdm.windows'").bind(c.tenant.to_string()).bind(device).fetch_one(&mut *tx).await?;
    let scope = rss_mdm_registration_service::device::scope_dataset(
        StorageProfile::Mdm,
        c.tenant,
        device,
        "mdm.windows",
        epoch,
        "asset-events",
    )?;
    let projection = rss_mdm_inventory_postgres::projection_scope(c.tenant);
    sqlx::query("INSERT INTO mdm.inventory(tenant_id,journal,generation,scope,coverage,field,value,batch_id,observed_at,received_at,state,registration,source,epoch,collection_sequence,field_scope) VALUES($1::uuid,$2,$3,$4,$5,$10,$6,$7,1,1,'known',$8,'mdm.windows',$9,1,'{\"kind\":\"device\"}') ON CONFLICT(tenant_id,journal,generation,scope,field,field_scope) DO UPDATE SET value=excluded.value,batch_id=excluded.batch_id,collection_sequence=mdm.inventory.collection_sequence+1")
        .bind(c.tenant.to_string()).bind(projection.source().source()).bind(projection.generation()).bind(scope.encode()?).bind(serde_json::to_string(&definition.coverage()?)?).bind(serde_json::to_string(&rss_mdm_inventory::Scalar::Boolean(value))?).bind(Uuid::new_v4().to_string()).bind(device).bind(epoch.to_string()).bind(field).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "T2: actual listeners and workers recover committed registration facts, publish Group/Scope and atomically schedule Policy"]
async fn actual_workers_recover_events_and_preserve_entry_without_idle_input_polling() -> Result<()>
{
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[P::InventoryRead, P::GroupRead, P::GroupWrite])
        .await?;
    let proof = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    let scopes = crate::scope_t2::open(&c).await?;
    let id = Uuid::new_v4();
    // Definition submission precedes worker/listener startup; discovery cannot rely on its NOTIFY.
    let definition = definition(&c).await?;
    owners.groups.execute(&group::Command::Group{id,change:Box::new(group::operation::Operation{operation_id:Uuid::new_v4(),expected_revision:0,input:group::GroupChange::Create{presentation:serde_json::from_value(json!({"name":"asset-inputs","description":""}))?,criteria:Some(serde_json::from_value(json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.asset.ready","op":"eq","value":{"kind":"boolean","value":true}}}))?),asset_context:rss_mdm_group::AssetContext::Endpoint}})},&c.request(&proof)?,&proof).await?;
    let scope = super::scope(&c, &[id]).await?;
    let device = planning::endpoint(&c).await?;
    let workers = Workers::start(&c, &owners, scopes.clone()).await?;
    wait_sql(&c,"SELECT member_set IS NOT NULL AND member_count=0 FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",id).await?;
    inventory(&c, &device.members[0].device, &definition, true).await?;
    wait_sql(
        &c,
        "SELECT member_count=1 FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",
        id,
    )
    .await?;
    wait_sql(&c,"SELECT EXISTS(SELECT FROM mdm_scope.scopes s JOIN mdm_scope.scope_channel_results r ON(r.tenant_id,r.run)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND r.channel='mdm' AND r.matched)",scope).await?;
    let (run,entry):(Uuid,i64)=sqlx::query_as("SELECT s.resolution,r.entry_revision FROM mdm_scope.scopes s JOIN mdm_scope.scope_channel_results r ON(r.tenant_id,r.run)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND r.device=$3 AND r.channel='mdm'").bind(c.tenant.to_string()).bind(scope).bind(&device.members[0].device).fetch_one(&c.operator).await?;
    let policy_scheduled:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_policy.work w JOIN rss_reconcile.targets t ON t.tenant_id=w.tenant_id AND t.entity='job:'||w.id::text AND t.reconciler='mdm.policy' WHERE w.tenant_id=$1::uuid AND w.id=$2 AND NOT w.started AND NOT w.completed)").bind(c.tenant.to_string()).bind(run).fetch_one(&c.operator).await?;
    assert!(policy_scheduled);
    wait_sql(&c,"SELECT NOT EXISTS(SELECT FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler IN('mdm.groups','mdm.scopes','mdm.compliance') AND entity='inputs' AND next_run IS NOT NULL) AND EXISTS(SELECT FROM mdm_scope.scopes WHERE tenant_id=$1::uuid AND id=$2 AND resolution IS NOT NULL)",scope).await?;
    let before:Vec<(String,i64)>=sqlx::query_as("SELECT reconciler,wake_version FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler IN('mdm.groups','mdm.scopes','mdm.compliance') AND entity='inputs' ORDER BY reconciler").bind(c.tenant.to_string()).fetch_all(&c.operator).await?;
    tokio::time::sleep(Duration::from_secs(6)).await;
    let after:Vec<(String,i64)>=sqlx::query_as("SELECT reconciler,wake_version FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler IN('mdm.groups','mdm.scopes','mdm.compliance') AND entity='inputs' AND next_run IS NULL ORDER BY reconciler").bind(c.tenant.to_string()).fetch_all(&c.operator).await?;
    assert_eq!(
        after, before,
        "idle input targets must remain converged across the old five-second interval"
    );
    let calculation: i64 = sqlx::query_scalar(
        "SELECT calculation_revision FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .fetch_one(&c.operator)
    .await?;
    inventory_field(
        &c,
        &device.members[0].device,
        &definition,
        "custom.asset.unrelated",
        true,
    )
    .await?;
    settled(&c).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT calculation_revision FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2"
        )
        .bind(c.tenant.to_string())
        .bind(id)
        .fetch_one(&c.operator)
        .await?,
        calculation,
        "unrelated fields must not evaluate this group"
    );
    let work_before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm_policy.work WHERE tenant_id=$1::uuid")
            .bind(c.tenant.to_string())
            .fetch_one(&c.operator)
            .await?;
    inventory(&c, &device.members[0].device, &definition, true).await?;
    settled(&c).await?;
    let work_after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm_policy.work WHERE tenant_id=$1::uuid")
            .bind(c.tenant.to_string())
            .fetch_one(&c.operator)
            .await?;
    assert_eq!(
        work_after, work_before,
        "same facts do not duplicate Policy effects"
    );
    let retained:i64=sqlx::query_scalar("SELECT r.entry_revision FROM mdm_scope.scopes s JOIN mdm_scope.scope_channel_results r ON(r.tenant_id,r.run)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND r.device=$3 AND r.channel='mdm'").bind(c.tenant.to_string()).bind(scope).bind(&device.members[0].device).fetch_one(&c.operator).await?;
    assert_eq!(retained, entry, "continuous membership retains its entry");
    for n in 0..33 {
        let group = Uuid::new_v4();
        owners.groups.execute(&group::Command::Group{id:group,change:Box::new(group::operation::Operation{operation_id:Uuid::new_v4(),expected_revision:0,input:group::GroupChange::Create{presentation:serde_json::from_value(json!({"name":format!("page-{n}"),"description":""}))?,criteria:Some(serde_json::from_value(json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.asset.ready","op":"eq","value":{"kind":"boolean","value":true}}}))?),asset_context:rss_mdm_group::AssetContext::Endpoint}})},&c.request(&proof)?,&proof).await?;
    }
    wait_sql(&c,"SELECT count(*)=34 AND bool_and(member_count=1) AND bool_or(id=$2) FROM mdm_group.groups WHERE tenant_id=$1::uuid AND NOT deleted",id).await?;
    inventory(&c, &device.members[0].device, &definition, false).await?;
    wait_sql(&c,"SELECT count(*)=34 AND bool_and(member_count=0) AND bool_or(id=$2) FROM mdm_group.groups WHERE tenant_id=$1::uuid AND NOT deleted",id).await?;
    wait_sql(&c,"SELECT s.resolution IS NOT NULL AND NOT EXISTS(SELECT FROM mdm_scope.scope_channel_results r WHERE(r.tenant_id,r.run)=(s.tenant_id,s.resolution) AND r.channel='mdm' AND r.matched) FROM mdm_scope.scopes s WHERE s.tenant_id=$1::uuid AND s.id=$2",scope).await?;
    inventory(&c, &device.members[0].device, &definition, true).await?;
    wait_sql(&c,"SELECT EXISTS(SELECT FROM mdm_scope.scopes s JOIN mdm_scope.scope_channel_results r ON(r.tenant_id,r.run)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND r.channel='mdm' AND r.matched)",scope).await?;
    let reentry:i64=sqlx::query_scalar("SELECT r.entry_revision FROM mdm_scope.scopes s JOIN mdm_scope.scope_channel_results r ON(r.tenant_id,r.run)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND r.device=$3 AND r.channel='mdm'").bind(c.tenant.to_string()).bind(scope).bind(&device.members[0].device).fetch_one(&c.operator).await?;
    assert!(
        reentry > entry,
        "actual exit and reentry allocate a new identity"
    );
    workers.close().await?;
    // A committed fact while all listeners are stopped is recovered after reconstruction.
    let mut change = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query(
        "UPDATE mdm_access.credentials SET state='revoked' WHERE tenant_id=$1::uuid AND device=$2",
    )
    .bind(c.tenant.to_string())
    .bind(&device.members[0].device)
    .execute(&mut *change)
    .await?;
    change.commit().await?;
    let workers = Workers::start(&c, &owners, scopes).await?;
    settled(&c).await?;
    let (new_run, matched):(Uuid,bool)=sqlx::query_as("SELECT s.resolution,coalesce(bool_or(r.matched) FILTER(WHERE r.channel='mdm'),false) FROM mdm_scope.scopes s LEFT JOIN mdm_scope.scope_channel_results r ON(r.tenant_id,r.run)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 GROUP BY s.resolution").bind(c.tenant.to_string()).bind(scope).fetch_one(&c.operator).await?;
    assert!(
        !matched,
        "revoked credential must remove MDM qualification after recovery"
    );
    assert_ne!(new_run, run);
    let publication:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_policy.work w JOIN rss_reconcile.targets t ON t.tenant_id=w.tenant_id AND t.entity='job:'||w.id::text AND t.reconciler='mdm.policy' WHERE w.tenant_id=$1::uuid AND w.id=$2)").bind(c.tenant.to_string()).bind(new_run).fetch_one(&c.operator).await?;
    assert!(
        publication,
        "recovered Scope publication must durably schedule its Policy work"
    );
    workers.close().await?;
    drop(owners);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: a static member edit cannot consume a later input without a successor, and Scope merged requests retain coverage"]
async fn coalesced_static_edit_and_scope_request_are_not_acknowledged_by_old_tasks() -> Result<()> {
    use rss_reconcile::{DurableStore, ReconcileStep, Reconciler};
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[P::InventoryRead, P::GroupRead, P::GroupWrite])
        .await?;
    let proof = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    let a = planning::endpoint(&c).await?;
    let b = planning::endpoint(&c).await?;
    let id = owners.create(&c, &proof, None).await?;
    let edit = |device: String| group::Command::Group {
        id,
        change: Box::new(group::operation::Operation {
            operation_id: Uuid::new_v4(),
            expected_revision: 1,
            input: group::GroupChange::Members {
                add: vec![rss_mdm_inventory_service::objects::ObjectRef::Endpoint(
                    device,
                )],
                remove: vec![],
            },
        }),
    };
    let first = owners
        .groups
        .execute(
            &edit(a.members[0].device.clone()),
            &c.request(&proof)?,
            &proof,
        )
        .await?;
    owners
        .settle(
            &c,
            Uuid::parse_str(first["task"].as_str().context("static task")?)?,
        )
        .await?;
    let second = owners
        .groups
        .execute(
            &edit(b.members[0].device.clone()),
            &c.request(&proof)?,
            &proof,
        )
        .await?;
    let task = Uuid::parse_str(second["task"].as_str().context("second static task")?)?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query(
        "UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id=$1::uuid AND device=$2",
    )
    .bind(c.tenant.to_string())
    .bind(&a.members[0].device)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(15), &cancel);
    let pool = c.inputs.pool("shared", "mdm_scheduler_runtime").await?;
    let schedule = rss_reconcile_postgres::PgStore::new(pool.clone(), &control).await?;
    let worker = group::runtime::GroupWork::new(owners.groups.clone(), schedule.clone());
    let target =
        rss_reconcile::Target::new(rss_reconcile::Scope::new(c.tenant, "mdm.groups")?, "inputs")?;
    schedule
        .wake(
            &target,
            &rss_reconcile::ResourceSet::empty(c.tenant),
            &control,
        )
        .await?;
    let mut batch = schedule
        .claim_due(target.scope(), 64, Duration::from_secs(30), &control)
        .await?;
    let position = batch
        .claims
        .iter()
        .position(|claim| claim.target() == &target)
        .context("input claim")?;
    let claim = batch.claims.swap_remove(position);
    for other in batch.claims {
        schedule.release(&other, &control).await?;
    }
    for _ in 0..8 {
        let ReconcileStep::Ready(diff) = worker.observe(&claim, &control).await? else {
            anyhow::bail!("input deferred")
        };
        if diff.drift() == rss_reconcile::DriftKind::Converged {
            break;
        }
        worker.apply(&claim, diff, &control).await?;
    }
    worker
        .finish(&claim, rss_reconcile::Completion::Converged, &control)
        .await?;
    let requested: i64 = sqlx::query_scalar(
        "SELECT input_revision FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .fetch_one(&c.operator)
    .await?;
    assert!(
        requested > 0,
        "the pending manual task must retain the merged asset request"
    );
    owners.settle(&c, task).await?;
    let pending:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND target=$2 AND NOT completed").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
    assert_eq!(
        pending, 1,
        "manual completion must leave exactly one background successor"
    );
    pool.close().await;
    let scopes = crate::scope_t2::open(&c).await?;
    let published = planning::published(&c, &b).await?;
    let staged = planning::staged(&c, &published, &b).await?;
    let binding = rss_mdm_scope_postgres::ScopeBinding::new(
        StorageProfile::Mdm,
        scopes.runtime.clone(),
        c.tenant,
    );
    scopes
        .runtime
        .local_tx_with_context(
            c.tenant,
            OperationDeadline::from_remaining(Duration::from_secs(6)),
            &binding,
            |binding, tx| {
                Box::pin(async move {
                    let merged = binding
                        .enqueue_in(tx, Uuid::new_v4(), published.scope)
                        .await
                        .map_err(|_| {
                            rss_transactional_messaging_postgres::PgError::from(
                                sqlx::Error::Protocol("scope merge".into()),
                            )
                        })?;
                    assert_eq!(merged, staged);
                    Ok(())
                })
            },
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    crate::scope_t2::advance(&scopes, staged, &published.cut, false).await?;
    let pending:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_scope.tasks WHERE tenant_id=$1::uuid AND scope=$2 AND NOT completed AND id<>$3").bind(c.tenant.to_string()).bind(published.scope).bind(staged).fetch_one(&c.operator).await?;
    assert_eq!(
        pending, 1,
        "publishing an older Scope input cannot acknowledge the merged request"
    );
    let workers = Workers::start(&c, &owners, scopes).await?;
    wait_sql(&c,"SELECT NOT EXISTS(SELECT FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND target=$2 AND NOT completed)",id).await?;
    let covered:i64=sqlx::query_scalar("SELECT (j.input->>'covered_inputs')::bigint FROM mdm_group.groups g JOIN mdm_assets.group_tasks j ON(j.tenant_id,j.id)=(g.tenant_id,g.member_set) WHERE g.tenant_id=$1::uuid AND g.id=$2").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
    assert!(covered >= requested);
    workers.close().await?;
    drop(owners);
    c.close().await;
    Ok(())
}

async fn put_rule(
    c: &Context,
    owners: &Owners,
    proof: &AuthorizedPrincipal,
    group: Uuid,
) -> Result<Uuid> {
    let rule = Uuid::new_v4();
    owners.compliance.execute(&compliance::Command::Put { id:rule, request:Box::new(compliance::operation::Operation {
        operation_id:Uuid::new_v4(), expected_revision:0,
        input:serde_json::from_value(json!({"presentation":{"name":"actual-inputs"},"severity":"low","enabled":true,"platform":"all","target":{"kind":"groups","ids":[group]},"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.asset.ready","op":"eq","value":{"kind":"boolean","value":true}}}}))?,
    })}, &c.request(proof)?, proof).await?;
    Ok(rule)
}
async fn rule_status(
    c: &Context,
    owners: &Owners,
    proof: &AuthorizedPrincipal,
    device: &str,
    rule: Uuid,
) -> Result<rss_mdm_compliance::Current> {
    let current = owners
        .compliance
        .execute(
            &compliance::Command::Current {
                device: device.into(),
            },
            &c.request(proof)?,
            proof,
        )
        .await?
        .current()?;
    Ok(current
        .rules
        .into_iter()
        .find(|r| r.rule_id == rule)
        .context("current rule")?
        .status)
}
async fn desired(c: &Context, rule: Uuid) -> Result<Uuid> {
    Ok(sqlx::query_scalar(
        "SELECT desired FROM mdm_compliance.rules WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(rule)
    .fetch_one(&c.operator)
    .await?)
}
async fn members(
    c: &Context,
    owners: &Owners,
    proof: &AuthorizedPrincipal,
    group: Uuid,
    device: &str,
    add: bool,
) -> Result<()> {
    let object = rss_mdm_inventory_service::objects::ObjectRef::Endpoint(device.into());
    owners
        .groups
        .execute(
            &group::Command::Group {
                id: group,
                change: Box::new(group::operation::Operation {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 1,
                    input: group::GroupChange::Members {
                        add: if add { vec![object.clone()] } else { vec![] },
                        remove: if add { vec![] } else { vec![object] },
                    },
                }),
            },
            &c.request(proof)?,
            proof,
        )
        .await?;
    Ok(())
}
#[tokio::test]
#[ignore = "T2: actual Compliance worker preserves unrelated results, retains Unknown candidates and follows Group entry/exit"]
async fn compliance_workers_share_candidate_and_freshness_semantics() -> Result<()> {
    use rss_mdm_compliance::Current;
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[
            P::InventoryRead,
            P::GroupRead,
            P::GroupWrite,
            P::ComplianceRead,
            P::ComplianceWrite,
            P::ComplianceRuleRead,
        ])
        .await?;
    let proof = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    let scopes = crate::scope_t2::open(&c).await?;
    let definition = definition(&c).await?;
    let a = planning::endpoint(&c).await?;
    let b = planning::endpoint(&c).await?;
    let a = &a.members[0].device;
    let b = &b.members[0].device;
    inventory(&c, a, &definition, true).await?;
    inventory(&c, b, &definition, true).await?;
    let fixed = owners.create(&c, &proof, None).await?;
    members(&c, &owners, &proof, fixed, a, true).await?;
    let dynamic = Uuid::new_v4();
    owners.groups.execute(&group::Command::Group{id:dynamic,change:Box::new(group::operation::Operation{operation_id:Uuid::new_v4(),expected_revision:0,input:group::GroupChange::Create{presentation:serde_json::from_value(json!({"name":"unknown-input","description":""}))?,criteria:Some(serde_json::from_value(json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.asset.unrelated","op":"eq","value":{"kind":"boolean","value":true}}}))?),asset_context:rss_mdm_group::AssetContext::Endpoint}})},&c.request(&proof)?,&proof).await?;
    let fixed_rule = put_rule(&c, &owners, &proof, fixed).await?;
    let unknown_rule = put_rule(&c, &owners, &proof, dynamic).await?;
    let workers = Workers::start(&c, &owners, scopes).await?;
    settled(&c).await?;
    assert_eq!(
        rule_status(&c, &owners, &proof, a, fixed_rule).await?,
        Current::Compliant
    );
    assert_eq!(
        rule_status(&c, &owners, &proof, a, unknown_rule).await?,
        Current::Unknown
    );
    let fixed_before = desired(&c, fixed_rule).await?;
    let unknown_before = desired(&c, unknown_rule).await?;
    inventory(&c, b, &definition, false).await?;
    settled(&c).await?;
    assert_eq!(
        desired(&c, fixed_rule).await?,
        fixed_before,
        "outside-target device must not schedule this rule"
    );
    assert_eq!(
        rule_status(&c, &owners, &proof, a, fixed_rule).await?,
        Current::Compliant,
        "outside-target changes must not turn a settled result into Pending"
    );
    assert_ne!(
        desired(&c, unknown_rule).await?,
        unknown_before,
        "Unknown membership remains a candidate even without Group publication"
    );
    inventory(&c, a, &definition, false).await?;
    settled(&c).await?;
    assert_eq!(
        rule_status(&c, &owners, &proof, a, fixed_rule).await?,
        Current::NonCompliant
    );
    let fixed_before = desired(&c, fixed_rule).await?;
    inventory_field(&c, a, &definition, "custom.asset.unrelated", true).await?;
    settled(&c).await?;
    assert_eq!(
        desired(&c, fixed_rule).await?,
        fixed_before,
        "unreferenced field must not schedule this rule"
    );
    assert_eq!(
        rule_status(&c, &owners, &proof, a, unknown_rule).await?,
        Current::NonCompliant,
        "Group completion wakes the previously Unknown assessment"
    );
    members(&c, &owners, &proof, fixed, a, false).await?;
    settled(&c).await?;
    assert_eq!(
        rule_status(&c, &owners, &proof, a, fixed_rule).await?,
        Current::NotApplicable
    );
    members(&c, &owners, &proof, fixed, a, true).await?;
    settled(&c).await?;
    assert_eq!(
        rule_status(&c, &owners, &proof, a, fixed_rule).await?,
        Current::NonCompliant
    );
    workers.close().await?;
    drop(owners);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: input failure survives restart and wake; successful owner settlement repairs every observer"]
async fn input_health_is_durable_across_instances() -> Result<()> {
    use rss_reconcile::DurableStore;
    let c = Context::open("shared", &[]).await?;
    let owners = Owners::open(&c).await?;
    let scopes = crate::scope_t2::open(&c).await?;
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(30), &cancel);
    let pool = c.inputs.pool("shared", "mdm_scheduler_runtime").await?;
    let schedule = rss_reconcile_postgres::PgStore::new(pool.clone(), &control).await?;
    let group = group::runtime::GroupWork::new(owners.groups.clone(), schedule.clone());
    let scope = rss_mdm_scope_service::runtime::ScopeWork::new(scopes.clone(), schedule.clone());
    let compliance =
        compliance::runtime::ComplianceWork::new(owners.compliance.clone(), schedule.clone());
    macro_rules! suspend {
        ($worker:expr,$domain:expr) => {{
            let target = rss_reconcile::Target::new(
                rss_reconcile::Scope::new(c.tenant, $domain)?,
                "inputs",
            )?;
            schedule
                .wake(
                    &target,
                    &rss_reconcile::ResourceSet::empty(c.tenant),
                    &control,
                )
                .await?;
            let mut claims = schedule
                .claim_due(target.scope(), 1, Duration::from_secs(30), &control)
                .await?;
            let claim = claims.claims.pop().context("input claim")?;
            $worker
                .finish(
                    &claim,
                    rss_reconcile::Completion::Suspended { failures: 3 },
                    &control,
                )
                .await?;
            // Wake resets scheduling eligibility, but is not proof of successful business progress.
            schedule
                .wake(
                    &target,
                    &rss_reconcile::ResourceSet::empty(c.tenant),
                    &control,
                )
                .await?;
        }};
    }
    suspend!(group, "mdm.groups");
    suspend!(scope, "mdm.scopes");
    suspend!(compliance, "mdm.compliance");
    let replica = Owners::open(&c).await?;
    let replica_scopes = crate::scope_t2::open(&c).await?;
    assert!(replica.groups.input_failed(Duration::from_secs(6)).await?);
    assert!(
        replica
            .compliance
            .input_failed(Duration::from_secs(6))
            .await?
    );
    assert!(replica_scopes.input_failed(Duration::from_secs(6)).await?);
    let workers = Workers::start(&c, &replica, replica_scopes).await?;
    settled(&c).await?;
    assert!(!owners.groups.input_failed(Duration::from_secs(6)).await?);
    assert!(
        !owners
            .compliance
            .input_failed(Duration::from_secs(6))
            .await?
    );
    assert!(!scopes.input_failed(Duration::from_secs(6)).await?);
    workers.close().await?;
    pool.close().await;
    drop(replica);
    drop(owners);
    c.close().await;
    Ok(())
}
