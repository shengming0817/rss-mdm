//! Actual SQL publishers, local projection and independent owner workers.
use super::*;
use crate::{asset_inputs, local_delivery, worker_wake};
use rss_mdm_install_support::StorageProfile;
use rss_reconcile::Timer as _;
use rss_transactional_messaging::{message::*, policy::OperationDeadline};
use rss_transactional_messaging_postgres::{PgConsumerEffect, PgRuntime};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Duration};

async fn cut(c: &Context) -> Result<rss_mdm_inventory::AssetCut> {
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(6));
    Ok(rss_mdm_inventory_service::assets::cut::capture(&c.audit, c.tenant, &budget).await?)
}
async fn consumer(c: &Context) -> Result<Arc<PgRuntime>> {
    use rss_transactional_messaging::fence::StorageIdentity;
    use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa};
    let db = c.inputs.database(&c.profile, "mdm_asset_ingress_consumer");
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
            StorageIdentity::new(c.inputs.installation.target, c.inputs.installation.lineage)?,
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
                .fetch_optional(&c.operator)
                .await?
                .unwrap_or(false)
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .with_context(|| format!("durable owner failed to converge: {sql}"))??;
    Ok(())
}

// Delivery and scheduling are different barriers. Every owner must consume its
// wake and finish durable work, including Group publication received by Scope.
async fn settled(c: &Context) -> Result<()> {
    wait_sql(c, "SELECT $2::uuid IS NOT NULL AND NOT EXISTS(SELECT FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain IN('mdm-assets','mdm-group') AND status<>'published') AND NOT EXISTS(SELECT FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler IN('mdm.groups','mdm.scopes','mdm.compliance') AND next_run IS NOT NULL) AND NOT EXISTS(SELECT FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND NOT completed) AND NOT EXISTS(SELECT FROM mdm_scope.tasks WHERE tenant_id=$1::uuid AND NOT completed) AND NOT EXISTS(SELECT FROM mdm_scope.group_changes WHERE tenant_id=$1::uuid AND NOT completed) AND NOT EXISTS(SELECT FROM mdm_compliance.runs WHERE tenant_id=$1::uuid AND NOT completed)",Uuid::new_v4()).await
}

async fn deliver_input(
    c: &Context,
    message: &MessageEnvelope<Vec<u8>>,
) -> Result<(Arc<PgRuntime>, asset_inputs::Receiver)> {
    let runtime = consumer(c).await?;
    let receiver = asset_inputs::Receiver {
        messaging: Box::pin(rss_reconcile_postgres::PgMessagingStore::new(
            runtime.clone(),
            c.execution(),
            OperationDeadline::from_remaining(Duration::from_secs(6)),
        ))
        .await?,
    };
    runtime
        .local_tx_with_context(
            c.execution(),
            OperationDeadline::from_remaining(Duration::from_secs(6)),
            (&receiver, message),
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
    Ok((runtime, receiver))
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
        event.identity.device.as_ref(),
        Some(&device.members[0].device)
    );
    assert!(event.identity.registration_epoch.is_some());
    assert!(!String::from_utf8(message.payload().clone())?.contains("locator"));
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain='mdm-assets'").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(
        count, 3,
        "device, credential and source each publish exactly one fact"
    );
    let (runtime, receiver) = deliver_input(&c, &message).await?;
    let before:Vec<(String,String,i64)>=sqlx::query_as("SELECT reconciler,entity,wake_version FROM rss_reconcile.targets WHERE tenant_id=$1::uuid ORDER BY reconciler,entity").bind(c.tenant.to_string()).fetch_all(&c.operator).await?;
    assert_eq!(before.len(), 7);
    let mut lock = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("SELECT 1 FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler='mdm.scopes' AND entity='inputs' FOR UPDATE").bind(c.tenant.to_string()).fetch_one(&mut *lock).await?;
    let attempt = runtime
        .local_tx_with_context(
            c.execution(),
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
    .bind(a.members[0].device.into_uuid())
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
    .bind(b.members[0].device.into_uuid())
    .execute(&mut *early)
    .await?;
    early.commit().await?;
    let middle = cut(&c).await?;
    late.commit().await?;
    let after = cut(&c).await?;
    let reader = rss_mdm_inventory_service::assets::planning::SnapshotReader::bind(
        StorageProfile::Mdm,
        owners.storage.runtime.clone(),
    );
    group::transaction::inspect(
        &owners.storage.runtime,
        c.execution(),
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
    .bind(a.members[0].device.into_uuid())
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
        sqlx::query("UPDATE mdm_access.report_sources SET enabled=$3 WHERE tenant_id=$1::uuid AND device=$2").bind(c.tenant.to_string()).bind(a.members[0].device.into_uuid()).bind(enabled).execute(&mut *batch).await?;
    }
    batch.commit().await?;
    let upper = cut(&c).await?;
    group::transaction::inspect(
        &owners.storage.runtime,
        c.execution(),
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

type AssetDelivery = local_delivery::Delivery<asset_inputs::Receiver, asset_inputs::Validator>;
type GroupDelivery = local_delivery::Delivery<
    rss_mdm_scope_service::group_changes::Receiver,
    rss_mdm_scope_service::group_changes::Validator,
>;
async fn projection_lanes(
    c: &Context,
    config: &crate::config::Config,
) -> Result<(Arc<AssetDelivery>, Arc<GroupDelivery>)> {
    let protection = crate::device_material_support::protection(c)?;
    let assets = local_delivery::Delivery::open(
        config,
        c.database.archive_pool(),
        protection.clone(),
        Arc::default(),
        local_delivery::Lane {
            database: &config.asset_input_database,
            role: "mdm_asset_ingress_consumer",
            domain: asset_inputs::DOMAIN,
            consumer: asset_inputs::CONSUMER,
            name: "asset-input-test",
            scopes: "SELECT * FROM mdm_devices.asset_delivery_scopes($1,$2)",
        },
        |_, binding, messaging| {
            (
                asset_inputs::Receiver { messaging },
                asset_inputs::Validator {
                    storage: binding.storage(),
                },
            )
        },
    )
    .await?;
    let groups = local_delivery::Delivery::open(
        config,
        c.database.archive_pool(),
        protection,
        Arc::default(),
        local_delivery::Lane {
            database: &config.scope_group_database,
            role: "mdm_scope_group_consumer",
            domain: rss_mdm_scope_service::group_changes::DOMAIN,
            consumer: rss_mdm_scope_service::group_changes::CONSUMER,
            name: "group-input-test",
            scopes: "SELECT * FROM mdm_group.delivery_scopes($1,$2)",
        },
        |runtime, binding, messaging| {
            (
                rss_mdm_scope_service::group_changes::Receiver::new(
                    StorageProfile::Mdm,
                    runtime,
                    messaging,
                ),
                rss_mdm_scope_service::group_changes::Validator {
                    storage: binding.storage(),
                },
            )
        },
    )
    .await?;
    Ok((assets, groups))
}

struct Workers {
    stack: rss_runtime::ShutdownStack,
    pool: sqlx::PgPool,
    policy_owner: Option<crate::owner_storage::OwnerRuntime>,
}
impl Workers {
    async fn start(
        c: &Context,
        owners: &Owners,
        scopes: Arc<rss_mdm_scope_service::Scopes>,
    ) -> Result<Self> {
        Self::start_policy(c, owners, scopes, None).await
    }
    async fn start_policy(
        c: &Context,
        owners: &Owners,
        scopes: Arc<rss_mdm_scope_service::Scopes>,
        policy: Option<&crate::policy_configuration_t2::fixture::Fixture>,
    ) -> Result<Self> {
        let mut config: crate::config::Config = serde_json::from_value(
            crate::host_t2_support::configuration(
                &c.inputs,
                &c.profile,
                "127.0.0.1:0".parse()?,
                Uuid::new_v4(),
            )
            .await?,
        )?;
        // Exercise durable owner transitions without waiting through a five-second
        // recovery scan for each page of an already active calculation.
        config.background.scheduling.planning.scan_interval_ms = 1;
        let background = config.background.compile(&config)?;
        let listener = worker_wake::Listener::new(config.access_options()?);
        let signals = listener.signals.clone();
        let (assets, groups) = projection_lanes(c, &config).await?;
        let pool = c.inputs.pool(&c.profile, "mdm_scheduler_runtime").await?;
        let timer = rss_mdm_device_service::control::recovery::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control =
            rss_reconcile::Control::new(&timer, timer.now() + Duration::from_secs(6), &cancel);
        let schedule = rss_mdm_work_page::scheduler::Scheduler::new(pool.clone(), &control).await?;
        let mut policy_owner = None;
        let policy_work = if let Some(fixture) = policy {
            let owner = planning::owner(c, "mdm_policy_runtime").await?;
            let app = crate::assembly::policy::application(
                &background,
                &owner,
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
                fixture.materials.clone(),
                fixture.software.materials.clone(),
                fixture.registration.materials.clone(),
                Vec::new(),
            )
            .await?;
            let work = rss_mdm_policy_service::worker::PolicyWork::new(
                c.database.archive_pool(),
                c.execution().storage(),
                app,
                events,
                schedule.clone(),
            );
            policy_owner = Some(owner);
            Some(rss_mdm_policy_service::worker::Automation::new(work))
        } else {
            None
        };
        let devices = Arc::new(
            rss_mdm_device_service::worker::DeviceWork::new(
                c.database.archive_pool(),
                c.execution(),
                Arc::new(rss_mdm_device_service::Associations::new(
                    c.audit.clone(),
                    &[7; 32],
                )?),
                c.runtime.clone(),
                schedule.clone(),
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
                .registration(
                    background.device,
                    background.device_drain,
                    signals.handle(worker_wake::Work::Devices),
                )
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
            .registration(
                background.group,
                background.planning_drain,
                signals.handle(worker_wake::Work::Groups),
            )
            .critical(),
        );
        launch.stage_deferred_task_with_token(
            Arc::new(compliance::runtime::ComplianceWork::new(
                owners.compliance.clone(),
                schedule.clone(),
            ))
            .registration(
                background.compliance,
                background.planning_drain,
                signals.handle(worker_wake::Work::Compliance),
            )
            .critical(),
        );
        launch.stage_deferred_task_with_token(
            Arc::new(rss_mdm_scope_service::runtime::ScopeWork::new(
                scopes, schedule,
            ))
            .registration(
                background.scope,
                background.planning_drain,
                signals.handle(worker_wake::Work::Scopes),
            )
            .critical(),
        );
        if let Some(fixture) = policy {
            launch.stage_deferred_task_with_token(
                fixture
                    .service
                    .clone()
                    .registration(
                        background.commands,
                        background.commands_drain,
                        Arc::new(
                            rss_mdm_device_service::control::worker_wake::Signals::from_handles([
                                signals.handle(worker_wake::Work::CommandRelay),
                                signals.handle(worker_wake::Work::CommandRecovery),
                            ]),
                        ),
                    )
                    .critical(),
            );
            launch.stage_deferred_task_with_token(
                fixture
                    .software
                    .service
                    .clone()
                    .registration(background.commands, background.commands_drain, Arc::new(
                        rss_mdm_software_service::deployment::worker_wake::Signals::from_handles([
                            signals.handle(worker_wake::Work::CommandRelay),
                            signals.handle(worker_wake::Work::SoftwareRecovery),
                        ]),
                    ))
                    .critical(),
            );
        }
        if let Some(work) = policy_work {
            launch.stage_deferred_task_with_token(
                work.registration(
                    background.policy_events,
                    background.policy,
                    background.policy_drain,
                    signals.policy(),
                )
                .critical(),
            );
        }
        launch.finish();
        Ok(Self {
            stack,
            pool,
            policy_owner,
        })
    }
    async fn close(self) -> Result<()> {
        anyhow::ensure!(
            self.stack.shutdown().join().await?.is_clean(),
            "worker shutdown failed"
        );
        self.pool.close().await;
        if let Some(owner) = self.policy_owner {
            owner.runtime.close().await;
        }
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
    device: &rss_mdm_agent_wire::DeviceId,
    definition: &rss_mdm_inventory::CollectionDefinition,
    value: bool,
) -> Result<()> {
    inventory_field(c, device, definition, "custom.asset.ready", value).await
}
async fn inventory_field(
    c: &Context,
    device: &rss_mdm_agent_wire::DeviceId,
    definition: &rss_mdm_inventory::CollectionDefinition,
    field: &str,
    value: bool,
) -> Result<()> {
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    let epoch:Uuid=sqlx::query_scalar("SELECT epoch FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND device=$2 AND source='mdm.windows'").bind(c.tenant.to_string()).bind(device.into_uuid()).fetch_one(&mut *tx).await?;
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
        .bind(c.tenant.to_string()).bind(projection.source().source()).bind(projection.generation()).bind(scope.encode()?).bind(serde_json::to_string(&definition.coverage()?)?).bind(serde_json::to_string(&rss_mdm_inventory::Scalar::Boolean(value))?).bind(Uuid::new_v4().to_string()).bind(device.into_uuid()).bind(epoch.to_string()).bind(field).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
async fn enqueue_policy_job(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    id: Uuid,
    work: rss_mdm_policy_postgres::work::Work,
) -> Result<()> {
    let deadline = crate::authority_t2_support::deadline();
    let store =
        rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), binding, deadline).await?;
    runtime
        .local_tx_with_context(binding, deadline, (store, work), |(store, work), tx| {
            Box::pin(async move {
                rss_mdm_policy_service::worker::jobs::enqueue_job_in(
                    StorageProfile::Mdm,
                    store,
                    tx,
                    id,
                    work,
                )
                .await
                .map(|_| ())
                .map_err(|e| sqlx::Error::Protocol(format!("{e:?}")).into())
            })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    Ok(())
}

async fn policy_defers_locked_scope(
    c: &Context,
    workers: &Workers,
    scope: Uuid,
    policy: Uuid,
) -> Result<()> {
    let mut held = c.operator.begin().await?;
    sqlx::query("SELECT id FROM mdm_scope.scopes WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
        .bind(c.tenant.to_string())
        .bind(scope)
        .fetch_one(&mut *held)
        .await?;
    let job = Uuid::new_v4();
    enqueue_policy_job(
        workers
            .policy_owner
            .as_ref()
            .context("Policy worker")?
            .runtime
            .clone(),
        c.execution(),
        job,
        rss_mdm_policy_postgres::work::Work::PolicyReconcile { policy },
    )
    .await?;
    let deferred = wait_sql(c,"SELECT epoch>0 AND token IS NULL AND next_run IS NOT NULL AND failures=0 AND result='pending' FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler='mdm.policy' AND entity='job:'||$2::uuid::text",job).await;
    held.rollback().await?;
    deferred?;
    wait_sql(c,"SELECT completed AND failure IS NULL FROM mdm_policy.work WHERE tenant_id=$1::uuid AND id=$2",job).await
}

#[tokio::test]
#[ignore = "T2: actual listeners and workers recover committed registration facts, publish Group/Scope and atomically schedule Policy"]
async fn actual_workers_recover_events_and_preserve_entry_without_idle_input_polling() -> Result<()>
{
    let c = Context::open("planning_workers", &[]).await?;
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
    let policy_fixture = crate::policy_configuration_t2::fixture::Fixture::open(&c).await?;
    let policy = crate::policy_configuration_t2::seed(
        &c,
        scope,
        &device,
        &policy_fixture.resources.protection,
    )
    .await?;
    let mut policy_scope = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("UPDATE mdm_scope.scopes SET policy_id=$3 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string())
        .bind(scope)
        .bind(policy)
        .execute(&mut *policy_scope)
        .await?;
    policy_scope.commit().await?;
    let workers = Workers::start_policy(&c, &owners, scopes.clone(), Some(&policy_fixture)).await?;
    wait_sql(&c,"SELECT member_set IS NOT NULL AND member_count=0 FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",id).await?;
    let idle = wait_sql(&c,"SELECT $2::uuid IS NOT NULL AND NOT EXISTS(SELECT FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND entity IN('inputs','configuration-inputs') AND next_run IS NOT NULL)",id).await;
    if idle.is_err() {
        let targets = sqlx::query_scalar::<_, serde_json::Value>("SELECT coalesce(jsonb_agg(jsonb_build_object('reconciler',reconciler,'entity',entity,'result',result,'failures',failures,'dueInSeconds',extract(epoch FROM next_run-clock_timestamp()),'leaseInSeconds',extract(epoch FROM lease_until-clock_timestamp()))),'[]'::jsonb) FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND next_run IS NOT NULL").bind(c.tenant.to_string()).fetch_one(&c.operator).await;
        eprintln!("input drain targets: {targets:?}");
    }
    idle?;
    let discover = c.database.archive_pool();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let drained:bool = sqlx::query_scalar("SELECT
                NOT EXISTS (SELECT FROM mdm_group.delivery_scopes(NULL,NULL) WHERE tenant_id=$1::uuid)
                AND NOT EXISTS (SELECT FROM mdm_devices.asset_delivery_scopes(NULL,NULL) WHERE tenant_id=$1::uuid)")
                .bind(c.tenant.to_string()).fetch_one(&discover).await?;
            if drained { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_,sqlx::Error>(())
    }).await??;
    let initial_operations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid",
    )
    .bind(c.tenant.to_string())
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(
        initial_operations, 0,
        "idle baseline has no pending configuration command"
    );
    wait_sql(&c,"SELECT EXISTS(SELECT FROM mdm_scope.scopes s JOIN mdm_policy.work w ON(w.tenant_id,w.id)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND w.started AND w.completed)",scope).await?;
    policy_defers_locked_scope(&c, &workers, scope, policy).await?;
    inventory(&c, &device.members[0].device, &definition, true).await?;
    wait_sql(
        &c,
        "SELECT member_count=1 FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",
        id,
    )
    .await?;
    wait_sql(&c,"SELECT EXISTS(SELECT FROM mdm_scope.scopes s JOIN mdm_scope.scope_channel_results r ON(r.tenant_id,r.run)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND r.channel='mdm' AND r.matched)",scope).await?;
    let (run,entry):(Uuid,i64)=sqlx::query_as("SELECT s.resolution,r.entry_revision FROM mdm_scope.scopes s JOIN mdm_scope.scope_channel_results r ON(r.tenant_id,r.run)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND r.device=$3 AND r.channel='mdm'").bind(c.tenant.to_string()).bind(scope).bind(device.members[0].device.into_uuid()).fetch_one(&c.operator).await?;
    wait_sql(&c,"SELECT EXISTS(SELECT FROM mdm_policy.work WHERE tenant_id=$1::uuid AND id=$2 AND started AND completed AND failure IS NULL) AND EXISTS(SELECT FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid)",run).await?;
    let policy_scheduled:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_policy.work w JOIN rss_reconcile.targets t ON t.tenant_id=w.tenant_id AND t.entity='job:'||w.id::text AND t.reconciler='mdm.policy' WHERE w.tenant_id=$1::uuid AND w.id=$2 AND w.started AND w.completed)").bind(c.tenant.to_string()).bind(run).fetch_one(&c.operator).await?;
    assert!(policy_scheduled);
    wait_sql(&c,"SELECT NOT EXISTS(SELECT FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND ((reconciler IN('mdm.groups','mdm.scopes','mdm.compliance','mdm.devices','mdm.commands.v1','mdm.software.deployment.v1') AND entity='inputs') OR (reconciler='mdm.policy' AND entity='configuration-inputs')) AND next_run IS NOT NULL) AND EXISTS(SELECT FROM mdm_scope.scopes WHERE tenant_id=$1::uuid AND id=$2 AND resolution IS NOT NULL)",scope).await?;
    let before:Vec<(String,i64)>=sqlx::query_as("SELECT reconciler,wake_version FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND ((reconciler IN('mdm.groups','mdm.scopes','mdm.compliance','mdm.devices','mdm.commands.v1','mdm.software.deployment.v1') AND entity='inputs') OR (reconciler='mdm.policy' AND entity='configuration-inputs')) ORDER BY reconciler").bind(c.tenant.to_string()).fetch_all(&c.operator).await?;
    tokio::time::sleep(Duration::from_secs(6)).await;
    let after:Vec<(String,i64)>=sqlx::query_as("SELECT reconciler,wake_version FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND ((reconciler IN('mdm.groups','mdm.scopes','mdm.compliance','mdm.devices','mdm.commands.v1','mdm.software.deployment.v1') AND entity='inputs') OR (reconciler='mdm.policy' AND entity='configuration-inputs')) AND next_run IS NULL ORDER BY reconciler").bind(c.tenant.to_string()).fetch_all(&c.operator).await?;
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
    let commands_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid",
    )
    .bind(c.tenant.to_string())
    .fetch_one(&c.operator)
    .await?;
    inventory(&c, &device.members[0].device, &definition, true).await?;
    settled(&c).await?;
    let commands_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid",
    )
    .bind(c.tenant.to_string())
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(
        commands_before, commands_after,
        "same facts do not repeat the actual configuration effect"
    );
    let work_after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm_policy.work WHERE tenant_id=$1::uuid")
            .bind(c.tenant.to_string())
            .fetch_one(&c.operator)
            .await?;
    assert_eq!(
        work_after, work_before,
        "same facts do not duplicate Policy effects"
    );
    let retained:i64=sqlx::query_scalar("SELECT r.entry_revision FROM mdm_scope.scopes s JOIN mdm_scope.scope_channel_results r ON(r.tenant_id,r.run)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND r.device=$3 AND r.channel='mdm'").bind(c.tenant.to_string()).bind(scope).bind(device.members[0].device.into_uuid()).fetch_one(&c.operator).await?;
    assert_eq!(retained, entry, "continuous membership retains its entry");
    workers.close().await?;
    for _ in 0..33 {
        let proof = c.authenticate(&account).await?;
        let candidate=owners.create(&c,&proof,Some(serde_json::from_value(json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.asset.ready","op":"eq","value":{"kind":"boolean","value":true}}}))?)).await?;
        let task:Option<Uuid>=sqlx::query_scalar("SELECT id FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND target=$2 AND NOT completed").bind(c.tenant.to_string()).bind(candidate).fetch_optional(&c.operator).await?;
        if let Some(task) = task {
            owners.settle(&c, task).await?;
        }
    }
    let workers = Workers::start_policy(&c, &owners, scopes.clone(), Some(&policy_fixture)).await?;
    wait_sql(&c,"SELECT count(*)=34 AND bool_and(member_count=1) AND bool_or(id=$2) FROM mdm_group.groups WHERE tenant_id=$1::uuid AND NOT deleted",id).await?;
    inventory(&c, &device.members[0].device, &definition, false).await?;
    let emptied = wait_sql(&c,"SELECT count(*)=34 AND bool_and(member_count=0) AND bool_or(id=$2) FROM mdm_group.groups WHERE tenant_id=$1::uuid AND NOT deleted",id).await;
    if emptied.is_err() {
        let trace: serde_json::Value = sqlx::query_scalar("SELECT jsonb_build_object('groups', (SELECT count(*) FROM mdm_group.groups WHERE tenant_id=$1::uuid AND member_count=0),'dispatch',(SELECT to_jsonb(d) FROM mdm_assets.group_dispatch d WHERE tenant_id=$1::uuid),'pending',(SELECT count(*) FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND NOT completed),'runner',(SELECT jsonb_agg(s) FROM (SELECT reconciler,result,count(*) FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND next_run IS NOT NULL GROUP BY 1,2) s))")
            .bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
        eprintln!("durable group checkpoints: {trace}");
    }
    emptied?;
    wait_sql(&c,"SELECT s.resolution IS NOT NULL AND NOT EXISTS(SELECT FROM mdm_scope.scope_channel_results r WHERE(r.tenant_id,r.run)=(s.tenant_id,s.resolution) AND r.channel='mdm' AND r.matched) FROM mdm_scope.scopes s WHERE s.tenant_id=$1::uuid AND s.id=$2",scope).await?;
    inventory(&c, &device.members[0].device, &definition, true).await?;
    wait_sql(&c,"SELECT EXISTS(SELECT FROM mdm_scope.scopes s JOIN mdm_scope.scope_channel_results r ON(r.tenant_id,r.run)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND r.channel='mdm' AND r.matched)",scope).await?;
    let reentry:i64=sqlx::query_scalar("SELECT r.entry_revision FROM mdm_scope.scopes s JOIN mdm_scope.scope_channel_results r ON(r.tenant_id,r.run)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND r.device=$3 AND r.channel='mdm'").bind(c.tenant.to_string()).bind(scope).bind(device.members[0].device.into_uuid()).fetch_one(&c.operator).await?;
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
    .bind(device.members[0].device.into_uuid())
    .execute(&mut *change)
    .await?;
    change.commit().await?;
    let workers = Workers::start_policy(&c, &owners, scopes, Some(&policy_fixture)).await?;
    settled(&c).await?;
    let (new_run, matched):(Uuid,bool)=sqlx::query_as("SELECT s.resolution,coalesce(bool_or(r.matched) FILTER(WHERE r.channel='mdm'),false) FROM mdm_scope.scopes s LEFT JOIN mdm_scope.scope_channel_results r ON(r.tenant_id,r.run)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 GROUP BY s.resolution").bind(c.tenant.to_string()).bind(scope).fetch_one(&c.operator).await?;
    assert!(
        !matched,
        "revoked credential must remove MDM qualification after recovery"
    );
    assert_ne!(new_run, run);
    let publication:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_policy.work w JOIN rss_reconcile.targets t ON t.tenant_id=w.tenant_id AND t.entity='job:'||w.id::text AND t.reconciler='mdm.policy' WHERE w.tenant_id=$1::uuid AND w.id=$2)").bind(c.tenant.to_string()).bind(new_run).fetch_one(&c.operator).await?;
    wait_sql(&c,"SELECT completed AND failure IS NULL FROM mdm_policy.work WHERE tenant_id=$1::uuid AND id=$2",new_run).await?;
    assert!(
        publication,
        "recovered Scope publication must durably schedule its Policy work"
    );
    workers.close().await?;
    policy_fixture.close().await?;
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
    let edit = |device: rss_mdm_agent_wire::DeviceId, expected_revision| group::Command::Group {
        id,
        change: Box::new(group::operation::Operation {
            operation_id: Uuid::new_v4(),
            expected_revision,
            input: group::GroupChange::Members {
                add: vec![rss_mdm_agent_wire::ObjectRef::Endpoint(device)],
                remove: vec![],
            },
        }),
    };
    let first = owners
        .groups
        .execute(&edit(a.members[0].device, 1), &c.request(&proof)?, &proof)
        .await?;
    owners
        .settle(
            &c,
            Uuid::parse_str(first["task"].as_str().context("static task")?)?,
        )
        .await?;
    let second = owners
        .groups
        .execute(&edit(b.members[0].device, 2), &c.request(&proof)?, &proof)
        .await?;
    let task = Uuid::parse_str(second["task"].as_str().context("second static task")?)?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query(
        "UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id=$1::uuid AND device=$2",
    )
    .bind(c.tenant.to_string())
    .bind(a.members[0].device.into_uuid())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let (event, _) = message(&c).await?;
    let (input_runtime, _) = deliver_input(&c, &event).await?;
    input_runtime.close().await;
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(15), &cancel);
    let pool = c.inputs.pool(&c.profile, "mdm_scheduler_runtime").await?;
    let schedule = rss_mdm_work_page::scheduler::Scheduler::new(pool.clone(), &control).await?;
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
        .claim_due(target.scope(), 64, 64, Duration::from_secs(30), &control)
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
    let binding =
        rss_mdm_scope_postgres::ScopeBinding::new(StorageProfile::Mdm, scopes.runtime.clone());
    scopes
        .runtime
        .local_tx_with_context(
            c.execution(),
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
    crate::scope_t2::advance(c.execution(), &scopes, staged, &published.cut, false).await?;
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
    account: &crate::authority_t2_support::Account,
    group: Uuid,
) -> Result<Uuid> {
    let proof = c.authenticate(account).await?;
    let rule = Uuid::new_v4();
    owners.compliance.execute(&compliance::Command::Put { id:rule, request:Box::new(compliance::operation::Operation {
        operation_id:Uuid::new_v4(), expected_revision:0,
        input:serde_json::from_value(json!({"presentation":{"name":"actual-inputs"},"severity":"low","enabled":true,"platform":"all","target":{"kind":"groups","ids":[group]},"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.asset.ready","op":"eq","value":{"kind":"boolean","value":true}}}}))?,
    })}, &c.request(&proof)?, &proof).await?;
    Ok(rule)
}
async fn rule_status(
    c: &Context,
    owners: &Owners,
    account: &crate::authority_t2_support::Account,
    device: &rss_mdm_agent_wire::DeviceId,
    rule: Uuid,
) -> Result<rss_mdm_compliance::Current> {
    let proof = c.authenticate(account).await?;
    let current = owners
        .compliance
        .execute(
            &compliance::Command::Current { device: *device },
            &c.request(&proof)?,
            &proof,
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
    account: &crate::authority_t2_support::Account,
    group: Uuid,
    device: &rss_mdm_agent_wire::DeviceId,
    add: bool,
) -> Result<()> {
    let proof = c.authenticate(account).await?;
    let revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(group)
    .fetch_one(&c.operator)
    .await?;
    let object = rss_mdm_agent_wire::ObjectRef::Endpoint(device.to_owned());
    owners
        .groups
        .execute(
            &group::Command::Group {
                id: group,
                change: Box::new(group::operation::Operation {
                    operation_id: Uuid::new_v4(),
                    expected_revision: revision as u64,
                    input: group::GroupChange::Members {
                        add: if add { vec![object] } else { vec![] },
                        remove: if add { vec![] } else { vec![object] },
                    },
                }),
            },
            &c.request(&proof)?,
            &proof,
        )
        .await?;
    Ok(())
}
#[tokio::test]
#[ignore = "T2: actual Compliance worker preserves unrelated results, retains Unknown candidates and follows Group entry/exit"]
async fn compliance_workers_share_candidate_and_freshness_semantics() -> Result<()> {
    use rss_mdm_compliance::Current;
    let c = Context::open("planning_workers", &[]).await?;
    let account = c
        .account(&[
            P::InventoryRead,
            P::GroupRead,
            P::GroupWrite,
            P::GroupRecompute,
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
    members(&c, &owners, &account, fixed, a, true).await?;
    let dynamic = Uuid::new_v4();
    owners.groups.execute(&group::Command::Group{id:dynamic,change:Box::new(group::operation::Operation{operation_id:Uuid::new_v4(),expected_revision:0,input:group::GroupChange::Create{presentation:serde_json::from_value(json!({"name":"unknown-input","description":""}))?,criteria:Some(serde_json::from_value(json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"custom.asset.unrelated","op":"eq","value":{"kind":"boolean","value":true}}}))?),asset_context:rss_mdm_group::AssetContext::Endpoint}})},&c.request(&proof)?,&proof).await?;
    let workers = Workers::start(&c, &owners, scopes).await?;
    settled(&c).await?;
    let fixed_rule = put_rule(&c, &owners, &account, fixed).await?;
    let unknown_rule = put_rule(&c, &owners, &account, dynamic).await?;
    settled(&c).await?;
    assert_eq!(
        rule_status(&c, &owners, &account, a, fixed_rule).await?,
        Current::Compliant
    );
    assert_eq!(
        rule_status(&c, &owners, &account, a, unknown_rule).await?,
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
        rule_status(&c, &owners, &account, a, fixed_rule).await?,
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
        rule_status(&c, &owners, &account, a, fixed_rule).await?,
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
        rule_status(&c, &owners, &account, a, unknown_rule).await?,
        Current::NonCompliant,
        "Group completion wakes the previously Unknown assessment"
    );
    members(&c, &owners, &account, fixed, a, false).await?;
    settled(&c).await?;
    assert_eq!(
        rule_status(&c, &owners, &account, a, fixed_rule).await?,
        Current::NotApplicable
    );
    members(&c, &owners, &account, fixed, a, true).await?;
    settled(&c).await?;
    assert_eq!(
        rule_status(&c, &owners, &account, a, fixed_rule).await?,
        Current::NonCompliant
    );
    // A rule revision is semantic even when the complete three-valued membership
    // is unchanged. Dependent Groups must capture the new source definition.
    let proof = c.authenticate(&account).await?;
    let child = Uuid::new_v4();
    owners.groups.execute(&group::Command::Group{id:child,change:Box::new(group::operation::Operation{operation_id:Uuid::new_v4(),expected_revision:0,input:group::GroupChange::Create{
        presentation:serde_json::from_value(json!({"name":"dependent","description":""}))?,
        criteria:Some(serde_json::from_value(json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"group","groupId":dynamic,"op":"member_of"}}))?),
        asset_context:rss_mdm_group::AssetContext::Endpoint,
    }})},&c.request(&proof)?,&proof).await?;
    settled(&c).await?;
    let before_member: i64 = sqlx::query_scalar(
        "SELECT member_version FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(dynamic)
    .fetch_one(&c.operator)
    .await?;
    let before_rule = desired(&c, unknown_rule).await?;
    let proof = c.authenticate(&account).await?;
    owners.groups.execute(&group::Command::Group{id:dynamic,change:Box::new(group::operation::Operation{operation_id:Uuid::new_v4(),expected_revision:1,input:group::GroupChange::Rule{
        criteria:serde_json::from_value(json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"and","children":[{"kind":"predicate","field":"custom.asset.unrelated","op":"eq","value":{"kind":"boolean","value":true}},{"kind":"predicate","field":"custom.asset.ready","op":"eq","value":{"kind":"boolean","value":false}}]}}))?,
    }})},&c.request(&proof)?,&proof).await?;
    settled(&c).await?;
    let after_member: i64 = sqlx::query_scalar(
        "SELECT member_version FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(dynamic)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(
        before_member, after_member,
        "definition changed without a three-valued membership change"
    );
    let sources:serde_json::Value=sqlx::query_scalar("SELECT convert_from(r.input,'UTF8')::jsonb->'sources' FROM mdm_group.groups g JOIN mdm_group.member_runs r ON(r.tenant_id,r.id)=(g.tenant_id,g.member_set) WHERE g.tenant_id=$1::uuid AND g.id=$2").bind(c.tenant.to_string()).bind(child).fetch_one(&c.operator).await?;
    let sources: Vec<rss_mdm_group::GroupSource> = serde_json::from_value(sources)?;
    assert_eq!(
        sources[0].coordinates.definition_version, 2,
        "equal membership still propagates source definition demand"
    );
    assert_ne!(desired(&c, unknown_rule).await?, before_rule);
    let stable = desired(&c, unknown_rule).await?;
    let child_calculation: i64 = sqlx::query_scalar(
        "SELECT calculation_revision FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(child)
    .fetch_one(&c.operator)
    .await?;
    for input in [
        group::GroupChange::Recompute {},
        group::GroupChange::Edit {
            presentation: serde_json::from_value(
                json!({"name":"renamed","description":"presentation only"}),
            )?,
        },
    ] {
        let proof = c.authenticate(&account).await?;
        owners
            .groups
            .execute(
                &group::Command::Group {
                    id: dynamic,
                    change: Box::new(group::operation::Operation {
                        operation_id: Uuid::new_v4(),
                        expected_revision: 2,
                        input,
                    }),
                },
                &c.request(&proof)?,
                &proof,
            )
            .await?;
        settled(&c).await?;
        assert_eq!(
            desired(&c, unknown_rule).await?,
            stable,
            "no new semantic demand"
        );
        assert_eq!(
            rule_status(&c, &owners, &account, a, unknown_rule).await?,
            Current::NonCompliant,
            "a complete frozen assessment survives a new identical calculation and presentation edits"
        );
    }
    let after_child: i64 = sqlx::query_scalar(
        "SELECT calculation_revision FROM mdm_group.groups WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(child)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(
        after_child, child_calculation,
        "presentation and observation alone do not propagate semantic work"
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
    planning::endpoint(&c).await?;
    let (event, _) = message(&c).await?;
    let (input_runtime, _) = deliver_input(&c, &event).await?;
    input_runtime.close().await;
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(30), &cancel);
    let pool = c.inputs.pool(&c.profile, "mdm_scheduler_runtime").await?;
    let schedule = rss_mdm_work_page::scheduler::Scheduler::new(pool.clone(), &control).await?;
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
                .claim_due(target.scope(), 1, 64, Duration::from_secs(30), &control)
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
    let execution = crate::policy_configuration_t2::fixture::Fixture::open(&c).await?;
    suspend!(execution.service.recovery_store(), "mdm.commands.v1");
    suspend!(
        execution.software.service.recovery_store(),
        "mdm.software.deployment.v1"
    );
    assert!(matches!(
        execution.service.health().inputs,
        Some(rss_mdm_recovery_observation::Phase::Failed(_))
    ));
    assert!(matches!(
        execution.software.service.health().inputs,
        Some(rss_mdm_recovery_observation::Phase::Failed(_))
    ));
    let execution_replica = crate::policy_configuration_t2::fixture::Fixture::open(&c).await?;
    let replica = Owners::open(&c).await?;
    let replica_scopes = crate::scope_t2::open(&c).await?;
    assert!(
        replica
            .groups
            .input_failed(c.execution(), Duration::from_secs(6))
            .await?
    );
    assert!(
        replica
            .compliance
            .input_failed(c.execution(), Duration::from_secs(6))
            .await?
    );
    assert!(
        replica_scopes
            .input_failed(c.execution(), Duration::from_secs(6))
            .await?
    );
    let workers =
        Workers::start_policy(&c, &replica, replica_scopes, Some(&execution_replica)).await?;
    settled(&c).await?;
    assert!(
        !owners
            .groups
            .input_failed(c.execution(), Duration::from_secs(6))
            .await?
    );
    assert!(
        !owners
            .compliance
            .input_failed(c.execution(), Duration::from_secs(6))
            .await?
    );
    assert!(
        !scopes
            .input_failed(c.execution(), Duration::from_secs(6))
            .await?
    );
    wait_sql(&c,"SELECT $2::uuid IS NOT NULL AND NOT EXISTS(SELECT FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler IN('mdm.commands.v1','mdm.software.deployment.v1') AND entity='inputs' AND next_run IS NOT NULL)",Uuid::new_v4()).await?;
    let fresh_control =
        rss_reconcile::Control::new(&timer, timer.now() + Duration::from_secs(6), &cancel);
    assert!(
        execution
            .service
            .recovery_store()
            .claim_due(
                &rss_mdm_device_service::control::recovery_scope(c.tenant),
                1,
                64,
                Duration::from_secs(30),
                &fresh_control
            )
            .await?
            .claims
            .is_empty()
    );
    assert!(
        execution
            .software
            .service
            .recovery_store()
            .claim_due(
                &rss_mdm_software_service::deployment::recovery_scope(c.tenant),
                1,
                64,
                Duration::from_secs(30),
                &fresh_control
            )
            .await?
            .claims
            .is_empty()
    );
    let failures: Vec<Option<String>> = sqlx::query_scalar("SELECT failure FROM mdm_devices.control_source_dispatch WHERE tenant_id=$1::uuid UNION ALL SELECT failure FROM mdm_software_deployment.device_source_dispatch WHERE tenant_id=$1::uuid")
        .bind(c.tenant.to_string()).fetch_all(&c.operator).await?;
    assert_eq!(failures, vec![None, None]);
    workers.close().await?;
    execution_replica.close().await?;
    execution.close().await?;
    pool.close().await;
    drop(replica);
    drop(owners);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: Device observer refreshes another instance's durable convergence, but keeps pending and unrelated failures"]
async fn association_health_recovers_after_another_instance_converges() -> Result<()> {
    use rss_reconcile::{Completion, ConvergeAction, DurableStore, ReconcileStep, Reconciler};
    let c = Context::open("shared", &[]).await?;
    let timer = rss_mdm_policy_service::clock::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(30), &cancel);
    let pool = c.inputs.pool(&c.profile, "mdm_scheduler_runtime").await?;
    let schedule = rss_mdm_work_page::scheduler::Scheduler::new(pool.clone(), &control).await?;
    let scope = rss_reconcile::Scope::new(c.tenant, "mdm.devices")?;
    let work = Uuid::new_v4();
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(6));
    let cut = rss_mdm_inventory_service::assets::cut::capture(&c.audit, c.tenant, &budget).await?;
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("INSERT INTO mdm_devices.checkpoints(tenant_id,expected_epoch,from_cut,rebuilding) VALUES($1::uuid,$2,$3,false)")
        .bind(c.tenant.to_string()).bind(c.execution().epoch().get()).bind(cut.to_json()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_devices.association_work(tenant_id,id,expected_epoch,kind,value,requested,completed,watermark) VALUES($1::uuid,$2,$3,'serial','retained-health-proof',1,1,1)")
        .bind(c.tenant.to_string()).bind(work).bind(c.execution().epoch().get()).execute(&mut *tx).await?;
    tx.commit().await?;
    let targets = [
        rss_reconcile::Target::new(scope.clone(), "inputs")?,
        rss_reconcile::Target::new(scope.clone(), format!("work:{work}"))?,
    ];
    let a = Arc::new(rss_mdm_device_service::Associations::new(
        c.audit.clone(),
        &[7; 32],
    )?);
    let worker_a = rss_mdm_device_service::worker::DeviceWork::new(
        c.database.archive_pool(),
        c.execution(),
        a.clone(),
        c.runtime.clone(),
        schedule.clone(),
        OperationDeadline::from_remaining(Duration::from_secs(6)),
    )
    .await?;
    let b = Arc::new(rss_mdm_device_service::Associations::new(
        c.audit.clone(),
        &[7; 32],
    )?);
    let worker_b = rss_mdm_device_service::worker::DeviceWork::new(
        c.database.archive_pool(),
        c.execution(),
        b,
        c.runtime.clone(),
        schedule.clone(),
        OperationDeadline::from_remaining(Duration::from_secs(6)),
    )
    .await?;
    for target in &targets {
        schedule
            .wake(
                target,
                &rss_reconcile::ResourceSet::empty(c.tenant),
                &control,
            )
            .await?;
        let claim = schedule
            .claim_due(&scope, 1, 64, Duration::from_secs(30), &control)
            .await?
            .claims
            .pop()
            .context("seed suspended target")?;
        worker_a
            .finish(&claim, Completion::Suspended { failures: 3 }, &control)
            .await?;
    }
    assert_eq!(a.worker_health().unresolved_attempts, 2);
    for (index, target) in targets.iter().enumerate() {
        schedule
            .wake(
                target,
                &rss_reconcile::ResourceSet::empty(c.tenant),
                &control,
            )
            .await?;
        let claim = worker_b
            .claim_due(&scope, 1, 64, Duration::from_secs(30), &control)
            .await?
            .claims
            .pop()
            .context("replica recovery claim")?;
        assert_eq!(claim.target(), target);
        assert!(
            worker_a
                .claim_due(&scope, 1, 64, Duration::from_secs(30), &control)
                .await?
                .claims
                .is_empty()
        );
        assert_eq!(
            a.worker_health().unresolved_attempts,
            (2 - index) as u64,
            "a wake and in-flight work cannot clear a failure"
        );
        let ReconcileStep::Ready(diff) = worker_b.observe(&claim, &control).await? else {
            anyhow::bail!("recovery observation deferred");
        };
        if diff.converge_action() != ConvergeAction::Noop {
            assert!(matches!(
                worker_b.apply(&claim, diff, &control).await?,
                ReconcileStep::Ready(())
            ));
        }
        let ReconcileStep::Ready(diff) = worker_b.observe(&claim, &control).await? else {
            anyhow::bail!("convergence observation deferred");
        };
        assert_eq!(diff.converge_action(), ConvergeAction::Noop);
        worker_b
            .finish(&claim, Completion::Converged, &control)
            .await?;
        assert!(
            worker_a
                .claim_due(&scope, 1, 64, Duration::from_secs(30), &control)
                .await?
                .claims
                .is_empty()
        );
        assert_eq!(
            a.worker_health().unresolved_attempts,
            (1 - index) as u64,
            "clear only the recovered target; preserve the other suspended target"
        );
    }
    assert!(a.worker_health().observed);
    assert!(a.worker_health().failure.is_none());
    drop(worker_a);
    drop(worker_b);
    drop(schedule);
    pool.close().await;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: paged association projection emits no partial snapshot; final publication durably wakes consumers without feeding its producer"]
async fn object_publication_waits_for_complete_cut_and_does_not_loop() -> Result<()> {
    use rss_mdm_inventory_service::objects::ObjectReader;
    use rss_reconcile::{Completion, DurableStore, ReconcileStep, Reconciler};
    let c = Context::open("shared", &[]).await?;
    for _ in 0..65 {
        planning::endpoint(&c).await?;
    }
    let pool = c.inputs.pool(&c.profile, "mdm_scheduler_runtime").await?;
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(40), &cancel);
    let schedule = rss_mdm_work_page::scheduler::Scheduler::new(pool.clone(), &control).await?;
    let worker = rss_mdm_device_service::worker::DeviceWork::new(
        c.database.archive_pool(),
        c.execution(),
        Arc::new(rss_mdm_device_service::Associations::new(
            c.audit.clone(),
            &[7; 32],
        )?),
        c.runtime.clone(),
        schedule.clone(),
        OperationDeadline::from_remaining(Duration::from_secs(6)),
    )
    .await?;
    let runtime = consumer(&c).await?;
    let receiver = asset_inputs::Receiver {
        messaging: Box::pin(rss_reconcile_postgres::PgMessagingStore::new(
            runtime.clone(),
            c.execution(),
            OperationDeadline::from_remaining(Duration::from_secs(6)),
        ))
        .await?,
    };
    let (event, _) = message(&c).await?;
    runtime
        .local_tx_with_context(
            c.execution(),
            OperationDeadline::from_remaining(Duration::from_secs(6)),
            (&receiver, &event),
            |(r, e), tx| {
                Box::pin(async move {
                    r.apply(
                        tx,
                        e,
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
    let scope = rss_reconcile::Scope::new(c.tenant, "mdm.devices")?;
    let mut published = false;
    for pass in 0..10 {
        let batch = worker
            .claim_due(&scope, 64, 64, Duration::from_secs(30), &control)
            .await?;
        for claim in batch.claims {
            if claim.target().entity() != "inputs" {
                worker
                    .finish(
                        &claim,
                        Completion::Deferred(Duration::from_secs(30)),
                        &control,
                    )
                    .await?;
                continue;
            }
            let ReconcileStep::Ready(diff) = worker.observe(&claim, &control).await? else {
                anyhow::bail!("input deferred");
            };
            assert!(matches!(
                worker.apply(&claim, diff, &control).await?,
                ReconcileStep::Ready(())
            ));
            worker
                .finish(
                    &claim,
                    Completion::Reobserve(Duration::from_millis(1)),
                    &control,
                )
                .await?;
        }
        let (open,changes,cuts,events):(bool,i64,i64,i64)=sqlx::query_as("SELECT to_cut IS NOT NULL,(SELECT count(*) FROM mdm_devices.object_changes WHERE tenant_id=$1::uuid),(SELECT count(*) FROM mdm_devices.object_cuts WHERE tenant_id=$1::uuid),(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain='mdm-assets' AND envelope->>'route'='object.published') FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
        assert_eq!(
            cuts, events,
            "one event in the same transaction as each complete cut"
        );
        if pass == 0 {
            assert!(open && changes > 0);
            assert_eq!(
                events, 0,
                "partial object rows cannot notify their consumers"
            );
            let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
            assert_eq!(
                rss_mdm_device_service::planning::PlanningObjects
                    .change_head(&mut tx, c.tenant)
                    .await?,
                0
            );
            tx.rollback().await?;
        }
        if !open {
            assert!(events > 0);
            published = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(published);
    let (wire,fingerprint):(serde_json::Value,Vec<u8>)=sqlx::query_as("SELECT envelope,fingerprint FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain='mdm-assets' AND envelope->>'route'='object.published' ORDER BY seq LIMIT 1").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    let event = MessageEnvelope::new(
        MessageId::parse(wire["id"].as_str().unwrap())?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                c.tenant,
                rss_contract::Timepoint::try_from(wire["occurred_at"].as_i64().unwrap())?,
                MessagingDomain::parse(asset_inputs::DOMAIN)?,
                MessageRoute::parse("object.published")?,
                ContractIdentity::new(
                    rss_contract::ContractId::parse("mdm.device.object-published")?,
                    rss_contract::ContractVersion::from_static_major(1),
                    rss_contract::SchemaDigest::parse(wire["schema"].as_str().unwrap())?,
                ),
            ),
            MessageMetadataExtensions::new(None, None, None, BTreeMap::new()),
        ),
        serde_json::from_value::<Vec<u8>>(wire["payload"].clone())?,
    );
    assert_eq!(
        Sha256::digest(event.canonical_bytes()).as_slice(),
        fingerprint
    );
    let payload: rss_mdm_device_service::object_published::ObjectPublished =
        serde_json::from_slice(event.payload())?;
    assert!(payload.valid());
    assert_eq!(payload.message_id(), event.id().as_str());
    let before:Vec<(String,i64)>=sqlx::query_as("SELECT reconciler,wake_version FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND entity IN('inputs','configuration-inputs') ORDER BY reconciler").bind(c.tenant.to_string()).fetch_all(&c.operator).await?;
    runtime
        .local_tx_with_context(
            c.execution(),
            OperationDeadline::from_remaining(Duration::from_secs(6)),
            (&receiver, &event),
            |(r, e), tx| {
                Box::pin(async move {
                    r.apply(
                        tx,
                        e,
                        OperationDeadline::from_remaining(Duration::from_secs(6)),
                    )
                    .await
                    .map_err(|_| {
                        rss_transactional_messaging_postgres::PgError::from(sqlx::Error::Protocol(
                            "publication effect".into(),
                        ))
                    })?;
                    Ok(())
                })
            },
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    let after:Vec<(String,i64)>=sqlx::query_as("SELECT reconciler,wake_version FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND entity IN('inputs','configuration-inputs') ORDER BY reconciler").bind(c.tenant.to_string()).fetch_all(&c.operator).await?;
    assert_eq!(after.len(), 7);
    for ((name, old), (current, new)) in before.iter().zip(&after) {
        assert_eq!(name, current);
        assert_eq!(
            *new,
            *old + if name == "mdm.devices" || name == "mdm.compliance" {
                0
            } else {
                1
            }
        );
    }
    drop(receiver);
    drop(runtime);
    drop(worker);
    drop(schedule);
    pool.close().await;
    c.close().await;
    Ok(())
}

async fn publish_pair(
    c: &Context,
    tenant: rss_request_context::TenantId,
    group: Uuid,
) -> Result<String> {
    use rss_mdm_device_service::object_published::{self, ObjectPublished};
    use rss_mdm_group_postgres::{GroupChangeKind, GroupChanged};
    let id = Uuid::from_bytes(tenant.octets());
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let operation = Uuid::new_v4();
    let g = GroupChanged {
        execution_epoch: 1,
        v: 1,
        kind: GroupChangeKind::Created,
        group_id: group.to_string(),
        operation_id: operation.to_string(),
        group_revision: 1,
        member_version: 0,
        authority_version: 1,
        member_count: 0,
        added: 0,
        removed: 0,
        rule_version: None,
    };
    let object = ObjectPublished {
        execution_epoch: 1,
        v: 1,
        tenant: id,
        history_epoch: Uuid::new_v4(),
        snapshot_id: Uuid::new_v4(),
        through: 1,
    };
    sqlx::query("SELECT rss_transactional_messaging.prepare_outbox_partitions($1)")
        .bind(json!([["mdm-group", group]]))
        .execute(&mut *tx)
        .await?;
    for (domain, route, contract, schema, message, body, partition) in [
        (
            "mdm-group",
            "group.changed",
            "mdm.group.changed",
            rss_mdm_group_postgres::EVENT_SCHEMA,
            format!("group.changed.v1:{operation}"),
            serde_json::to_vec(&g)?,
            Some(PartitionKey::parse(&group.to_string())?),
        ),
        (
            "mdm-assets",
            "object.published",
            "mdm.device.object-published",
            object_published::SCHEMA,
            object.message_id(),
            serde_json::to_vec(&object)?,
            None,
        ),
    ] {
        let envelope = MessageEnvelope::new(
            MessageId::parse(&message)?,
            MessageMetadata::new(
                AuthoredMessageMetadata::new(
                    tenant,
                    rss_contract::Timepoint::try_from(
                        time::OffsetDateTime::now_utc().unix_timestamp(),
                    )?,
                    MessagingDomain::parse(domain)?,
                    MessageRoute::parse(route)?,
                    ContractIdentity::new(
                        rss_contract::ContractId::parse(contract)?,
                        rss_contract::ContractVersion::from_static_major(1),
                        rss_contract::SchemaDigest::parse(&format!(
                            "sha256:{:x}",
                            Sha256::digest(schema.as_bytes())
                        ))?,
                    ),
                ),
                MessageMetadataExtensions::new(None, partition, None, BTreeMap::new()),
            ),
            body,
        );
        let result: String =
            sqlx::query_scalar("SELECT rss_transactional_messaging.append_outbox($1,$2)")
                .bind(envelope.canonical_bytes())
                .bind(json!({"trace":null,"tenant_authority":null}))
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(result, "inserted");
    }
    sqlx::query(
        "SELECT pg_notify('mdm_work','group_events'), pg_notify('mdm_work','asset_inputs')",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(format!("group.changed.v1:{operation}"))
}

#[tokio::test]
#[ignore = "T2: both registered projections cross a 32-binding discovery page while a source row is locked"]
async fn local_delivery_rotates_past_a_locked_first_tenant_and_a_full_page() -> Result<()> {
    use rss_request_context::TenantId;
    let mut tenants = (0..33).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    tenants.sort_unstable();
    let keys = tenants
        .iter()
        .map(|id| TenantId::parse(&id.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let c = Context::open("shared", &keys).await?;
    let (valid, columns, predicate): (bool, String, String) = sqlx::query_as(
        "SELECT i.indisvalid, pg_get_indexdef(i.indexrelid), pg_get_expr(i.indpred,i.indrelid)
         FROM pg_index i WHERE i.indexrelid='rss_transactional_messaging.mdm_local_projection_scopes'::regclass")
        .fetch_one(&c.operator).await?;
    assert!(valid && columns.contains("(domain, tenant_id, claim_epoch)"));
    for value in [
        "mdm-group",
        "mdm-assets",
        "pending",
        "publishing",
        "dead_letter",
    ] {
        assert!(predicate.contains(value), "{predicate}");
    }
    for tenant in &keys {
        publish_pair(&c, *tenant, Uuid::new_v4()).await?;
    }
    let mut held = c.operator.begin().await?;
    // Both claimed effects insert this same tenant's dispatch row. Keep the insert
    // uncommitted so each lane actually waits inside its owner transaction.
    sqlx::query("INSERT INTO mdm_scope.asset_dispatch(tenant_id,expected_epoch) VALUES($1,1)")
        .bind(tenants[0])
        .execute(&mut *held)
        .await?;
    let locked=sqlx::query("SELECT seq FROM rss_transactional_messaging.outbox WHERE tenant_id=ANY($1) AND domain IN ('mdm-assets','mdm-group') FOR UPDATE")
        .bind(&tenants[1..32]).fetch_all(&mut *held).await?;
    assert_eq!(locked.len(), 62);
    let owners = Owners::open(&c).await?;
    let scopes = crate::scope_t2::open(&c).await?;
    let workers = Workers::start(&c, &owners, scopes.clone()).await?;
    let count = |ids: Vec<Uuid>| {
        sqlx::query_scalar::<_,i64>("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=ANY($1) AND domain IN ('mdm-group','mdm-assets') AND status='published'").bind(ids).fetch_one(&c.operator)
    };
    let siblings = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let inflight: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1 AND domain IN ('mdm-assets','mdm-group') AND status='publishing'")
                .bind(tenants[0]).fetch_one(&c.operator).await?;
            if inflight == 2 && count(vec![tenants[32]]).await? == 2 { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(count(tenants[..32].to_vec()).await?, 0);
        Ok::<_, anyhow::Error>(())
    })
    .await;
    held.rollback().await?;
    workers.close().await?;
    siblings??;
    let workers = Workers::start(&c, &owners, scopes.clone()).await?;
    let drained = tokio::time::timeout(Duration::from_secs(15), async {
        while count(tenants.clone()).await? != 66 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    workers.close().await?;
    drained??;
    owners.storage.runtime.close().await;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: registered projections refill beside a locked effect, drain and resume on the same database"]
async fn local_delivery_refills_while_a_group_head_is_in_flight() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let second = Context::open("shared", &[]).await?;
    let late = second.tenant;
    let config = serde_json::from_value(
        crate::host_t2_support::configuration(
            &c.inputs,
            "shared",
            "127.0.0.1:0".parse()?,
            Uuid::new_v4(),
        )
        .await?,
    )?;
    let start = || async {
        let (assets, groups) = projection_lanes(&c, &config).await?;
        let hint = Arc::new(tokio::sync::Notify::new());
        let mut stack = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(25))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let mut startup = stack.startup()?;
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(
            local_delivery::Resource(assets.clone()),
        ));
        startup.stage_resource(rss_runtime::DynManagedResource::new_box(
            local_delivery::Resource(groups.clone()),
        ));
        let mut launch = startup.commit();
        launch.stage_task_with_token(
            assets
                .clone()
                .registration(Arc::new(tokio::sync::Notify::new()))
                .critical(),
        );
        launch.stage_task_with_token(groups.registration(hint.clone()).critical());
        launch.finish();
        Ok::<_, anyhow::Error>((stack, hint, assets))
    };
    planning::endpoint(&c).await?;
    let (asset, _) = message(&c).await?;
    let (seed, _) = deliver_input(&c, &asset).await?;
    seed.close().await;
    planning::endpoint(&second).await?;
    let (third, _) = message(&second).await?;
    let (seed, _) = deliver_input(&second, &third).await?;
    seed.close().await;
    let group = Uuid::new_v4();
    let head = publish_pair(&c, c.tenant, group).await?;
    let tail = publish_pair(&c, c.tenant, group).await?;
    let peer = publish_pair(&c, c.tenant, Uuid::new_v4()).await?;
    let mut lock = c.operator.begin().await?;
    sqlx::query(
        "INSERT INTO mdm_scope.group_changes(tenant_id,event_id,group_id) VALUES($1,$2,$3)",
    )
    .bind(Uuid::from_bytes(c.tenant.octets()))
    .bind(&head)
    .bind(group)
    .execute(&mut *lock)
    .await?;
    // Hold both tenants' Scope targets. The first tenant supplies both routes,
    // the second supplies the third independent head. Each needs a physical
    // connection for its effect after its initial RSS lease renewal.
    // Keep the observation connection independent of both lock holders.
    let barrier = c.inputs.pool(&c.profile, "postgres").await?;
    let mut inputs = barrier.begin().await?;
    let tenant = Uuid::from_bytes(c.tenant.octets());
    let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid() FROM rss_reconcile.targets WHERE tenant_id=$1 AND reconciler='mdm.scopes' AND entity='inputs' FOR UPDATE")
        .bind(tenant).fetch_one(&mut *inputs).await?;
    let late_tenant = Uuid::from_bytes(late.octets());
    sqlx::query("SELECT 1 FROM rss_reconcile.targets WHERE tenant_id=$1 AND reconciler='mdm.scopes' AND entity='inputs' FOR UPDATE")
        .bind(late_tenant).fetch_one(&mut *inputs).await?;
    let object: String = sqlx::query_scalar("SELECT message_id FROM rss_transactional_messaging.outbox WHERE tenant_id=$1 AND domain='mdm-assets' AND envelope->>'route'='object.published' ORDER BY seq LIMIT 1")
        .bind(tenant).fetch_one(&mut *inputs).await?;
    let routes = vec![
        asset.id().as_str().to_owned(),
        object,
        third.id().as_str().to_owned(),
    ];
    sqlx::query("SELECT seq FROM rss_transactional_messaging.outbox WHERE tenant_id=ANY($1) AND domain='mdm-assets' AND message_id<>ALL($2) FOR UPDATE")
        .bind(&[tenant,late_tenant][..]).bind(&routes).fetch_all(&mut *inputs).await?;
    let (stack, hint, assets) = start().await?;
    let tenants = [tenant, late_tenant];
    let blocked = || {
        sqlx::query_as::<_, (i64, i64)>(
            "WITH RECURSIVE blockers(effect, blocker) AS (
            SELECT pid, unnest(pg_blocking_pids(pid)) FROM pg_stat_activity
            WHERE datname=current_database() AND usename='mdm_asset_ingress_consumer'
            UNION SELECT effect, unnest(pg_blocking_pids(blocker)) FROM blockers
          ) SELECT
            (SELECT count(*) FROM rss_transactional_messaging.outbox
                WHERE tenant_id=ANY($1) AND message_id=ANY($2) AND status='publishing'),
            (SELECT count(DISTINCT effect) FROM blockers WHERE blocker=$3)",
        )
        .bind(&tenants[..])
        .bind(&routes)
        .bind(holder)
        .fetch_one(&c.operator)
    };
    tokio::time::timeout(Duration::from_secs(15), async {
        while blocked().await? != (3, 3) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<_, sqlx::Error>(())
    })
    .await
    .context("three real asset effects waiting on Scope targets")??;
    // Same projection and pool used by RSS renewal. With three connections
    // this read cannot complete until an effect releases its lock.
    tokio::time::timeout(Duration::from_secs(1), assets.next_delay(c.execution()))
        .await
        .context("fourth physical connection available while all three effects are held")??;
    assert_eq!(blocked().await?, (3, 3));
    drop(assets);
    inputs.rollback().await?;
    barrier.close().await;
    let status = |id: String| {
        sqlx::query_scalar::<_, String>("SELECT status FROM rss_transactional_messaging.outbox WHERE domain='mdm-group' AND message_id=$1")
            .bind(id).fetch_one(&c.operator)
    };
    let published = |id: String| async move {
        tokio::time::timeout(Duration::from_secs(15), async {
            while status(id.clone()).await? != "published" {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await?
    };
    published(peer.clone()).await?;
    let refill = publish_pair(&c, c.tenant, Uuid::new_v4()).await?;
    let late_event = publish_pair(&c, late, Uuid::new_v4()).await?;
    hint.notify_one();
    published(refill.clone()).await?;
    published(late_event.clone()).await?;
    assert_eq!(status(head.clone()).await?, "publishing");
    assert_eq!(status(tail.clone()).await?, "pending");
    // Root cancellation is synchronous. The registered lane still owns the
    // effect blocked on our INSERT, and the pool lives until its drain joins.
    let drain = stack.shutdown();
    let after_stop = publish_pair(&c, c.tenant, Uuid::new_v4()).await?;
    hint.notify_one();
    lock.rollback().await?;
    assert!(drain.join().await?.is_clean());
    assert_eq!(status(head.clone()).await?, "published");
    assert_eq!(status(tail.clone()).await?, "pending");
    assert_eq!(status(after_stop.clone()).await?, "pending");
    let (restart, _, _) = start().await?;
    published(tail.clone()).await?;
    published(after_stop.clone()).await?;
    assert!(restart.shutdown().join().await?.is_clean());
    let events = [head, tail, peer, refill, late_event, after_stop];
    let confirmed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.outbox o
         JOIN rss_transactional_messaging.inbox i USING (tenant_id,message_id)
         JOIN mdm_scope.group_changes g ON (g.tenant_id,g.event_id)=(o.tenant_id,o.message_id)
         WHERE o.message_id=ANY($1) AND o.status='published' AND i.disposition='succeeded'
           AND i.consumer_group='mdm-scope-group-changes' AND i.fingerprint=o.fingerprint",
    )
    .bind(events.as_slice())
    .fetch_one(&c.operator)
    .await?;
    let assets: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_transactional_messaging.outbox o
        JOIN rss_transactional_messaging.inbox i USING (tenant_id,message_id)
        WHERE o.tenant_id=ANY($1) AND o.message_id=ANY($2) AND i.consumer_group='mdm-asset-inputs'
          AND o.status='published' AND i.disposition='succeeded' AND o.fingerprint=i.fingerprint",
    )
    .bind(&[tenant, late_tenant][..])
    .bind(&routes)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(assets, 3);
    assert_eq!(confirmed, events.len() as i64);
    second.close().await;
    c.close().await;
    Ok(())
}

async fn wait_checkpoint(peer: &Context, receipt: &str) -> Result<()> {
    while !sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(receipt))
        .bind(peer.tenant.to_string())
        .fetch_optional(&peer.operator)
        .await?
        .unwrap_or(false)
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

#[expect(
    clippy::cognitive_complexity,
    reason = "one transaction holds the original attempt through peer admission, receipt and worker shutdown"
)]
async fn peer_advances_during_locked_checkpoint(
    table: &'static str,
    lock: &'static str,
    receipt: &'static str,
) -> Result<()> {
    let first = Context::open("planning_workers", &[]).await?;
    let second = Context::open("planning_workers", &[]).await?;
    let (slow, peer) = if first.tenant.to_string() < second.tenant.to_string() {
        (&first, &second)
    } else {
        (&second, &first)
    };
    let owners = Owners::open(slow).await?;
    let scopes = crate::scope_t2::open(slow).await?;
    let fixture = crate::policy_configuration_t2::fixture::Fixture::open(slow).await?;
    planning::endpoint(slow).await?;
    let (event, _) = message(slow).await?;
    let (runtime, _) = deliver_input(slow, &event).await?;
    runtime.close().await;
    let mut held = slow.operator.begin().await?;
    let blocker: i32 = sqlx::query_scalar(lock)
        .bind(slow.tenant.to_string())
        .fetch_one(&mut *held)
        .await?;
    let workers = Workers::start_policy(slow, &owners, scopes, Some(&fixture)).await?;
    let check = tokio::time::timeout(Duration::from_secs(20), async {
        let attempt =
            crate::authority_t2_support::wait_for_blocked_attempt(&slow.operator, blocker, table)
                .await?;
        // B enters through the normal publisher and production consumer while A holds this exact attempt.
        planning::endpoint(peer).await?;
        wait_checkpoint(peer, receipt).await?;
        anyhow::ensure!(
            crate::authority_t2_support::blocked_attempt(&slow.operator, blocker, table).await?
                == Some(attempt),
            "{table}: peer did not commit before the blocked attempt ended"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await;
    held.rollback().await?;
    workers.close().await?;
    fixture.close().await?;
    first.close().await;
    second.close().await;
    check.with_context(|| format!("owner checkpoint {table}"))?
}

macro_rules! checkpoint_isolation {
    ($test:ident, $table:literal) => {
        #[tokio::test]
        #[ignore = "T2: a late tenant commits while its peer waits on the owner's business checkpoint"]
        async fn $test() -> Result<()> {
            peer_advances_during_locked_checkpoint(
                $table,
                concat!("SELECT pg_backend_pid() FROM ", $table, " WHERE tenant_id=$1::uuid FOR UPDATE"),
                concat!("SELECT from_cut IS NOT NULL OR to_cut IS NOT NULL FROM ", $table, " WHERE tenant_id=$1::uuid"),
            ).await
        }
    }
}
checkpoint_isolation!(
    group_advances_while_a_peer_checkpoint_is_locked,
    "mdm_assets.group_dispatch"
);
checkpoint_isolation!(
    scope_advances_while_a_peer_checkpoint_is_locked,
    "mdm_scope.asset_dispatch"
);
checkpoint_isolation!(
    compliance_advances_while_a_peer_checkpoint_is_locked,
    "mdm_compliance.dispatch"
);
checkpoint_isolation!(
    policy_configuration_advances_while_a_peer_checkpoint_is_locked,
    "mdm_planning.configuration_source_dispatch"
);
checkpoint_isolation!(
    device_association_advances_while_a_peer_checkpoint_is_locked,
    "mdm_devices.checkpoints"
);
checkpoint_isolation!(
    device_control_advances_while_a_peer_checkpoint_is_locked,
    "mdm_devices.control_source_dispatch"
);
checkpoint_isolation!(
    software_recovery_advances_while_a_peer_checkpoint_is_locked,
    "mdm_software_deployment.device_source_dispatch"
);

#[tokio::test]
#[ignore = "T2: a peer asset query finishes while an earlier tenant cannot commit its query run"]
async fn asset_query_commits_during_a_peer_run_lock() -> Result<()> {
    use crate::authority_t2_support::{blocked_attempt, wait_for_blocked_attempt};
    use rss_mdm_inventory_service::assets;
    use rss_reconcile::DurableStore;
    let a = Context::open("shared", &[]).await?;
    let b = Context::open("shared", &[]).await?;
    let fixture = crate::assembly::software_assets_t2::fixture::Fixture::open(&a).await?;
    let mut tasks = Vec::new();
    for c in [&a, &b] {
        let account = c.account(&[P::InventoryRead]).await?;
        let scope = assets::ReadScope::from_proof(&c.authenticate(&account).await?)?;
        let id = Uuid::new_v4();
        let input = json!({"query":{},"scope":scope,"asset_cut":cut(c).await?,"as_of":1700000000});
        let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
        sqlx::query("INSERT INTO mdm_assets.asset_query_runs(tenant_id,id,input,expected_epoch) VALUES($1::uuid,$2,$3,$4)").bind(c.tenant.to_string()).bind(id).bind(input).bind(c.execution().epoch().get()).execute(&mut *tx).await?;
        tx.commit().await?;
        tasks.push(assets::tasks::target(c.tenant, id));
    }
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(60), &cancel);
    let pool = a.inputs.pool("shared", "mdm_scheduler_runtime").await?;
    let schedule = rss_mdm_work_page::scheduler::Scheduler::new(pool.clone(), &control).await?;
    let mut held = a.operator.begin().await?;
    let pid=sqlx::query_scalar("SELECT pg_backend_pid() FROM mdm_assets.asset_query_runs WHERE tenant_id=$1::uuid FOR UPDATE").bind(a.tenant.to_string()).fetch_one(&mut *held).await?;
    schedule
        .wake(
            &tasks[0],
            &rss_reconcile::ResourceSet::empty(a.tenant),
            &control,
        )
        .await?;
    let config: crate::config::Config = serde_json::from_value(
        crate::host_t2_support::configuration(
            &a.inputs,
            "shared",
            "127.0.0.1:0".parse()?,
            Uuid::new_v4(),
        )
        .await?,
    )?;
    let background = config.background.compile(&config)?;
    let notify = Arc::new(tokio::sync::Notify::new());
    let worker = Arc::new(assets::runtime::QueryWork::new(
        fixture.assets,
        schedule.clone(),
    ));
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(25))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    launch.stage_deferred_task_with_token(
        worker
            .registration(
                background.inventory,
                background.planning_drain,
                notify.clone(),
            )
            .critical(),
    );
    launch.finish();
    let statement = "mdm_assets.asset_query_runs";
    let result=async {
        let attempt=wait_for_blocked_attempt(&a.operator,pid,statement).await?;
        schedule.wake(&tasks[1],&rss_reconcile::ResourceSet::empty(b.tenant),&control).await?;
        notify.notify_one();
        wait_sql(&b,"SELECT completed AND failure IS NULL FROM mdm_assets.asset_query_runs WHERE tenant_id=$1::uuid AND id=$2",Uuid::parse_str(tasks[1].entity().strip_prefix("task:").unwrap())?).await?;
        anyhow::ensure!(blocked_attempt(&a.operator,pid,statement).await?==Some(attempt));
        Ok::<_,anyhow::Error>(())
    }.await;
    held.rollback().await?;
    anyhow::ensure!(stack.shutdown().join().await?.is_clean());
    pool.close().await;
    a.close().await;
    b.close().await;
    result
}

#[tokio::test]
#[ignore = "T2: the Policy event worker commits a peer batch while a prior event's final work receipt is locked"]
async fn event_batch_commits_during_a_peer_receipt_lock() -> Result<()> {
    use crate::authority_t2_support::{blocked_attempt, wait_for_blocked_attempt};
    let a = Context::open("planning_workers", &[]).await?;
    let b = Context::open("planning_workers", &[]).await?;
    let owners = Owners::open(&a).await?;
    let scopes = crate::scope_t2::open(&a).await?;
    let fixture = crate::policy_configuration_t2::fixture::Fixture::open(&a).await?;
    let policy = planning::owner(&a, "mdm_policy_runtime").await?;
    let jobs = [
        pending_policy_event(&a, &fixture.resources.protection).await?,
        pending_policy_event(&b, &fixture.resources.protection).await?,
    ];
    let enqueue = |binding, id| {
        enqueue_policy_job(
            policy.runtime.clone(),
            binding,
            id,
            rss_mdm_policy_postgres::work::Work::PolicyEvent { batch: id },
        )
    };
    enqueue(a.execution(), jobs[0]).await?;
    let mut held = a.operator.begin().await?;
    let pid=sqlx::query_scalar("SELECT pg_backend_pid() FROM mdm_policy.work WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(a.tenant.to_string()).bind(jobs[0]).fetch_one(&mut *held).await?;
    let workers = Workers::start_policy(&a, &owners, scopes, Some(&fixture)).await?;
    let check=async {
        let attempt=wait_for_blocked_attempt(&a.operator,pid,"mdm_policy.work").await?;
        enqueue(b.execution(),jobs[1]).await?;
        wait_sql(&b,"SELECT w.completed AND w.failure IS NULL AND m.decision->>'state'='expired' FROM mdm_policy.work w JOIN mdm_policy.event_members m ON (m.tenant_id,m.batch)=(w.tenant_id,w.id) WHERE w.tenant_id=$1::uuid AND w.id=$2",jobs[1]).await?;
        anyhow::ensure!(blocked_attempt(&a.operator,pid,"mdm_policy.work").await?==Some(attempt));
        Ok::<_,anyhow::Error>(())
    }.await;
    held.rollback().await?;
    workers.close().await?;
    fixture.close().await?;
    policy.runtime.close().await;
    b.close().await;
    a.close().await;
    check
}

async fn pending_policy_event(
    c: &Context,
    key: &rss_mdm_native_protection::Protector,
) -> Result<Uuid> {
    let object = planning::endpoint(c).await?;
    let scope = super::scope(c, &[]).await?;
    let policy = crate::policy_configuration_t2::seed(c, scope, &object, key).await?;
    let device = object.members[0].device;
    let id = Uuid::new_v4();
    let account = c.account(&[P::InventoryRead]).await?;
    let actor = c.authenticate(&account).await?.actor();
    let caller = rss_mdm_policy_service::events::Caller::Management { actor };
    let input = rss_mdm_agent_wire::runtime::PolicyEventRequest {
        operation_id: id,
        event: rss_mdm_agent_wire::runtime::PolicyEventName::parse("peer")?,
        source: rss_mdm_agent_wire::runtime::PolicyEventSource::Human,
        execution_context: None,
    };
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_policy.event_batches(tenant_id,id,request,actor,caller,device,input,fingerprint,created_at,deadline) VALUES($1::uuid,$2,$2,$3,$4,$5,$6,$7,1700000000,1700000010)")
        .bind(c.tenant.to_string()).bind(id).bind(serde_json::to_string(&caller)?).bind(serde_json::to_value(caller)?)
        .bind(device.into_uuid()).bind(serde_json::to_value(input)?).bind([17u8;32].as_slice()).execute(&mut *tx).await?;
    let member = sqlx::query("INSERT INTO mdm_policy.event_members(tenant_id,batch,id,policy,revision,version,target,authority,decision) SELECT tenant_id,$2,$3,id,revision,current_version,$5,$6,$7 FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND id=$4")
        .bind(c.tenant.to_string()).bind(id).bind(Uuid::new_v4()).bind(policy).bind(json!({"device":device}))
        .bind(json!({"permissions":[],"retirement_target":null})).bind(json!({"state":"pending"})).execute(&mut *tx).await?;
    anyhow::ensure!(member.rows_affected() == 1);
    tx.commit().await?;
    Ok(id)
}
