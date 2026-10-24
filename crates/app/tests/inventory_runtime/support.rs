use super::*;
use crate::device::{DeviceService, VerifiedChannelCredential, test_support::options};
use anyhow::Result;
use rss_mdm_audit_integration::RequestAudit;
use uuid::Uuid;
fn case_a() -> &'static str {
    crate::test_support::case::tenant()
}
#[allow(
    clippy::disallowed_methods,
    reason = "T2 composition owns the monotonic clock"
)]
pub(super) fn clock() -> Arc<dyn rss_observation::Clock> {
    Arc::new(crate::Monotonic(std::time::Instant::now))
}

pub(crate) async fn report(
    service: &DeviceService,
    store: &rss_mdm_audit_integration::AuditStore,
    credential: &VerifiedChannelCredential,
    values: [Option<&str>; 2],
) -> Result<Run> {
    report_statuses(
        service,
        store,
        credential,
        values,
        values.map(|value| if value.is_some() { 200 } else { 404 }),
    )
    .await
}

pub(crate) async fn report_statuses(
    service: &DeviceService,
    store: &rss_mdm_audit_integration::AuditStore,
    credential: &VerifiedChannelCredential,
    values: [Option<&str>; 2],
    statuses: [u16; 2],
) -> Result<Run> {
    let principal = service.management_principal(credential).await?;
    let audit = RequestAudit::new(principal.tenant().to_string(), "windows_management");
    audit.registration(principal.registration());
    audit.identify_device(principal.registration());
    audit.target(principal.device());
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = CancellationToken::new();
    let deadline = rss_request_context::Deadline::from_timeout(&timer, Duration::from_secs(2))?;
    let control = {
        let cutoff = deadline;
        rss_mdm_audit_integration::budget::SourceControl::new(&timer, cutoff, cutoff, &cancel)
    };
    let attempt = store
        .write(
            principal.tenant(),
            &control,
            (&store, &principal, values, statuses, &audit),
            |(store, principal, values, statuses, audit), tx| {
                Box::pin(async move {
                    let mut facts = Vec::new();
                    let (scope, id) = tx
                        .with_connection_context(
                            &mut (*principal, *values, *statuses, &mut facts),
                            |(principal, values, statuses, facts), c| {
                                Box::pin(report_on(c, principal, *values, *statuses, facts))
                            },
                        )
                        .await?;
                    for fact in &facts {
                        store.append(tx, fact, false).await?;
                    }
                    audit.operation(id, "windows_management");
                    audit.require_request_settlement();
                    audit.mark_commit_started();
                    Ok::<_, anyhow::Error>((scope, id))
                })
            },
        )
        .await;
    let result = attempt.fold(
        Ok,
        |error| Err(anyhow::anyhow!("{error}")),
        |error| Err(anyhow::anyhow!("{error}")),
        |error| Err(anyhow::anyhow!("rollback unconfirmed: {error}")),
        |error| Err(anyhow::anyhow!("commit unconfirmed: {error}")),
        |error| Err(anyhow::anyhow!("{error}")),
    );
    if result.is_ok() {
        audit.mark_committed();
    }
    audit.finalize(
        result
            .as_ref()
            .err()
            .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
    );
    let (scope, id) = result?;
    Ok(
        crate::collection::store::collection(&Arc::new(access.clone()), &scope, Some(id))
            .await?
            .unwrap(),
    )
}

async fn report_on(
    tx: &mut sqlx::PgConnection,
    principal: &crate::device::DevicePrincipal,
    values: [Option<&str>; 2],
    statuses: [u16; 2],
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
) -> Result<(Scope, Uuid)> {
    let scope = crate::device::store::revalidate_source(
        tx,
        principal,
        rss_mdm_inventory::ReportSource::MdmWindows,
    )
    .await?;
    let id = Uuid::new_v4();
    let catalog = rss_mdm_inventory_postgres::catalog_in(tx, principal.tenant()).await?;
    let keys = [
        rss_mdm_inventory::builtin::MODEL,
        rss_mdm_inventory::builtin::OS_VERSION,
    ];
    let definition = rss_mdm_inventory::CollectionDefinition::new(
        "inventory",
        "fixture-template-v1",
        rss_mdm_inventory::Source::MdmWindows,
        keys.iter()
            .map(|k| {
                catalog.definition(*k).cloned().map(|definition| {
                    rss_mdm_inventory::CollectionField {
                        definition,
                        scope: rss_mdm_inventory::CollectionScope::Device,
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let template = rss_mdm_resource::NativeCollectionDefinition::new(
        rss_mdm_resource::NativeCollectionSpec {
            scope: rss_mdm_resource::TemplateScope::Device,
            applicability: Default::default(),
            adapter: rss_mdm_resource::NativeAdapter::WindowsRead,
            mappings: keys
                .iter()
                .zip(["./DevInfo/Mod", "./DevDetail/SwV"])
                .map(|(key, query)| {
                    (
                        key.as_str().into(),
                        rss_mdm_resource::NativeMapping {
                            query: rss_mdm_resource::NativeQuery::Windows(
                                rss_mdm_resource::WindowsRead::Scalar { uri: query.into() },
                            ),
                            mapping: rss_mdm_resource::ValueMapping::identity(""),
                        },
                    )
                })
                .collect(),
            timeout_seconds: 300,
            output_bytes: 1048576,
        },
    )?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await?;
    rss_mdm_inventory_service::collection::native::start(
        tx,
        &rss_mdm_inventory_service::collection::native::Target {
            tenant: principal.tenant(),
            device: principal.device().into(),
            registration: principal.registration(),
            generation: principal.generation(),
        },
        id,
        definition,
        template,
        now + 300,
    )
    .await?;
    let mut run =
        crate::collection::store::load_on(tx, &principal.tenant().to_string(), id).await?;
    for (index, key) in keys.iter().enumerate() {
        run.attempts.observe_status(*key, statuses[index], now)?;
        if let Some(value) = values[index] {
            run.attempts.observe_value(
                *key,
                rss_mdm_inventory::CollectedValue::Value(rss_mdm_inventory::Scalar::String(
                    value.into(),
                )),
                now,
            )?;
        }
    }
    facts.extend(crate::collection::store::seal(tx, &mut run, "complete").await?);
    Ok((scope, id))
}

pub(crate) async fn start(
    runtime: Arc<InventoryRuntime>,
) -> Result<Option<rss_runtime::ShutdownStack>> {
    if !crate::test_support::case::owns_worker() {
        return Ok(None);
    }
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(10))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let notifications = crate::worker_wake::Listener::new(
        crate::device::test_support::options("mdm_access")?,
        rss_request_context::TenantId::parse(case_a())?,
    );
    let signals = notifications.signals.clone();
    let mut startup = owner.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        notifications.clone(),
    ));
    let mut launch = startup.commit();
    launch.stage_task_with_token(notifications.registration().critical());
    launch.stage_deferred_task_with_token(
        runtime
            .registration(signals.handle(crate::worker_wake::Work::Inventory))
            .critical(),
    );
    launch.finish();
    Ok(Some(owner))
}

pub(crate) async fn wait_ready_projection(runtime: &InventoryRuntime, run: &Run) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if (!crate::test_support::case::owns_worker() || runtime.readiness.health().is_ready())
                && runtime.inspect(run).await?.projection
                    == crate::inventory_runtime::ProjectionStatus::Projected
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, Error>(())
    })
    .await??;
    Ok(())
}

pub(super) async fn open(access: Arc<Database>) -> Result<Arc<InventoryRuntime>> {
    Ok(InventoryRuntime::fixture(
        options("mdm_runtime")?,
        Arc::new(access.clone()),
        TenantId::parse(case_a())?,
        clock(),
        access
            .audit_store_fixture(&crate::config::AuditConfig::Plain)
            .await?,
    )
    .await?)
}
