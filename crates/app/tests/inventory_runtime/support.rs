use super::*;
use crate::device::{DeviceService, VerifiedChannelCredential, test_support::options};
use anyhow::{Result, ensure};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_windows_mdm::{
    CodecLimits, Secret,
    syncml::{self, Command, CommandName, Header, Message, Status},
};
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

fn status(id: u32, command_ref: u32, command: CommandName, code: u16) -> Command {
    Command::Status(Status {
        id,
        message_ref: 1,
        command_ref,
        command,
        code,
        target_refs: vec![],
        source_refs: vec![],
        items: vec![],
        challenge: None,
        credential: None,
    })
}

pub(crate) async fn report(
    service: &DeviceService,
    access: &Database,
    credential: &VerifiedChannelCredential,
    values: [Option<&str>; 2],
) -> Result<Run> {
    report_statuses(
        service,
        access,
        credential,
        values,
        values.map(|value| if value.is_some() { 200 } else { 404 }),
    )
    .await
}

pub(crate) async fn report_statuses(
    service: &DeviceService,
    access: &Database,
    credential: &VerifiedChannelCredential,
    values: [Option<&str>; 2],
    statuses: [u16; 2],
) -> Result<Run> {
    let principal = service.management_principal(credential).await?;
    let store = access
        .audit_store(&crate::config::AuditConfig::Plain)
        .await?;
    let audit = RequestAudit::new(principal.tenant().to_string(), "windows_management");
    audit.registration(principal.registration());
    audit.identify_device(principal.registration());
    audit.target(principal.device());
    let timer = crate::lifecycle::RuntimeTimer;
    let cancel = CancellationToken::new();
    let deadline = rss_request_context::Deadline::from_timeout(&timer, Duration::from_secs(2))?;
    let control = {
        let cutoff = deadline;
        rss_audit_postgres::Control::new(&timer, cutoff, cutoff, &cancel)
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
                    store.append_request(tx, audit, 200, "success").await?;
                    audit.mark_commit_started();
                    Ok::<_, anyhow::Error>((scope, id))
                })
            },
        )
        .await;
    let result = attempt.fold(
        |value| Ok(value.into_value()),
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
        crate::collection::store::collection(&access.inventory(), &scope, Some(id))
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
    let scope = crate::device::store::revalidate(tx, principal).await?;
    let mut request = Message {
        header: Header {
            session_id: 1,
            message_id: 1,
            source: "https://mdm.example/planning".into(),
            target: principal.device().into(),
            credential: None,
            meta: None,
        },
        commands: vec![status(1, 0, CommandName::SyncHdr, 212)],
        final_message: true,
    };
    let id = rss_mdm_windows_channel::test_support::create(tx, &scope, &mut request).await?;
    let previous = String::from_utf8(syncml::encode(&request, &CodecLimits::default())?)?;
    let mut response = Message {
        header: Header {
            message_id: 2,
            source: request.header.target.clone(),
            target: request.header.source.clone(),
            ..request.header.clone()
        },
        commands: vec![status(1, 0, CommandName::SyncHdr, 200)],
        final_message: true,
    };
    for (index, value) in values.iter().enumerate() {
        let Command::Get { id: get, items, .. } = &request.commands[index + 1] else {
            panic!()
        };
        response.commands.push(status(
            index as u32 + 2,
            *get,
            CommandName::Get,
            statuses[index],
        ));
        if let Some(value) = value {
            response.commands.push(Command::Results(syncml::Results {
                id: index as u32 + 10,
                message_ref: Some(1),
                command_ref: Some(*get),
                command: Some(CommandName::Get),
                meta: None,
                items: vec![syncml::Item {
                    source: items[0].target.clone(),
                    target: None,
                    meta: None,
                    data: Some(Secret((*value).into())),
                }],
            }));
        }
    }
    ensure!(
        rss_mdm_windows_channel::test_support::accept(
            tx,
            facts,
            &principal.tenant().to_string(),
            id,
            &response,
            &previous
        )
        .await?
    );
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
            if (!crate::test_support::case::owns_worker() || runtime.readiness.ready())
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
        access.inventory(),
        TenantId::parse(case_a())?,
        clock(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    )
    .await?)
}
