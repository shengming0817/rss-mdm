use super::*;
use crate::{
    audit::Audit,
    collection,
    device::{
        Channel, DeviceService, VerifiedChannelCredential,
        tests::{admin, bind, options, policy, proof},
    },
};
use anyhow::{Result, ensure};
use rss_mdm_windows_mdm::{
    CodecLimits, Secret,
    syncml::{self, Command, CommandName, Header, Message, Status},
};
use rss_observation::Body;
use sqlx::{Connection, Executor, PgConnection};
use uuid::Uuid;
const A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
#[allow(
    clippy::disallowed_methods,
    reason = "T2 composition owns the monotonic clock"
)]
fn clock() -> Arc<dyn rss_observation::Clock> {
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
async fn report(
    service: &DeviceService,
    access: &AccessStore,
    credential: &VerifiedChannelCredential,
    values: [Option<&str>; 2],
) -> Result<Run> {
    let principal = service.management_principal(credential).await?;
    let mut tx = access.begin(A).await?;
    let scope = collection::revalidate(&mut tx, &principal).await?;
    let mut request = Message {
        header: Header {
            session_id: 1,
            message_id: 1,
            source: "https://mdm.example/management".into(),
            target: principal.device().into(),
            credential: None,
            meta: None,
        },
        commands: vec![status(1, 0, CommandName::SyncHdr, 212)],
        final_message: true,
    };
    let id = collection::create(&mut tx, &scope, &mut request).await?;
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
            if value.is_some() { 200 } else { 404 },
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
    ensure!(collection::accept(&mut tx, A, id, &response, &previous).await?);
    let audit = Audit::new(A.into(), "windows_management");
    audit.operation(id, "windows_management");
    audit.registration(principal.registration());
    audit.identify_device(principal.registration());
    audit.target(principal.device());
    access.commit_audited(tx, &audit, None).await?;
    audit.finalize(None);
    Ok(access.collection(&scope, Some(id)).await?.unwrap())
}
async fn start(runtime: Arc<InventoryRuntime>) -> Result<rss_runtime::ShutdownStack> {
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(10))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = owner.startup()?.commit();
    launch.stage_deferred_task_with_token(runtime.registration().critical());
    launch.finish();
    Ok(owner)
}
async fn wait_ready_projection(runtime: &InventoryRuntime, run: &Run) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if runtime.readiness.ready()
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
async fn open(access: Arc<AccessStore>) -> Result<Arc<InventoryRuntime>> {
    Ok(InventoryRuntime::fixture(
        options("mdm_runtime")?,
        access,
        TenantId::parse(A)?,
        clock(),
    )
    .await?)
}

#[test]
fn journal_permission_is_independent_and_readiness_requires_a_running_worker() {
    let tenant = TenantId::parse(A).unwrap();
    let token = CancellationToken::new();
    let authority = JournalAuthority {
        tenant,
        token: &token,
    };
    ensure_authority(&authority, tenant, &token);
    let readiness = Readiness::default();
    readiness.initialized.store(true, Ordering::Release);
    assert!(!readiness.ready());
}
fn ensure_authority(authority: &JournalAuthority<'_>, tenant: TenantId, token: &CancellationToken) {
    assert!(JournalReadGrant::verify(authority, tenant).is_ok());
    assert!(JournalReadGrant::verify(authority, TenantId::parse(B).unwrap()).is_err());
    let scope =
        crate::device::scope(tenant, Uuid::new_v4(), "mdm.windows", Uuid::new_v4()).unwrap();
    assert!(LifecycleGrant::verify(authority, scope.clone()).is_err());
    assert!(ReadGrant::verify(authority, scope).is_err());
    token.cancel();
    assert!(JournalReadGrant::verify(authority, tenant).is_err());
}

#[tokio::test]
#[ignore = "make t2: real PostgreSQL intake, RSS settlement, projection and restart"]
#[allow(
    clippy::cognitive_complexity,
    reason = "sequential fault/restart acceptance matrix"
)]
async fn durable_report_recovery_and_projection() -> Result<()> {
    ensure!(
        cfg!(feature = "integration"),
        "integration feature required"
    );
    let access = Arc::new(AccessStore::connect(options("mdm_access")?).await?);
    let service = Arc::new(DeviceService::new(access.clone(), policy(A, true, true)));
    let admin = admin(A, "admin-a").await?;
    let credential = proof(A, Channel::Mdm, 121);
    let (_, registration) = bind(&service, &admin, &credential, "collection-recovery", 0).await?;
    let first = report(&service, &access, &credential, [Some("First"), Some("10")]).await?;
    // Simulate a corrupt relational coordinate while retaining a valid sealed blob/digest.
    let mut corrupt_root = PgConnection::connect_with(&options("postgres")?).await?;
    corrupt_root
        .execute("ALTER TABLE mdm_access.collection_runs DISABLE TRIGGER immutable_collection")
        .await?;
    let corrupt_epoch = Uuid::new_v4();
    sqlx::query("UPDATE mdm_access.collection_runs SET epoch=$1::uuid WHERE tenant_id=$2::uuid AND id=$3::uuid")
        .bind(corrupt_epoch.to_string()).bind(A).bind(first.id.to_string()).execute(&mut corrupt_root).await?;
    let corrupt_scope = crate::device::scope(
        TenantId::parse(A)?,
        registration.registration,
        "mdm.windows",
        corrupt_epoch,
    )?;
    let read = access.collection(&corrupt_scope, Some(first.id)).await;
    let pending = access.pending_reports(A).await;
    sqlx::query("UPDATE mdm_access.collection_runs SET epoch=$1::uuid WHERE tenant_id=$2::uuid AND id=$3::uuid")
        .bind(first.scope.epoch().as_str()).bind(A).bind(first.id.to_string()).execute(&mut corrupt_root).await?;
    corrupt_root
        .execute("ALTER TABLE mdm_access.collection_runs ENABLE TRIGGER immutable_collection")
        .await?;
    corrupt_root.close().await?;
    ensure!(
        read.is_err() && pending.is_err(),
        "relational scope corruption was accepted"
    );
    let canonical = first.batch().unwrap().encode().to_vec();
    let runtime = open(access.clone()).await?;
    ensure!(runtime.inspect(&first).await?.receipt.is_none());
    let reports = access.pending_reports(A).await?;
    let durable = reports
        .iter()
        .find(|r| r.batch().id().as_str() == first.id.to_string())
        .unwrap();
    // Revoke after durable intake and before any receipt. New input is denied; frozen intake remains.
    let stale = service.management_principal(&credential).await?;
    service
        .revoke(
            &admin,
            "collection-recovery",
            registration.registration,
            Uuid::new_v4(),
        )
        .await?;
    ensure!(service.management_principal(&credential).await.is_err());
    let mut tx = access.begin(A).await?;
    ensure!(collection::revalidate(&mut tx, &stale).await.is_err());
    tx.rollback().await?;
    #[cfg(feature = "integration")]
    {
        let authority = ReportAuthority(durable);
        runtime
            .observation
            .activate(
                &LifecycleGrant::verify(&authority, durable.scope().clone())?,
                None,
                &rss_observation::Policy::new(86400, 3600, 3600)?,
                runtime.clock.deadline(),
            )
            .await?;
        let verified =
            VerifiedBatch::verify(&authority, durable.scope().clone(), durable.batch().clone())?;
        for fault in [
            rss_observation_postgres::Fault::BeforeCommit,
            rss_observation_postgres::Fault::CommitPending,
        ] {
            runtime.observation.inject_next_fault(fault);
            ensure!(
                runtime
                    .observation
                    .receive(&verified, runtime.clock.deadline())
                    .await
                    .is_err()
            );
            ensure!(runtime.inspect(&first).await?.receipt.is_none());
            ensure!(
                access
                    .pending_reports(A)
                    .await?
                    .iter()
                    .any(|r| r.batch().id() == durable.batch().id())
            );
        }
        runtime
            .observation
            .inject_next_fault(rss_observation_postgres::Fault::CommitAckAndReadLost);
        let outcome = runtime
            .observation
            .receive(&verified, runtime.clock.deadline())
            .await
            .unwrap_err();
        ensure!(outcome.kind() == rss_observation::ErrorKind::CommitUnknown);
        ensure!(runtime.inspect(&first).await?.receipt.is_some());
    }
    runtime.deliver(durable, runtime.clock.deadline()).await?;
    let received = runtime.inspect(&first).await?;
    ensure!(
        received.receipt.is_some()
            && received.projection == crate::inventory_runtime::ProjectionStatus::Pending
    );
    ensure!(
        access
            .collection(&first.scope, Some(first.id))
            .await?
            .unwrap()
            .batch()
            .unwrap()
            .encode()
            == canonical
    );
    ensure!(
        access
            .collection(
                &crate::device::scope(
                    TenantId::parse(B)?,
                    registration.registration,
                    "mdm.windows",
                    registration.epoch
                )?,
                Some(first.id)
            )
            .await?
            .is_none()
    );
    // A process restart between receipt and projection uses the original journal and definition.
    runtime.close_fixture().await?;
    let runtime = open(access.clone()).await?;
    let owner = start(runtime.clone()).await?;
    wait_ready_projection(&runtime, &first).await?;
    ensure!(runtime.readiness.ready());
    runtime.readiness.stop();
    ensure!(!runtime.readiness.ready());
    ensure!(owner.shutdown().join().await?.is_clean());
    let reader =
        Arc::new(rss_mdm_inventory_postgres::InventoryReader::connect(options("mdm_api")?).await?);
    ensure!(reader.read(&first.scope).await?[0].value == "First");
    runtime.close_fixture().await?;

    // Fresh epoch; Partial/Failed receipts retain the last complete values.
    let newer = proof(A, Channel::Mdm, 122);
    let (_, registration) = bind(&service, &admin, &newer, "collection-recovery", 1).await?;
    let full = report(&service, &access, &newer, [Some("New"), Some("11")]).await?;
    let partial = report(&service, &access, &newer, [Some("Unconfirmed"), None]).await?;
    let failed = report(&service, &access, &newer, [None, None]).await?;
    ensure!(
        matches!(partial.batch().unwrap().body(), Body::Partial(_))
            && matches!(failed.batch().unwrap().body(), Body::Failed { .. })
    );
    let runtime = open(access.clone()).await?;
    let owner = start(runtime.clone()).await?;
    wait_ready_projection(&runtime, &full).await?;
    ensure!(
        runtime.inspect(&partial).await?.projection
            == crate::inventory_runtime::ProjectionStatus::NotApplicable
    );
    ensure!(
        runtime.inspect(&failed).await?.projection
            == crate::inventory_runtime::ProjectionStatus::NotApplicable
    );
    ensure!(reader.read(&full.scope).await?[0].value == "New");
    ensure!(owner.shutdown().join().await?.is_clean());
    runtime.close_fixture().await?;

    // Deterministically commit/project a newer run between the constituent reads.
    let runtime = open(access.clone()).await?;
    let owner = start(runtime.clone()).await?;
    let inventory = crate::access::InventoryService::new(
        reader.clone(),
        service.clone(),
        access.clone(),
        runtime.clone(),
    );
    let (latest, fields, _) = inventory
        .read_state(&full.scope, async {
            let newer_run = report(&service, &access, &newer, [Some("New"), Some("11")])
                .await
                .unwrap();
            wait_ready_projection(&runtime, &newer_run).await.unwrap();
        })
        .await?;
    let latest = latest.unwrap();
    ensure!(
        fields
            .iter()
            .all(|field| field.batch_id == latest.id.to_string()),
        "inventory mixed a new projection with an older run"
    );
    ensure!(owner.shutdown().join().await?.is_clean());
    runtime.close_fixture().await?;

    let mut root = PgConnection::connect_with(&options("postgres")?).await?;
    // The role cannot rewrite accepted bytes, reset sequence, or delete collection history.
    let mut tx = access.begin(A).await?;
    ensure!(sqlx::query("UPDATE mdm_access.collection_runs SET batch=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(A).bind(full.id.to_string()).bind(canonical).execute(&mut *tx).await.is_err());
    tx.rollback().await?;
    let mut tx = access.begin(A).await?;
    ensure!(
        sqlx::query("DELETE FROM mdm_access.collection_runs")
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await?;

    // Stop after Inventory writes but before its projection transaction commits. Restart replays.
    let broken = report(
        &service,
        &access,
        &newer,
        [Some("After-failure"), Some("12")],
    )
    .await?;
    root.execute("CREATE FUNCTION mdm.reject_inventory_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; REVOKE ALL ON FUNCTION mdm.reject_inventory_test() FROM PUBLIC; CREATE TRIGGER reject_inventory_test AFTER INSERT ON mdm.inventory FOR EACH ROW EXECUTE FUNCTION mdm.reject_inventory_test()").await?;
    let runtime = open(access.clone()).await?;
    let owner = start(runtime.clone()).await?;
    let stopped = tokio::time::timeout(
        Duration::from_secs(8),
        runtime.readiness.task.get().unwrap().wait_stopped(),
    )
    .await?;
    ensure!(matches!(stopped, rss_runtime::TaskExit::Failed(_)) && !runtime.readiness.ready());
    ensure!(!owner.shutdown().join().await?.is_clean());
    ensure!(reader.read(&full.scope).await?[0].value == "New");
    ensure!(
        runtime.inspect(&broken).await?.projection
            == crate::inventory_runtime::ProjectionStatus::Pending
    );
    runtime.close_fixture().await?;
    root.execute("DROP TRIGGER reject_inventory_test ON mdm.inventory; DROP FUNCTION mdm.reject_inventory_test()").await?;
    let runtime = open(access.clone()).await?;
    let owner = start(runtime.clone()).await?;
    wait_ready_projection(&runtime, &broken).await?;
    ensure!(reader.read(&full.scope).await?[0].value == "After-failure");
    ensure!(owner.shutdown().join().await?.is_clean());

    // Explicit CmdID exhaustion fails without allocating a new run or wrapping to old IDs.
    sqlx::query("UPDATE mdm_access.report_sources SET next_command=4294967296 WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(A).bind(registration.registration.to_string()).execute(&mut root).await?;
    ensure!(
        report(&service, &access, &newer, [Some("wrap"), Some("13")])
            .await
            .is_err()
    );
    runtime.close_fixture().await?;
    reader.close().await;
    root.close().await?;
    access.close().await;
    Ok(())
}
