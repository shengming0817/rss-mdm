use super::test_support::*;
use super::*;
use crate::device::{
    DeviceService,
    test_support::{admin, bind, options, proof},
};
use anyhow::{Result, ensure};
use rss_mdm_inventory::Channel;
use rss_observation::Body;
use sqlx::{Connection, Executor, PgConnection};
use uuid::Uuid;
fn case_a() -> &'static str {
    crate::test_support::case::tenant()
}
fn case_b() -> &'static str {
    crate::test_support::case::peer()
}

#[tokio::test]
#[ignore = "make t2: real PostgreSQL intake, RSS settlement, projection and restart"]
#[allow(
    clippy::cognitive_complexity,
    reason = "sequential fault/restart acceptance matrix"
)]
async fn durable_report_recovery_and_projection() -> Result<()> {
    if let Some(output) = crate::test_support::process::captured_test(
        concat!(module_path!(), "::durable_report_recovery_and_projection"),
        Duration::from_secs(180),
    )
    .await?
    {
        let diagnostic = String::from_utf8_lossy(&output.stderr)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .any(|event| {
                event["event"] == "mdm_inventory_failure" && event["phase"] == "projection_run"
            });
        ensure!(diagnostic, "worker failure lost safe phase diagnostic");
        return Ok(());
    }
    ensure!(
        cfg!(feature = "integration"),
        "integration feature required"
    );
    let startup_clock = Clock::new(clock());
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let control = Control::new(&startup_clock, startup_clock.cutoff(), &cancelled);
    ensure!(
        ProjectionResource::open(options("mdm_runtime")?, startup_clock.clone(), &control)
            .await
            .is_err()
    );
    let active = CancellationToken::new();
    let expired = Control::new(&startup_clock, Duration::ZERO, &active);
    ensure!(
        ProjectionResource::open(options("mdm_runtime")?, startup_clock.clone(), &expired)
            .await
            .is_err()
    );
    let access = Arc::new(Database::connect(options("mdm_access")?).await?);
    let service = Arc::new(DeviceService::new(
        access.registration(),
        case_a().into(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    ));
    let admin = admin(case_a(), "admin-a").await?;
    let credential = proof(case_a(), Channel::Mdm, 121);
    let (_, registration) = bind(&service, &admin, &credential, "collection-recovery", 0).await?;
    let first = report(&service, &access, &credential, [Some("First"), Some("10")]).await?;
    // Simulate a corrupt relational coordinate while retaining a valid sealed blob/digest.
    let mut corrupt_root = PgConnection::connect_with(&options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_a())
        .execute(&mut corrupt_root)
        .await?;
    corrupt_root
        .execute("ALTER TABLE mdm_access.collection_runs DISABLE TRIGGER immutable_collection")
        .await?;
    let corrupt_epoch = Uuid::new_v4();
    sqlx::query("UPDATE mdm_access.collection_runs SET epoch=$1::uuid WHERE tenant_id=$2::uuid AND id=$3::uuid")
        .bind(corrupt_epoch.to_string()).bind(case_a()).bind(first.id.to_string()).execute(&mut corrupt_root).await?;
    let corrupt_scope = crate::device::scope(
        TenantId::parse(case_a())?,
        registration.registration,
        "mdm.windows",
        corrupt_epoch,
    )?;
    let read =
        crate::collection::store::collection(&access.inventory(), &corrupt_scope, Some(first.id))
            .await;
    let pending = crate::collection::store::Delivery::new(
        access.inventory(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    )
    .pending_reports(case_a())
    .await;
    sqlx::query("UPDATE mdm_access.collection_runs SET epoch=$1::uuid WHERE tenant_id=$2::uuid AND id=$3::uuid")
        .bind(first.scope.epoch().as_str()).bind(case_a()).bind(first.id.to_string()).execute(&mut corrupt_root).await?;
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
    let reports = crate::collection::store::Delivery::new(
        access.inventory(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    )
    .pending_reports(case_a())
    .await?;
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
    let mut tx = access.begin(case_a()).await?;
    ensure!(
        crate::device::store::revalidate(&mut tx, &stale)
            .await
            .is_err()
    );
    tx.rollback().await?;
    #[cfg(feature = "integration")]
    {
        let verified = runtime.fixture_activate(durable).await?;
        for fault in [
            rss_observation_postgres::Fault::BeforeCommit,
            rss_observation_postgres::Fault::CommitPending,
        ] {
            ensure!(runtime.fixture_receive(&verified, fault).await.is_err());
            ensure!(runtime.inspect(&first).await?.receipt.is_none());
            ensure!(
                crate::collection::store::Delivery::new(
                    access.inventory(),
                    access
                        .audit_store(&crate::config::AuditConfig::Plain)
                        .await?
                )
                .pending_reports(case_a())
                .await?
                .iter()
                .any(|r| r.batch().id() == durable.batch().id())
            );
        }
        let outcome = runtime
            .fixture_receive(
                &verified,
                rss_observation_postgres::Fault::CommitAckAndReadLost,
            )
            .await
            .unwrap_err();
        ensure!(outcome.kind() == rss_observation::ErrorKind::CommitUnknown);
        ensure!(runtime.inspect(&first).await?.receipt.is_some());
    }
    runtime.fixture_deliver(durable).await?;
    let received = runtime.inspect(&first).await?;
    ensure!(
        received.receipt.is_some()
            && received.projection == crate::inventory_runtime::ProjectionStatus::Pending
    );
    ensure!(
        crate::collection::store::collection(&access.inventory(), &first.scope, Some(first.id))
            .await?
            .unwrap()
            .batch()
            .unwrap()
            .encode()
            == canonical
    );
    ensure!(
        crate::collection::store::collection(
            &access.inventory(),
            &crate::device::scope(
                TenantId::parse(case_b())?,
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
    ensure!(runtime.readiness.health().is_ready());
    runtime.readiness.stop();
    ensure!(!runtime.readiness.health().is_ready());
    crate::test_support::stop_worker(owner).await?;
    let reader =
        Arc::new(rss_mdm_inventory_postgres::InventoryReader::connect(options("mdm_api")?).await?);
    ensure!(
        reader
            .read(first.scope.tenant(), std::slice::from_ref(&first.scope))
            .await?[0]
            .fact
            .state
            == rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String("First".into()))
    );
    runtime.close_fixture().await?;

    // Fresh epoch; Partial/Failed receipts retain the last complete values.
    let newer = proof(case_a(), Channel::Mdm, 122);
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
    ensure!(
        reader
            .read(full.scope.tenant(), std::slice::from_ref(&full.scope))
            .await?[0]
            .fact
            .state
            == rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String("New".into()))
    );
    crate::test_support::stop_worker(owner).await?;
    runtime.close_fixture().await?;

    // A borrowed repeatable-read snapshot never mixes a concurrently committed projection.
    let runtime = open(access.clone()).await?;
    let owner = start(runtime.clone()).await?;
    let mut connection = PgConnection::connect_with(&options("mdm_api")?).await?;
    let mut snapshot = connection.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *snapshot)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_a())
        .execute(&mut *snapshot)
        .await?;
    let before = rss_mdm_inventory_postgres::read_in(
        &mut snapshot,
        full.scope.tenant(),
        std::slice::from_ref(&full.scope),
    )
    .await?;
    let newer_run = report(&service, &access, &newer, [Some("Newer"), Some("12")]).await?;
    wait_ready_projection(&runtime, &newer_run).await?;
    ensure!(
        before
            == rss_mdm_inventory_postgres::read_in(
                &mut snapshot,
                full.scope.tenant(),
                std::slice::from_ref(&full.scope)
            )
            .await?
    );
    snapshot.commit().await?;
    connection.close().await?;
    ensure!(
        reader
            .read(full.scope.tenant(), std::slice::from_ref(&full.scope))
            .await?
            .iter()
            .all(|f| f.fact.evidence.snapshot_id == newer_run.id.to_string())
    );
    crate::test_support::stop_worker(owner).await?;
    runtime.close_fixture().await?;

    let mut root = PgConnection::connect_with(&options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_a())
        .execute(&mut root)
        .await?;
    // The role cannot rewrite accepted bytes, reset sequence, or delete collection history.
    let mut tx = access.begin(case_a()).await?;
    ensure!(sqlx::query("UPDATE mdm_access.collection_runs SET batch=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid")
        .bind(case_a()).bind(full.id.to_string()).bind(canonical).execute(&mut *tx).await.is_err());
    tx.rollback().await?;
    let mut tx = access.begin(case_a()).await?;
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
    root.execute("CREATE FUNCTION mdm.reject_inventory_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$; REVOKE ALL ON FUNCTION mdm.reject_inventory_test() FROM PUBLIC; CREATE TRIGGER reject_inventory_test AFTER INSERT OR UPDATE ON mdm.inventory FOR EACH ROW EXECUTE FUNCTION mdm.reject_inventory_test()").await?;
    let runtime = open(access.clone()).await?;
    let owner = start(runtime.clone()).await?;
    let stopped =
        tokio::time::timeout(Duration::from_secs(8), runtime.fixture_wait_stopped()).await?;
    ensure!(
        matches!(stopped, rss_runtime::TaskExit::Failed(_))
            && !runtime.readiness.health().is_ready()
    );
    ensure!(
        !owner
            .expect("fault case owns its inventory worker")
            .shutdown()
            .join()
            .await?
            .is_clean()
    );
    ensure!(
        reader
            .read(full.scope.tenant(), std::slice::from_ref(&full.scope))
            .await?[0]
            .fact
            .state
            == rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String("Newer".into()))
    );
    ensure!(
        runtime.inspect(&broken).await?.projection
            == crate::inventory_runtime::ProjectionStatus::Pending
    );
    runtime.close_fixture().await?;
    root.execute("DROP TRIGGER reject_inventory_test ON mdm.inventory; DROP FUNCTION mdm.reject_inventory_test()").await?;
    let runtime = open(access.clone()).await?;
    let owner = start(runtime.clone()).await?;
    wait_ready_projection(&runtime, &broken).await?;
    ensure!(
        reader
            .read(full.scope.tenant(), std::slice::from_ref(&full.scope))
            .await?[0]
            .fact
            .state
            == rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String(
                "After-failure".into()
            ))
    );
    crate::test_support::stop_worker(owner).await?;

    // Explicit CmdID exhaustion fails without allocating a new run or wrapping to old IDs.
    sqlx::query("UPDATE mdm_access.report_sources SET next_command=4294967296 WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(case_a()).bind(registration.registration.to_string()).execute(&mut root).await?;
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

#[tokio::test]
#[ignore = "MODULE=inventory.runtime: pure discovery does not create an Audit or Ledger head"]
async fn empty_discovery_has_no_audit_head() -> Result<()> {
    let database = Arc::new(Database::connect(options("mdm_access")?).await?);
    let audit = database
        .audit_store(&crate::config::AuditConfig::Plain)
        .await?;
    let tenant = Uuid::new_v4().to_string();
    let delivery = crate::collection::store::Delivery::new(database.inventory(), audit);
    ensure!(delivery.pending_reports(&tenant).await?.is_empty());
    let mut tx = database.begin(&tenant).await?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_audit.heads WHERE tenant_id=$1::uuid")
            .bind(&tenant)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(count == 0, "empty discovery created an Audit head");
    tx.rollback().await?;
    database.close().await;
    Ok(())
}
