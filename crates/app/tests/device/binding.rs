#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use super::*;
#[tokio::test]
#[ignore = "MODULE=device.binding: real registration state and PostgreSQL"]
async fn bindings_generations_and_competing_credentials() -> anyhow::Result<()> {
    let admin_a = admin(case_a(), "admin-a").await?;
    let admin_b = admin(case_b(), "admin-b").await?;
    let other = admin(case_a(), "other-a").await?;
    let (pool, source, audit) = crate::audit_test_support::request_store().await?;
    let mut access = crate::test_support::runtime::Resources::default();
    access.resource(crate::test_support::runtime::PoolResource(pool.clone()));
    access.resource(crate::test_support::runtime::SourceResource(source));
    let registration = Arc::new(rss_mdm_registration_service::Store::from_pool(
        pool,
        Arc::new(crate::registration_lifecycle::Bridge),
    ));
    let service = DeviceService::new(registration.clone(), case_a().into(), audit.clone());
    let service_b = DeviceService::new(registration, case_b().into(), audit);
    let mut root = PgConnection::connect_with(&options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_a())
        .execute(&mut root)
        .await?;
    let mdm = proof(case_a(), Channel::Mdm, 1);
    let independent = proof(case_a(), Channel::Mdm, 20);
    let (command, first) = bind(
        &service,
        &admin_a,
        &mdm,
        crate::test_support::case::name("same-serial"),
        0,
    )
    .await?;
    let (_, other_channel) = bind(
        &service,
        &admin_a,
        &independent,
        crate::test_support::case::name("independent-native"),
        0,
    )
    .await?;

    let (_, other_tenant) = bind(
        &service_b,
        &admin_b,
        &proof(case_b(), Channel::Mdm, 1),
        crate::test_support::case::name("same-serial"),
        0,
    )
    .await?;
    assert_ne!(first.registration, other_tenant.registration);
    assert!(matches!(
        service
            .authorize_report(&proof(case_b(), Channel::Mdm, 1), ReportSource::MdmWindows)
            .await,
        Err(Error::Forbidden)
    ));
    assert_ne!(first.registration, other_channel.registration);
    assert_eq!(service.bind(&admin_a, &mdm, command.clone()).await?, first);
    for bad in [
        service.bind(&other, &mdm, command.clone()).await,
        service.bind(&admin_b, &mdm, command.clone()).await,
    ] {
        assert!(matches!(bad, Err(Error::Forbidden)));
    }
    assert!(matches!(
        service
            .bind(&admin_a, &proof(case_a(), Channel::Mdm, 9), command.clone())
            .await,
        Err(Error::Conflict)
    ));
    let mut reused = command.clone();
    reused.operation_id = Uuid::new_v4();
    assert!(matches!(
        service.bind(&admin_a, &mdm, reused).await,
        Err(Error::Conflict)
    ));
    eprintln!("device T2: bindings and permission checks passed");
    assert!(matches!(
        service
            .authorize_report(&independent, ReportSource::MdmApple)
            .await,
        Err(Error::Forbidden)
    ));
    // Explicit source permission can be removed independently of an active credential.
    sqlx::query("UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id=$1::uuid AND source='mdm.windows' AND registration=$2").bind(case_a()).bind(first.registration).execute(&mut root)
        .await?;
    assert!(matches!(
        service
            .authorize_report(&mdm, ReportSource::MdmWindows)
            .await,
        Err(Error::Forbidden)
    ));
    sqlx::query("UPDATE mdm_access.report_sources SET enabled=true WHERE tenant_id=$1::uuid AND source='mdm.windows' AND registration=$2").bind(case_a()).bind(first.registration).execute(&mut root)
        .await?;
    let newer = proof(case_a(), Channel::Mdm, 2);
    let (_, second) = bind(
        &service,
        &admin_a,
        &newer,
        crate::test_support::case::name("same-serial"),
        1,
    )
    .await?;
    assert_eq!(second.device, first.device);
    assert_eq!(second.generation, 2);
    assert_ne!(second.epoch, first.epoch);
    assert!(matches!(
        service
            .authorize_report(&mdm, ReportSource::MdmWindows)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(
        service
            .authorize_report(&independent, ReportSource::MdmWindows)
            .await
            .is_ok()
    );
    let current = service
        .current_scope(
            &admin_a,
            crate::test_support::case::name("same-serial"),
            Coordinates {
                source: ReportSource::MdmWindows,
            },
        )
        .await?;
    assert_eq!(
        current.registration().as_str(),
        second.registration.to_string()
    );
    credential_race(&service, &admin_a, &mut root).await?;
    // Two accepted requests racing for the same expected generation cannot silently overwrite.
    let left = BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: service
            .fixture_request(&admin_a, "concurrent", Channel::Mdm)
            .await?,
        expected_generation: 0,
        source: ReportSource::MdmWindows,
    };
    let right = BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: service
            .fixture_request(&admin_a, "concurrent", Channel::Mdm)
            .await?,
        expected_generation: 0,
        source: ReportSource::MdmWindows,
    };
    let p1 = proof(case_a(), Channel::Mdm, 50);
    let p2 = proof(case_a(), Channel::Mdm, 51);
    let mut hold = root.begin().await?;
    rss_mdm_registration_service::device::store::lock_channel(
        &mut hold,
        case_a(),
        "concurrent",
        Channel::Mdm,
    )
    .await?;
    let release = async {
        let observed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let waiting: bool = sqlx::query_scalar("WITH RECURSIVE blocked(pid) AS (SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database()) SELECT count(*)=2 FROM blocked").fetch_one(&mut *hold).await?;
                if waiting { return Ok::<_, sqlx::Error>(()); }
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *hold).await?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await;
        hold.rollback().await?;
        observed.context("generation contenders must overlap")??;
        Ok::<_, anyhow::Error>(())
    };
    let (l, r, released) = tokio::join!(
        service.bind(&admin_a, &p1, left),
        service.bind(&admin_a, &p2, right),
        release
    );
    released?;
    assert_eq!(usize::from(l.is_ok()) + usize::from(r.is_ok()), 1);
    assert!(matches!(l, Err(Error::Conflict)) || matches!(r, Err(Error::Conflict)));
    root.close().await?;
    access.finish(async { Ok(()) }).await?;
    Ok(())
}
// Hold both business rows. The first contender must wait there while the second
// waits on the earlier Audit head; after release exactly one credential bind wins.
async fn credential_race(
    service: &DeviceService,
    admin: &AuthorizedPrincipal,
    root: &mut PgConnection,
) -> anyhow::Result<()> {
    let pa = proof(case_a(), Channel::Mdm, 60);
    let pb = proof(case_a(), Channel::Mdm, 61);
    let (_, a) = bind(
        service,
        admin,
        &pa,
        crate::test_support::case::name("locator-left"),
        0,
    )
    .await?;
    let (_, b) = bind(
        service,
        admin,
        &pb,
        crate::test_support::case::name("locator-right"),
        0,
    )
    .await?;
    let mut commands = Vec::new();
    for device in [&a.device, &b.device] {
        commands.push(BindRegistration {
            operation_id: Uuid::new_v4(),
            request_id: service.fixture_request(admin, device, Channel::Mdm).await?,
            expected_generation: 1,
            source: ReportSource::MdmWindows,
        });
    }
    let mut hold = root.begin().await?;
    sqlx::query("SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id IN ($2::uuid,$3::uuid) FOR UPDATE")
        .bind(case_a()).bind(a.registration.to_string()).bind(b.registration.to_string()).fetch_all(&mut *hold).await?;
    let shared = proof(case_a(), Channel::Mdm, 62);
    let release = async {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let waiting:bool=sqlx::query_scalar("WITH RECURSIVE blocked(pid) AS (SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database()) SELECT count(*)=2 FROM blocked")
                    .fetch_one(&mut *hold).await?;
                if waiting { return Ok::<_, sqlx::Error>(()); }
                // Clear the transaction-local statistics snapshot before the next poll.
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *hold).await?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.context("credential contenders must overlap at the held business locks")??;
        hold.commit().await?;
        Ok::<_, anyhow::Error>(())
    };
    let (left, right, released) = tokio::join!(
        service.bind(admin, &shared, commands[0].clone()),
        service.bind(admin, &shared, commands[1].clone()),
        release
    );
    released?;
    let (winner, loser, old_proof) = match (left, right) {
        (Ok(receipt), Err(Error::Conflict)) => (receipt, b, pb),
        (Err(Error::Conflict), Ok(receipt)) => (receipt, a, pa),
        _ => anyhow::bail!("credential race must have exactly one winner and one conflict"),
    };
    assert_eq!(winner.generation, 2);
    assert_eq!(
        service
            .authorize_report(&shared, ReportSource::MdmWindows)
            .await?
            .0
            .registration(),
        winner.registration
    );
    assert_eq!(
        service
            .authorize_report(&old_proof, ReportSource::MdmWindows)
            .await?
            .0
            .registration(),
        loser.registration
    );
    let generations:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm'")
        .bind(case_a()).bind(&loser.device).fetch_one(&mut *root).await?;
    assert_eq!(generations, 1);
    // Even after revocation the winning locator cannot move to the other device.
    service
        .revoke(admin, &winner.device, winner.registration, Uuid::new_v4())
        .await?;
    let retry = BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: service
            .fixture_request(admin, &loser.device, loser.channel)
            .await?,
        expected_generation: 1,
        source: ReportSource::MdmWindows,
    };
    assert!(matches!(
        service.bind(admin, &shared, retry).await,
        Err(Error::Conflict)
    ));
    assert_eq!(
        service
            .authorize_report(&old_proof, ReportSource::MdmWindows)
            .await?
            .0
            .registration(),
        loser.registration
    );
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=device.binding: current registration communication persistence and fencing"]
async fn communication_is_transactional_and_bound_to_current_registration() -> anyhow::Result<()> {
    use rss_mdm_registration_service::device::{directory::SCHEMA, store::record_communication_in};
    let (access, service, viewer, mut root) = fixture().await?;
    let device = crate::test_support::case::name("communication");
    let credential = proof(case_a(), Channel::Mdm, 71);
    let (_, first) = bind(&service, &viewer, &credential, device, 0).await?;
    let principal = service.management_principal(&credential).await?;
    assert!(
        service.directory_device(&viewer, device).await?.channels[0]
            .last_communication_received_at
            .is_none()
    );
    let mut c = PgConnection::connect_with(&options("mdm_access")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_a())
        .execute(&mut c)
        .await?;
    let mut tx = c.begin().await?;
    record_communication_in(&mut tx, &principal).await?;
    tx.rollback().await?;
    assert!(
        service.directory_device(&viewer, device).await?.channels[0]
            .last_communication_received_at
            .is_none()
    );
    let watermark: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(revision),0) FROM mdm.asset_changes WHERE tenant_id=$1::uuid",
    )
    .bind(case_a())
    .fetch_one(&mut root)
    .await?;
    let mut tx = c.begin().await?;
    record_communication_in(&mut tx, &principal).await?;
    tx.commit().await?;
    c.close().await?;
    let detail = service.directory_device(&viewer, device).await?;
    assert!(
        detail.channels[0]
            .last_communication_received_at
            .is_some_and(|v| v > 0)
    );
    let page = service
        .directory(
            &viewer,
            &SCHEMA.parse("limit=1000")?,
            &rss_mdm_query::cursor::CursorCodec::new(&[7; 32])?,
        )
        .await?;
    assert_eq!(
        serde_json::to_value(&page.items.iter().find(|v| v.id == device).unwrap().channels)?,
        serde_json::to_value(&detail.channels)?
    );
    let unchanged: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(revision),0) FROM mdm.asset_changes WHERE tenant_id=$1::uuid",
    )
    .bind(case_a())
    .fetch_one(&mut root)
    .await?;
    assert_eq!(
        watermark, unchanged,
        "communication must not invalidate asset snapshots"
    );
    // A clock moving backwards must not erase a later persisted receipt.
    sqlx::query("UPDATE mdm_access.registrations SET last_communication_received_at=clock_timestamp()+interval '1 day' WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_a()).bind(first.registration).execute(&mut root).await?;
    let future =
        service.directory_device(&viewer, device).await?.channels[0].last_communication_received_at;
    let mut c = PgConnection::connect_with(&options("mdm_access")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_a())
        .execute(&mut c)
        .await?;
    let mut tx = c.begin().await?;
    record_communication_in(&mut tx, &principal).await?;
    tx.commit().await?;
    assert_eq!(
        service.directory_device(&viewer, device).await?.channels[0].last_communication_received_at,
        future
    );
    let (_, replacement) = bind(
        &service,
        &viewer,
        &proof(case_a(), Channel::Mdm, 72),
        device,
        1,
    )
    .await?;
    let mut tx = c.begin().await?;
    assert!(record_communication_in(&mut tx, &principal).await.is_err());
    tx.rollback().await?;
    let current = service.directory_device(&viewer, device).await?;
    assert_eq!(
        current.channels[0].registration_id.to_string(),
        replacement.registration.to_string()
    );
    assert!(current.channels[0].last_communication_received_at.is_none());
    let hidden = admin(case_b(), "admin-b").await?;
    assert!(service.directory_device(&hidden, device).await.is_err());
    c.close().await?;
    access.finish(async { Ok(()) }).await?;
    Ok(())
}
