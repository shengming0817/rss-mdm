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
    assert!(admin(case_b(), "admin-a").await.is_err());
    let access = Arc::new(
        Database::connect(options("mdm_access")?)
            .await
            .context("access store admission")?,
    );
    let service = DeviceService::new(
        access.registration(),
        case_a().into(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    );
    let service_b = DeviceService::new(
        access.registration(),
        case_b().into(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    );
    let mut root = PgConnection::connect_with(&options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_a())
        .execute(&mut root)
        .await?;
    let mdm = proof(case_a(), Channel::Mdm, 1);
    let agent = proof(case_a(), Channel::Agent, 1);
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
        &agent,
        crate::test_support::case::name("same-serial"),
        0,
    )
    .await?;
    sqlx::query("INSERT INTO mdm_agent.bindings(tenant_id,registration,wire_version,capabilities,platform,architecture,execution_context) VALUES($1::uuid,$2::uuid,6,'[\"inventory.collect.v6\"]','macos','aarch64',$3::jsonb)")
        .bind(case_a())
        .bind(other_channel.registration.to_string()).bind(serde_json::json!({"revision":1,"osVersion":[14,0,0,0],"systemBroker":true,"interactiveUser":null,"sourceCredentials":[],"msixSideload":false,"msixUnsigned":false}))
        .execute(&mut root)
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
    assert!(
        service
            .authorize_report(&proof(case_b(), Channel::Mdm, 1), ReportSource::MdmWindows)
            .await
            .is_err()
    );
    assert_ne!(first.registration, other_channel.registration);
    assert_eq!(service.bind(&admin_a, &mdm, command.clone()).await?, first);
    for bad in [
        service.bind(&other, &mdm, command.clone()).await,
        service.bind(&admin_b, &mdm, command.clone()).await,
    ] {
        assert!(bad.is_err());
    }
    assert!(
        service
            .bind(&admin_a, &proof(case_a(), Channel::Mdm, 9), command.clone())
            .await
            .is_err()
    );
    let mut reused = command.clone();
    reused.operation_id = Uuid::new_v4();
    assert!(matches!(
        service.bind(&admin_a, &mdm, reused).await,
        Err(Error::Conflict)
    ));
    eprintln!("device T2: bindings and permission checks passed");
    assert!(
        service
            .authorize_report(&agent, ReportSource::MdmWindows)
            .await
            .is_err()
    );
    // Explicit source permission can be removed independently of an active credential.
    sqlx::query("UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id=$1::uuid AND source='mdm.windows' AND registration=$2").bind(case_a()).bind(first.registration).execute(&mut root)
        .await?;
    assert!(
        service
            .authorize_report(&mdm, ReportSource::MdmWindows)
            .await
            .is_err()
    );
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
    assert!(
        service
            .authorize_report(&mdm, ReportSource::MdmWindows)
            .await
            .is_err()
    );
    assert!(
        service
            .authorize_report(&agent, ReportSource::AgentBuiltin)
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
        request_id: request(&access, &admin_a, "concurrent", Channel::Mdm).await?,
        expected_generation: 0,
        source: ReportSource::MdmWindows,
    };
    let right = BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: request(&access, &admin_a, "concurrent", Channel::Mdm).await?,
        expected_generation: 0,
        source: ReportSource::MdmWindows,
    };
    let p1 = proof(case_a(), Channel::Mdm, 50);
    let p2 = proof(case_a(), Channel::Mdm, 51);
    let (l, r) = tokio::join!(
        service.bind(&admin_a, &p1, left),
        service.bind(&admin_a, &p2, right)
    );
    assert_eq!(usize::from(l.is_ok()) + usize::from(r.is_ok()), 1);
    assert!(matches!(l, Err(Error::Conflict)) || matches!(r, Err(Error::Conflict)));
    root.close().await?;
    access.close().await;
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
                let (business,audit):(i64,i64)=sqlx::query_as("SELECT count(*) FILTER(WHERE query LIKE 'SELECT id::text AS id FROM mdm_access.registrations%'),count(*) FILTER(WHERE query LIKE '%rss_audit.reserve%') FROM pg_stat_activity WHERE usename='mdm_access' AND wait_event_type='Lock'")
                    .fetch_one(&mut *hold).await?;
                if business == 1 && audit == 1 { return Ok::<_, sqlx::Error>(()); }
                // Clear the transaction-local statistics snapshot before the next poll.
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *hold).await?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.context("Audit head must serialize contenders before their business locks")??;
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
