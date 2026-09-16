#![allow(
    clippy::cognitive_complexity,
    reason = "sequential integration matrices preserve each failure and recovery assertion; production code remains checked"
)]
use super::*;
use crate::{
    access::{Binding, Role},
    enrollment::Password,
};
use anyhow::Context;
use sqlx::{
    Connection, Executor, PgConnection,
    postgres::{PgConnectOptions, PgSslMode},
};
const A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
pub(crate) fn proof(tenant: &str, channel: Channel, key: u8) -> VerifiedChannelCredential {
    VerifiedChannelCredential {
        tenant: TenantId::parse(tenant).unwrap(),
        channel,
        locator: [key; 32],
    }
}
pub(crate) fn policy(tenant: &str, enroll: bool, credentials: bool) -> Arc<Policy> {
    Arc::new(
        Policy::new(
            tenant,
            "mdm",
            vec![Binding {
                management: Default::default(),
                tenant_id: tenant.into(),
                client_id: "mdm".into(),
                subject: "administrator".into(),
                roles: [Role::MdmAdmin].into(),
                devices: ["*".into()].into(),
                allow_wipe: false,
                allow_enrollment: enroll,
                allow_manage_credentials: credentials,
            }],
        )
        .unwrap(),
    )
}
pub(crate) async fn admin(tenant: &str, token: &str) -> anyhow::Result<VerifiedIdentity> {
    let origin = std::env::var("MDM_TEST_IDENTITY")?;
    let client = rss_identity_client::IdentityClient::new(
        rss_identity_client::ClientConfig {
            identity_origin: origin.clone(),
            issuer: origin,
            client_id: "mdm".into(),
            validation_secret: zeroize::Zeroizing::new(
                "device-t2-validation-secret-00000000".into(),
            ),
            tenant_id: tenant.into(),
            audience: "rss-mdm".into(),
            timeout: Duration::from_secs(2),
            ca_pem: Some(std::fs::read(std::env::var("PG_CA_FILE")?)?),
        },
        Arc::new(rss_identity_client::SystemClock),
    )?;
    Ok(client.validate(token).await?)
}
pub(crate) fn options(user: &str) -> anyhow::Result<PgConnectOptions> {
    Ok(std::env::var(if user == "postgres" {
        "MDM_ADMIN_URL"
    } else {
        "DATABASE_URL"
    })?
    .parse::<PgConnectOptions>()?
    .username(user)
    .password(match user {
        "mdm_access" => "access-fixture",
        "mdm_runtime" => "runtime-fixture",
        "mdm_api" => "api-fixture",
        _ => "local-fixture",
    })
    .ssl_mode(PgSslMode::VerifyFull)
    .ssl_root_cert(std::env::var("PG_CA_FILE")?))
}
async fn request(
    store: &AccessStore,
    policy: &Policy,
    admin: &VerifiedIdentity,
    device: &str,
) -> anyhow::Result<Uuid> {
    let audit = Audit::new(admin.tenant_id().into(), "enrollment_create");
    audit.identify(admin);
    audit.target(device);
    let key = Uuid::new_v4();
    audit.operation(key, "enrollment_create");
    let receipt = store
        .create_enrollment(
            policy.enrollment(admin, device)?,
            &Password::new(crate::sessions::random())?,
            Uuid::new_v4(),
            key,
            &audit,
        )
        .await?;
    audit.finalize(None);
    Ok(receipt.enrollment_id)
}
pub(crate) async fn bind(
    service: &DeviceService,
    admin: &VerifiedIdentity,
    proof: &VerifiedChannelCredential,
    device: &str,
    generation: i64,
) -> anyhow::Result<(BindRegistration, RegistrationReceipt)> {
    let command = BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: request(&service.access, &service.policy, admin, device).await?,
        expected_generation: generation,
        source: match proof.channel {
            Channel::Mdm => ReportSource::MdmWindows,
            Channel::Agent => ReportSource::AgentBuiltin,
        },
    };
    let receipt = service
        .bind(admin, proof, command.clone())
        .await
        .context("device bind")?;
    Ok((command, receipt))
}
#[tokio::test]
#[ignore = "make t2: real TLS PostgreSQL; SDK response authority and channel evidence are test fixtures"]
async fn postgres_boundary() -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg!(feature = "integration"),
        "device T2 requires integration; run make t2"
    );
    let admin_a = admin(A, "admin-a").await?;
    let admin_b = admin(B, "admin-b").await?;
    let other = admin(A, "other-a").await?;
    assert!(admin(B, "admin-a").await.is_err());
    let access = Arc::new(
        AccessStore::connect(options("mdm_access")?)
            .await
            .context("access store admission")?,
    );
    let service = DeviceService::new(access.clone(), policy(A, true, true));
    let service_b = DeviceService::new(access.clone(), policy(B, true, true));
    let no_permission = DeviceService::new(access.clone(), policy(A, false, false));
    let mut root = PgConnection::connect_with(&options("postgres")?).await?;
    commit_deadlines(&service, &admin_a, &mut root).await?;
    let mdm = proof(A, Channel::Mdm, 1);
    let agent = proof(A, Channel::Agent, 1);
    let (command, first) = bind(&service, &admin_a, &mdm, "same-serial", 0).await?;
    let (_, other_channel) = bind(&service, &admin_a, &agent, "same-serial", 0).await?;
    let (_, other_tenant) = bind(
        &service_b,
        &admin_b,
        &proof(B, Channel::Mdm, 1),
        "same-serial",
        0,
    )
    .await?;
    assert_ne!(first.registration, other_tenant.registration);
    assert!(
        service
            .authorize_report(&proof(B, Channel::Mdm, 1), ReportSource::MdmWindows)
            .await
            .is_err()
    );
    assert_ne!(first.registration, other_channel.registration);
    assert_eq!(service.bind(&admin_a, &mdm, command.clone()).await?, first);
    for bad in [
        service.bind(&other, &mdm, command.clone()).await,
        service.bind(&admin_b, &mdm, command.clone()).await,
        no_permission.bind(&admin_a, &mdm, command.clone()).await,
    ] {
        assert!(bad.is_err());
    }
    assert!(
        service
            .bind(&admin_a, &proof(A, Channel::Mdm, 9), command.clone())
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
    root.execute("UPDATE mdm_access.report_sources SET enabled=false WHERE source='mdm.windows'")
        .await?;
    assert!(
        service
            .authorize_report(&mdm, ReportSource::MdmWindows)
            .await
            .is_err()
    );
    root.execute("UPDATE mdm_access.report_sources SET enabled=true WHERE source='mdm.windows'")
        .await?;
    let newer = proof(A, Channel::Mdm, 2);
    let (next, second) = bind(&service, &admin_a, &newer, "same-serial", 1).await?;
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
            "same-serial",
            Coordinates {
                source: ReportSource::MdmWindows,
            },
        )
        .await?;
    assert_eq!(
        current.registration().as_str(),
        second.registration.to_string()
    );
    // Independent explicit credential permission, including on replay.
    let revoke_key = Uuid::new_v4();
    assert!(
        no_permission
            .revoke(&admin_a, "same-serial", second.registration, revoke_key)
            .await
            .is_err()
    );
    // Real commit succeeds but its ACK is lost; recreate the owner and recover by original key.
    access.fail_next(2);
    assert!(matches!(
        service
            .revoke(&admin_a, "same-serial", second.registration, revoke_key)
            .await,
        Err(Error::CommitUnknown)
    ));
    let restart_access = Arc::new(
        AccessStore::connect(options("mdm_access")?)
            .await
            .context("access store admission")?,
    );
    let restart = DeviceService::new(restart_access.clone(), policy(A, true, true));
    let receipt = restart
        .revoke(&admin_a, "same-serial", second.registration, revoke_key)
        .await?;
    assert_eq!(receipt.registration, second.registration);
    assert!(matches!(
        no_permission
            .revoke(&admin_a, "same-serial", second.registration, revoke_key)
            .await,
        Err(Error::Forbidden)
    ));
    assert_eq!(
        restart
            .revoke(&admin_a, "same-serial", second.registration, revoke_key)
            .await?,
        receipt
    );
    assert!(
        restart
            .authorize_report(&newer, ReportSource::MdmWindows)
            .await
            .is_err()
    );
    assert!(
        restart
            .current_scope(
                &admin_a,
                "same-serial",
                Coordinates {
                    source: ReportSource::MdmWindows
                }
            )
            .await
            .is_err()
    );
    // Recovery of an old bind is its original receipt, never reactivation.
    assert_eq!(restart.bind(&admin_a, &newer, next).await?, second);
    assert!(
        restart
            .authorize_report(&newer, ReportSource::MdmWindows)
            .await
            .is_err()
    );
    let third_proof = proof(A, Channel::Mdm, 3);
    let pending = BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: request(&access, &service.policy, &admin_a, "same-serial").await?,
        expected_generation: 2,
        source: ReportSource::MdmWindows,
    };
    root.execute("REVOKE INSERT ON mdm_access.audit FROM mdm_access")
        .await?;
    assert!(
        service
            .bind(&admin_a, &third_proof, pending.clone())
            .await
            .is_err()
    );
    assert!(
        service
            .revoke(
                &admin_a,
                "same-serial",
                other_channel.registration,
                Uuid::new_v4()
            )
            .await
            .is_err()
    );
    root.execute("GRANT INSERT ON mdm_access.audit TO mdm_access")
        .await?;
    assert!(
        service
            .authorize_report(&agent, ReportSource::AgentBuiltin)
            .await
            .is_ok()
    );
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND request_id=$2::uuid").bind(A).bind(pending.request_id.to_string()).fetch_one(&mut root).await?;
    assert_eq!(count, 0);
    access.fail_next(1);
    assert!(
        service
            .bind(&admin_a, &third_proof, pending.clone())
            .await
            .is_err()
    );
    access.fail_next(2);
    assert!(matches!(
        service.bind(&admin_a, &third_proof, pending.clone()).await,
        Err(Error::CommitUnknown)
    ));
    let third = restart
        .bind(&admin_a, &third_proof, pending.clone())
        .await?;
    assert_eq!(third.generation, 3);
    assert_eq!(
        third,
        restart
            .bind(&admin_a, &third_proof, pending.clone())
            .await?
    );
    let audits:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.audit WHERE tenant_id=$1::uuid AND operation_id=$2::uuid AND result='success'").bind(A).bind(pending.operation_id.to_string()).fetch_one(&mut root).await?;
    assert_eq!(audits, 1);
    assert!(
        no_permission
            .bind(&admin_a, &third_proof, pending)
            .await
            .is_err()
    );
    // Failed replacement must leave the existing generation/credential/source fully active.
    let replace = BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: request(&access, &service.policy, &admin_a, "same-serial").await?,
        expected_generation: 3,
        source: ReportSource::MdmWindows,
    };
    root.execute("REVOKE INSERT ON mdm_access.audit FROM mdm_access")
        .await?;
    assert!(
        service
            .bind(&admin_a, &proof(A, Channel::Mdm, 4), replace.clone())
            .await
            .is_err()
    );
    root.execute("GRANT INSERT ON mdm_access.audit TO mdm_access")
        .await?;
    assert!(
        service
            .authorize_report(&third_proof, ReportSource::MdmWindows)
            .await
            .is_ok()
    );
    // Replacement commits with its old generation still active, then loses its ACK.
    let fourth_proof = proof(A, Channel::Mdm, 4);
    access.fail_next(2);
    assert!(matches!(
        service.bind(&admin_a, &fourth_proof, replace.clone()).await,
        Err(Error::CommitUnknown)
    ));
    let fourth = restart
        .bind(&admin_a, &fourth_proof, replace.clone())
        .await?;
    assert_eq!(fourth.generation, 4);
    assert_eq!(fourth.device, third.device);
    assert_eq!(
        fourth,
        restart.bind(&admin_a, &fourth_proof, replace).await?
    );
    let state: String = sqlx::query_scalar(
        "SELECT state FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2::uuid",
    )
    .bind(A)
    .bind(third.registration.to_string())
    .fetch_one(&mut root)
    .await?;
    assert_eq!(state, "superseded");
    let active: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm' AND state='active'")
        .bind(A).bind(&fourth.device).fetch_one(&mut root).await?;
    assert_eq!(active, 1);
    assert!(
        restart
            .authorize_report(&third_proof, ReportSource::MdmWindows)
            .await
            .is_err()
    );
    assert_eq!(
        restart
            .authorize_report(&fourth_proof, ReportSource::MdmWindows)
            .await?
            .0
            .registration(),
        fourth.registration
    );
    assert_eq!(
        restart
            .authorize_report(&agent, ReportSource::AgentBuiltin)
            .await?
            .0
            .registration(),
        other_channel.registration
    );
    // A fresh operation cannot reactivate superseded or revoked credential locators.
    for retired in [&mdm, &newer] {
        let retry = BindRegistration {
            operation_id: Uuid::new_v4(),
            request_id: request(&access, &service.policy, &admin_a, "same-serial").await?,
            expected_generation: 4,
            source: ReportSource::MdmWindows,
        };
        assert!(matches!(
            service.bind(&admin_a, retired, retry).await,
            Err(Error::Conflict)
        ));
        assert_eq!(
            service
                .authorize_report(&fourth_proof, ReportSource::MdmWindows)
                .await?
                .0
                .registration(),
            fourth.registration
        );
    }
    credential_race(&service, &admin_a, &mut root).await?;
    // Two accepted requests racing for the same expected generation cannot silently overwrite.
    let left = BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: request(&access, &service.policy, &admin_a, "concurrent").await?,
        expected_generation: 0,
        source: ReportSource::MdmWindows,
    };
    let right = BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: request(&access, &service.policy, &admin_a, "concurrent").await?,
        expected_generation: 0,
        source: ReportSource::MdmWindows,
    };
    let p1 = proof(A, Channel::Mdm, 50);
    let p2 = proof(A, Channel::Mdm, 51);
    let (l, r) = tokio::join!(
        service.bind(&admin_a, &p1, left),
        service.bind(&admin_a, &p2, right)
    );
    assert_eq!(usize::from(l.is_ok()) + usize::from(r.is_ok()), 1);
    assert!(matches!(l, Err(Error::Conflict)) || matches!(r, Err(Error::Conflict)));
    // Revocation wins the row lock: an authorization waiting behind it must fail.
    let mut revoke_tx = root.begin().await?;
    sqlx::query("UPDATE mdm_access.registrations SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(A).bind(fourth.registration.to_string()).execute(&mut *revoke_tx).await?;
    let authorize = service.authorize_report(&fourth_proof, ReportSource::MdmWindows);
    let release = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        revoke_tx.commit().await
    };
    let (result, committed) = tokio::join!(authorize, release);
    committed?;
    assert!(result.is_err());
    // Minimum role remains closed to audit/history mutation and tenant bypass.
    let mut runtime = PgConnection::connect_with(&options("mdm_access")?).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.registrations")
        .fetch_one(&mut runtime)
        .await?;
    assert_eq!(count, 0);
    for statement in [
        "DELETE FROM mdm_access.registrations",
        "UPDATE mdm_access.credentials SET locator=repeat('0',64)",
        "UPDATE mdm_access.audit SET result='success'",
    ] {
        assert!(runtime.execute(statement).await.is_err());
    }
    runtime.close().await?;
    root.close().await?;
    restart_access.close().await;
    access.close().await;
    Ok(())
}

// Force both contenders past the locator precheck. Different device locks cannot
// arbitrate this race: the database unique constraint must roll back the loser's retire.
async fn credential_race(
    service: &DeviceService,
    admin: &VerifiedIdentity,
    root: &mut PgConnection,
) -> anyhow::Result<()> {
    let pa = proof(A, Channel::Mdm, 60);
    let pb = proof(A, Channel::Mdm, 61);
    let (_, a) = bind(service, admin, &pa, "locator-left", 0).await?;
    let (_, b) = bind(service, admin, &pb, "locator-right", 0).await?;
    let mut commands = Vec::new();
    for device in [&a.device, &b.device] {
        commands.push(BindRegistration {
            operation_id: Uuid::new_v4(),
            request_id: request(&service.access, &service.policy, admin, device).await?,
            expected_generation: 1,
            source: ReportSource::MdmWindows,
        });
    }
    let mut hold = root.begin().await?;
    sqlx::query("SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id IN ($2::uuid,$3::uuid) FOR UPDATE")
        .bind(A).bind(a.registration.to_string()).bind(b.registration.to_string()).fetch_all(&mut *hold).await?;
    let shared = proof(A, Channel::Mdm, 62);
    let release = async {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let blocked:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='mdm_access' AND wait_event_type='Lock' AND query LIKE 'SELECT id::text AS id FROM mdm_access.registrations%'")
                    .fetch_one(&mut *hold).await?;
                if blocked == 2 { return Ok::<_, sqlx::Error>(()); }
                // Clear the transaction-local statistics snapshot before the next poll.
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *hold).await?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.context("both credential contenders must pass precheck")??;
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
        .bind(A).bind(&loser.device).fetch_one(&mut *root).await?;
    assert_eq!(generations, 1);
    // Even after revocation the winning locator cannot move to the other device.
    service
        .revoke(admin, &winner.device, winner.registration, Uuid::new_v4())
        .await?;
    let retry = BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: request(&service.access, &service.policy, admin, &loser.device).await?,
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

async fn commit_deadlines(
    service: &DeviceService,
    admin: &VerifiedIdentity,
    root: &mut PgConnection,
) -> anyhow::Result<()> {
    let mut outcomes = Vec::new();
    for fault in [3, 4] {
        let device = format!("commit-deadline-{fault}");
        let credential = proof(A, Channel::Mdm, 100 + fault);
        let command = BindRegistration {
            operation_id: Uuid::new_v4(),
            request_id: request(&service.access, &service.policy, admin, &device).await?,
            expected_generation: 0,
            source: ReportSource::MdmWindows,
        };
        service.access.fail_next(fault);
        let result = service.bind(admin, &credential, command.clone()).await;
        outcomes.push(matches!(result, Err(Error::CommitUnknown)));
        let stored: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mdm_access.operations WHERE operation_id=$1::uuid",
        )
        .bind(command.operation_id.to_string())
        .fetch_one(&mut *root)
        .await?;
        assert_eq!(stored, i64::from(fault == 4));
        let receipt = service.bind(admin, &credential, command.clone()).await?;
        assert_eq!(service.bind(admin, &credential, command).await?, receipt);

        let key = Uuid::new_v4();
        service.access.fail_next(fault);
        let result = service
            .revoke(admin, &device, receipt.registration, key)
            .await;
        outcomes.push(matches!(result, Err(Error::CommitUnknown)));
        let stored: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mdm_access.operations WHERE operation_id=$1::uuid",
        )
        .bind(key.to_string())
        .fetch_one(&mut *root)
        .await?;
        assert_eq!(stored, i64::from(fault == 4));
        let revoked = service
            .revoke(admin, &device, receipt.registration, key)
            .await?;
        assert_eq!(
            service
                .revoke(admin, &device, receipt.registration, key)
                .await?,
            revoked
        );
    }
    assert_eq!(
        outcomes, [true; 4],
        "bind/revoke must preserve unknown for both possible commit results"
    );
    Ok(())
}
