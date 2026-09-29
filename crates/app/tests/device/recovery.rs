#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use super::*;
#[tokio::test]
#[ignore = "MODULE=device.recovery: real registration state and PostgreSQL"]
async fn revocation_and_replacement_unknown_commit() -> anyhow::Result<()> {
    let (access, service, admin_a, mut root) = fixture().await?;
    let other = admin(case_a(), "other-a").await?;
    let mdm = proof(case_a(), Channel::Mdm, 1);
    let agent = proof(case_a(), Channel::Agent, 1);
    bind(
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
    sqlx::query("INSERT INTO mdm_access.agent_bindings(tenant_id,registration,wire_version,capabilities,platform,architecture) VALUES($1::uuid,$2::uuid,3,'[\"inventory.basic.v3\"]','macos','aarch64')")
        .bind(case_a()).bind(other_channel.registration.to_string()).execute(&mut root).await?;
    let newer = proof(case_a(), Channel::Mdm, 2);
    let (next, second) = bind(
        &service,
        &admin_a,
        &newer,
        crate::test_support::case::name("same-serial"),
        1,
    )
    .await?;
    // Independent explicit credential permission, including on replay.
    let revoke_key = Uuid::new_v4();
    assert!(
        service
            .revoke(
                &other,
                crate::test_support::case::name("same-serial"),
                second.registration,
                revoke_key
            )
            .await
            .is_err()
    );
    // Real commit succeeds but its ACK is lost; recreate the owner and recover by original key.
    service
        .audit_store
        .inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    assert!(matches!(
        service
            .revoke(
                &admin_a,
                crate::test_support::case::name("same-serial"),
                second.registration,
                revoke_key
            )
            .await,
        Err(Error::CommitUnknown)
    ));
    let restart_access = Arc::new(
        Database::connect(options("mdm_access")?)
            .await
            .context("access store admission")?,
    );
    let restart = DeviceService::new(
        restart_access.clone(),
        case_a().into(),
        restart_access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    );
    let receipt = restart
        .revoke(
            &admin_a,
            crate::test_support::case::name("same-serial"),
            second.registration,
            revoke_key,
        )
        .await?;
    assert_eq!(receipt.registration, second.registration);
    assert!(matches!(
        service
            .revoke(
                &other,
                crate::test_support::case::name("same-serial"),
                second.registration,
                revoke_key
            )
            .await,
        Err(Error::Forbidden)
    ));
    assert_eq!(
        restart
            .revoke(
                &admin_a,
                crate::test_support::case::name("same-serial"),
                second.registration,
                revoke_key
            )
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
                crate::test_support::case::name("same-serial"),
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
    let third_proof = proof(case_a(), Channel::Mdm, 3);
    let pending = BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: request(
            &access,
            &admin_a,
            crate::test_support::case::name("same-serial"),
            Channel::Mdm,
        )
        .await?,
        expected_generation: 2,
        source: ReportSource::MdmWindows,
    };
    root.execute("REVOKE INSERT ON mdm_audit.receipts FROM mdm_access")
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
                crate::test_support::case::name("same-serial"),
                other_channel.registration,
                Uuid::new_v4()
            )
            .await
            .is_err()
    );
    root.execute("GRANT INSERT ON mdm_audit.receipts TO mdm_access")
        .await?;
    assert!(
        service
            .authorize_report(&agent, ReportSource::AgentBuiltin)
            .await
            .is_ok()
    );
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND request_id=$2::uuid").bind(case_a()).bind(pending.request_id.to_string()).fetch_one(&mut root).await?;
    assert_eq!(count, 0);
    service
        .audit_store
        .inject_next_fault(rss_audit_postgres::PgFault::BeforeCommitPending);
    assert!(
        service
            .bind(&admin_a, &third_proof, pending.clone())
            .await
            .is_err()
    );
    service
        .audit_store
        .inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
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
    let audits = crate::audit_test_support::read(&mut root)
        .await?
        .iter()
        .filter(|r| {
            r.source() == "mdm.business"
                && r.operation() == Some(pending.operation_id.to_string().as_str())
                && r.result() == "success"
        })
        .count();
    assert_eq!(audits, 1);
    assert!(service.bind(&other, &third_proof, pending).await.is_err());
    // Failed replacement must leave the existing generation/credential/source fully active.
    let replace = BindRegistration {
        operation_id: Uuid::new_v4(),
        request_id: request(
            &access,
            &admin_a,
            crate::test_support::case::name("same-serial"),
            Channel::Mdm,
        )
        .await?,
        expected_generation: 3,
        source: ReportSource::MdmWindows,
    };
    root.execute("REVOKE INSERT ON mdm_audit.receipts FROM mdm_access")
        .await?;
    assert!(
        service
            .bind(&admin_a, &proof(case_a(), Channel::Mdm, 4), replace.clone())
            .await
            .is_err()
    );
    root.execute("GRANT INSERT ON mdm_audit.receipts TO mdm_access")
        .await?;
    assert!(
        service
            .authorize_report(&third_proof, ReportSource::MdmWindows)
            .await
            .is_ok()
    );
    // Replacement commits with its old generation still active, then loses its ACK.
    let fourth_proof = proof(case_a(), Channel::Mdm, 4);
    service
        .audit_store
        .inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
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
    .bind(case_a())
    .bind(third.registration.to_string())
    .fetch_one(&mut root)
    .await?;
    assert_eq!(state, "superseded");
    let active: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm' AND state='active'")
        .bind(case_a()).bind(&fourth.device).fetch_one(&mut root).await?;
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
            request_id: request(
                &access,
                &admin_a,
                crate::test_support::case::name("same-serial"),
                Channel::Mdm,
            )
            .await?,
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
    root.close().await?;
    restart_access.close().await;
    access.close().await;
    Ok(())
}
async fn commit_deadlines(
    service: &DeviceService,
    admin: &AuthorizedPrincipal,
    root: &mut PgConnection,
) -> anyhow::Result<()> {
    let mut outcomes = Vec::new();
    for (number, fault, committed) in [
        (3, rss_audit_postgres::PgFault::BeforeCommitPending, false),
        (4, rss_audit_postgres::PgFault::CommitUnknownAfterAck, true),
    ] {
        let device = format!(
            "{}-{number}",
            crate::test_support::case::name("commit-deadline")
        );
        let credential = proof(case_a(), Channel::Mdm, 100 + number);
        let command = BindRegistration {
            operation_id: Uuid::new_v4(),
            request_id: request(&service.access, admin, &device, Channel::Mdm).await?,
            expected_generation: 0,
            source: ReportSource::MdmWindows,
        };
        service.audit_store.inject_next_fault(fault);
        let result = service.bind(admin, &credential, command.clone()).await;
        outcomes.push(matches!(result, Err(Error::CommitUnknown)));
        let stored: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mdm_access.operations WHERE operation_id=$1::uuid",
        )
        .bind(command.operation_id.to_string())
        .fetch_one(&mut *root)
        .await?;
        assert_eq!(stored, i64::from(committed));
        let receipt = service.bind(admin, &credential, command.clone()).await?;
        assert_eq!(service.bind(admin, &credential, command).await?, receipt);

        let key = Uuid::new_v4();
        service.audit_store.inject_next_fault(fault);
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
        assert_eq!(stored, i64::from(committed));
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
#[tokio::test]
#[ignore = "MODULE=device.recovery: real registration state and PostgreSQL"]
async fn bounded_bind_and_revoke_settlement() -> anyhow::Result<()> {
    let (access, service, admin_a, mut root) = fixture().await?;
    commit_deadlines(&service, &admin_a, &mut root).await?;
    root.close().await?;
    access.close().await;
    Ok(())
}
