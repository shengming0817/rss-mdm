use crate::enrollment::test_support::{audit, create};
use crate::windows::test_support::*;
use crate::windows::*;
use crate::{
    Database,
    device::test_support::{admin, options},
    enrollment::Password,
};
use anyhow::ensure;
use sqlx::{Connection, Executor, PgConnection};
use std::time::Duration;
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_cert::der::{Decode, Encode};
#[tokio::test]
#[ignore = "make t2 MODULE=windows.issuance"]
async fn issuance_recovery_and_enrollment_boundaries() -> anyhow::Result<()> {
    let w = windows()?;
    let csr = std::fs::read(root()?.join("device.csr"))?;
    certificate::Csr::verify(&csr)?;
    for input in [
        std::fs::read(root()?.join("weak.csr"))?,
        std::fs::read(root()?.join("sha1.csr"))?,
        [csr.clone(), vec![0]].concat(),
        {
            let mut b = csr.clone();
            let end = b.len() - 1;
            b[end] ^= 1;
            b
        },
    ] {
        ensure!(certificate::Csr::verify(&input).is_err());
    }
    let mut absent = x509_cert::request::CertReq::from_der(&csr)?;
    absent.algorithm.parameters = None;
    certificate::Csr::verify(&absent.to_der()?)?;
    ensure!(
        certificate::Ca::load(
            &root()?.join("device-ca.pem"),
            &root()?.join("device.pk8"),
            now()
        )
        .is_err()
    );
    ensure!(
        certificate::Ca::load(
            &root()?.join("device-ca.pem"),
            &root()?.join("device-ca.pk8"),
            now() + 181 * 86400
        )
        .is_err()
    );
    let proof = admin(case_tenant(), "admin-a").await?;
    let store = Database::connect(options("mdm_access")?).await?;
    let mut pg = PgConnection::connect_with(&options("postgres")?).await?;
    let password = Password::new(crate::enrollment::random())?;
    let key = Uuid::new_v4();
    let receipt = create(
        &store,
        &proof,
        "windows-device",
        &password,
        Uuid::new_v4(),
        key,
    )
    .await?;
    let auth = crate::enrollment::store::enrollment_authorization(
        &store,
        case_tenant(),
        receipt.enrollment_id,
        &password,
    )
    .await?;
    let intent = crate::windows::issuance::issuance_intent(
        &store,
        &w,
        &auth,
        &proof,
        (
            &csr,
            rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
        ),
        now(),
    )
    .await?;
    let cert = w.ca.sign(&intent.tbs)?;
    ensure!(cert == w.ca.sign(&intent.tbs)?);
    // CSR, enrollment context and protocol protection identity are immutable on retry.
    ensure!(
        crate::windows::issuance::issuance_intent(
            &store,
            &w,
            &auth,
            &proof,
            (
                &absent.to_der()?,
                rss_mdm_windows_mdm::provisioning::EnrollmentType::Full
            ),
            now()
        )
        .await
        .is_err()
    );
    ensure!(
        crate::windows::issuance::issuance_intent(
            &store,
            &w,
            &auth,
            &proof,
            (
                &csr,
                rss_mdm_windows_mdm::provisioning::EnrollmentType::Device
            ),
            now()
        )
        .await
        .is_err()
    );
    ensure!(
        w.protection
            .open(crate::test_support::case::peer(), auth.id, &intent.sealed)
            .is_err()
    );
    let mut altered = intent.sealed.clone();
    altered[15] ^= 1;
    ensure!(w.protection.open(case_tenant(), auth.id, &altered).is_err());
    ensure!(
        w.ca.verify(&[CertificateDer::from(cert.as_slice())], now() + 91 * 86400)
            .is_err()
    );
    let mut wrong_usage = x509_cert::TbsCertificate::from_der(&intent.tbs)?;
    wrong_usage
        .extensions
        .as_mut()
        .unwrap()
        .retain(|e| e.extn_id.to_string() != "2.5.29.37");
    let wrong_usage = w.ca.sign(&wrong_usage.to_der()?)?;
    ensure!(
        w.ca.verify(&[CertificateDer::from(wrong_usage)], now())
            .is_err()
    );

    let checked =
        w.ca.verify(&[CertificateDer::from(cert.as_slice())], now())?;
    let credential = crate::device::VerifiedChannelCredential::windows(
        rss_request_context::TenantId::parse(case_tenant())?,
        &checked,
    );
    let access = Arc::new(store);
    let audit_store = access
        .audit_store(&crate::config::AuditConfig::Plain)
        .await?;
    let service = crate::device::DeviceService::new(
        access.clone(),
        case_tenant().into(),
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    );
    ensure!(
        service.management_principal(&credential).await.is_err(),
        "unbound signed certificate admitted"
    );
    let mut unrelated = x509_cert::TbsCertificate::from_der(&intent.tbs)?;
    unrelated.subject = "CN=another-intent".parse()?;
    let unrelated = w.ca.sign(&unrelated.to_der()?)?;
    w.ca.verify(&[CertificateDer::from(unrelated.as_slice())], now())?;
    ensure!(matches!(
        complete(&audit_store, &w, &auth, &proof, &intent, &unrelated).await,
        Err(Error::Conflict)
    ));
    ensure!(service.management_principal(&credential).await.is_err());
    // Failed final write leaves only the exact immutable intent.
    audit_store.inject_next_fault(rss_audit_postgres::PgFault::BeforeCommitPending);
    ensure!(
        complete(&audit_store, &w, &auth, &proof, &intent, &cert)
            .await
            .is_err()
    );
    ensure!(service.management_principal(&credential).await.is_err());
    let restarted = Database::connect(options("mdm_access")?).await?;
    let restarted_ca = windows()?;
    let saved = crate::windows::issuance::issuance_intent(
        &restarted,
        &restarted_ca,
        &auth,
        &proof,
        (
            &csr,
            rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
        ),
        now(),
    )
    .await?;
    ensure!(
        saved.tbs == intent.tbs
            && saved.registration == intent.registration
            && restarted_ca.ca.sign(&saved.tbs)? == cert
    );
    audit_store.inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    ensure!(matches!(
        complete(&audit_store, &w, &auth, &proof, &intent, &cert).await,
        Err(Error::CommitUnknown)
    ));
    complete(
        restarted
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?
            .as_ref(),
        &restarted_ca,
        &auth,
        &proof,
        &saved,
        &cert,
    )
    .await?;
    ensure!(
        service
            .management_principal(&credential)
            .await?
            .registration()
            == intent.registration
    );
    let successes = crate::audit_test_support::read(&mut pg)
        .await?
        .iter()
        .filter(|r| {
            r.source() == "mdm.business"
                && r.action() == "enrollment_issue"
                && r.operation() == Some(auth.operation.to_string().as_str())
                && r.result() == "success"
        })
        .count();
    ensure!(successes == 1);
    for fault in [3, 4] {
        let device = format!("windows-commit-deadline-{fault}");
        let r = create(
            &access,
            &proof,
            &device,
            &password,
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .await?;
        let a = crate::enrollment::store::enrollment_authorization(
            &access,
            case_tenant(),
            r.enrollment_id,
            &password,
        )
        .await?;
        let i = crate::windows::issuance::issuance_intent(
            &access,
            &w,
            &a,
            &proof,
            (
                &csr,
                rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
            ),
            now(),
        )
        .await?;
        let c = w.ca.sign(&i.tbs)?;
        audit_store.inject_next_fault(if fault == 3 {
            rss_audit_postgres::PgFault::BeforeCommitPending
        } else {
            rss_audit_postgres::PgFault::CommitUnknownAfterAck
        });
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            complete(&audit_store, &w, &a, &proof, &i, &c),
        )
        .await;
        ensure!(if fault == 3 {
            result.is_err()
        } else {
            matches!(result, Ok(Err(Error::CommitUnknown)))
        });
        complete(&audit_store, &w, &a, &proof, &i, &c).await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2",
        )
        .bind(case_tenant())
        .bind(&device)
        .fetch_one(&mut pg)
        .await?;
        ensure!(count == 1);
    }
    // Rotation invalidates an in-flight authorization without replacing the CSR or generation.
    let next = Password::new(crate::enrollment::random())?;
    let resume_key = Uuid::new_v4();
    let a = audit(&proof, resume_key, "windows-device", "enrollment_resume");
    crate::enrollment::store::change_enrollment(
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?
            .as_ref(),
        proof.enrollment("windows-device")?,
        auth.id,
        Some((&next, Uuid::new_v4())),
        resume_key,
        &a,
    )
    .await?;
    a.finalize(None);
    ensure!(
        crate::enrollment::store::enrollment_authorization(
            &access,
            case_tenant(),
            auth.id,
            &password
        )
        .await
        .is_err()
    );
    ensure!(
        complete(&audit_store, &w, &auth, &proof, &intent, &cert)
            .await
            .is_err()
    );
    let resumed =
        crate::enrollment::store::enrollment_authorization(&access, case_tenant(), auth.id, &next)
            .await?;
    ensure!(
        resumed.operation == auth.operation
            && resumed.expected_generation == auth.expected_generation
    );
    complete(&audit_store, &w, &resumed, &proof, &intent, &cert).await?;
    // Cancelled/expired authorizations cannot publish an already computed signature.
    for (device, cause) in [
        ("cancel-race", "cancel"),
        ("expiry-race", "expiry"),
        ("permission-race", "permission"),
    ] {
        let pending = create(
            &access,
            &proof,
            device,
            &password,
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .await?;
        let auth = crate::enrollment::store::enrollment_authorization(
            &access,
            case_tenant(),
            pending.enrollment_id,
            &password,
        )
        .await?;
        let intent = crate::windows::issuance::issuance_intent(
            &access,
            &w,
            &auth,
            &proof,
            (
                &csr,
                rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
            ),
            now(),
        )
        .await?;
        if cause == "cancel" {
            let key = Uuid::new_v4();
            let a = audit(&proof, key, device, "enrollment_cancel");
            crate::enrollment::store::change_enrollment(
                access
                    .audit_store(&crate::config::AuditConfig::Plain)
                    .await?
                    .as_ref(),
                proof.enrollment(device)?,
                auth.id,
                None,
                key,
                &a,
            )
            .await?;
            a.finalize(None);
        } else if cause == "expiry" {
            sqlx::query("UPDATE mdm_access.requests SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(case_tenant()).bind(auth.id.to_string()).execute(&mut pg).await?;
        }
        let current = if cause == "permission" {
            crate::test_support::identity::set_grants(
                case_tenant(),
                crate::test_support::case::admin(),
                vec![],
            )
            .await?;
            Some(admin(case_tenant(), "admin-a").await?)
        } else {
            None
        };
        let result = complete(
            &audit_store,
            &w,
            &auth,
            current.as_ref().unwrap_or(&proof),
            &intent,
            &w.ca.sign(&intent.tbs)?,
        )
        .await;
        if cause == "permission" {
            crate::test_support::identity::set_grants(
                case_tenant(),
                crate::test_support::case::admin(),
                crate::test_support::identity::device_grants(
                    None,
                    &["inventory_read", "enrollment", "credentials"],
                )?,
            )
            .await?;
        }
        ensure!(result.is_err());
        let bound: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND request_id=$2::uuid")
            .bind(case_tenant()).bind(auth.id.to_string()).fetch_one(&mut pg).await?;
        ensure!(bound == 0);
    }
    // RequestAudit failure rolls back the entire final binding, then the same intent can finish.
    let r = create(
        &access,
        &proof,
        "audit-race",
        &password,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await?;
    let a = crate::enrollment::store::enrollment_authorization(
        &access,
        case_tenant(),
        r.enrollment_id,
        &password,
    )
    .await?;
    let i = crate::windows::issuance::issuance_intent(
        &access,
        &w,
        &a,
        &proof,
        (
            &csr,
            rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
        ),
        now(),
    )
    .await?;
    let c = w.ca.sign(&i.tbs)?;
    pg.execute("REVOKE INSERT ON mdm_audit.receipts FROM mdm_access")
        .await?;
    let failed = complete(&audit_store, &w, &a, &proof, &i, &c).await;
    let reopened = Database::connect(options("mdm_access")?).await?;
    let rejected = reopened
        .audit_store(&crate::config::AuditConfig::Plain)
        .await
        .is_err();
    reopened.close().await;
    pg.execute("GRANT INSERT ON mdm_audit.receipts TO mdm_access")
        .await?;
    ensure!(rejected);
    ensure!(matches!(
        failed,
        Err(Error::Unavailable(Failure::AuditAdmission))
    ));
    complete(&audit_store, &w, &a, &proof, &i, &c).await?;
    // Two accepted enrollments freeze the same base; only one final generation can win.
    let first = create(
        &access,
        &proof,
        "concurrent-windows",
        &password,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await?;
    let second = create(
        &access,
        &proof,
        "concurrent-windows",
        &password,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await?;
    let a1 = crate::enrollment::store::enrollment_authorization(
        &access,
        case_tenant(),
        first.enrollment_id,
        &password,
    )
    .await?;
    let a2 = crate::enrollment::store::enrollment_authorization(
        &access,
        case_tenant(),
        second.enrollment_id,
        &password,
    )
    .await?;
    let i1 = crate::windows::issuance::issuance_intent(
        &access,
        &w,
        &a1,
        &proof,
        (
            &csr,
            rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
        ),
        now(),
    )
    .await?;
    let i2 = crate::windows::issuance::issuance_intent(
        &access,
        &w,
        &a2,
        &proof,
        (
            &csr,
            rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
        ),
        now(),
    )
    .await?;
    let (c1, c2) = (w.ca.sign(&i1.tbs)?, w.ca.sign(&i2.tbs)?);
    let (r1, r2) = tokio::join!(
        complete(&audit_store, &w, &a1, &proof, &i1, &c1),
        complete(&audit_store, &w, &a2, &proof, &i2, &c2)
    );
    ensure!(r1.is_ok() != r2.is_ok());
    // Revocation cannot be undone by enrollment resume or by replay of issuance.
    service
        .revoke(
            &proof,
            "windows-device",
            intent.registration,
            Uuid::new_v4(),
        )
        .await?;
    ensure!(service.management_principal(&credential).await.is_err());
    ensure!(
        complete(&audit_store, &w, &resumed, &proof, &intent, &cert)
            .await
            .is_err()
    );
    let key = Uuid::new_v4();
    let a = audit(&proof, key, "windows-device", "enrollment_resume");
    ensure!(
        crate::enrollment::store::change_enrollment(
            access
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?
                .as_ref(),
            proof.enrollment("windows-device")?,
            auth.id,
            Some((&password, Uuid::new_v4())),
            key,
            &a
        )
        .await
        .is_err()
    );
    a.finalize(None);
    for (grant, revoke) in [
        (
            "GRANT UPDATE(tbs) ON mdm_access.enrollment_intents TO mdm_access",
            "REVOKE UPDATE(tbs) ON mdm_access.enrollment_intents FROM mdm_access",
        ),
        (
            "GRANT UPDATE(state) ON mdm_access.grants TO mdm_access",
            "REVOKE UPDATE(state) ON mdm_access.grants FROM mdm_access",
        ),
        (
            "GRANT UPDATE(canonical) ON mdm_audit.receipts TO mdm_access",
            "REVOKE UPDATE(canonical) ON mdm_audit.receipts FROM mdm_access",
        ),
    ] {
        pg.execute(grant).await?;
        let rejected = match Database::connect(options("mdm_access")?).await {
            Err(_) => true,
            Ok(store) => {
                let rejected = store
                    .audit_store(&crate::config::AuditConfig::Plain)
                    .await
                    .is_err();
                store.close().await;
                rejected
            }
        };
        pg.execute(revoke).await?;
        ensure!(rejected);
    }
    pg.close().await?;
    restarted.close().await;
    access.close().await;
    Ok(())
}
