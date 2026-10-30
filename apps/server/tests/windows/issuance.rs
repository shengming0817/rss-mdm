use crate::enrollment::test_support::{audit, create};
use crate::windows::test_support::*;
use crate::windows::*;
use crate::{
    device::test_support::{admin, options},
    enrollment::Password,
};
use anyhow::ensure;
use sqlx::{Connection, Executor, PgConnection};
use std::time::Duration;
use tokio_rustls::rustls::pki_types::CertificateDer;
use uuid::Uuid;
use x509_cert::der::{Decode, Encode};
#[tokio::test]
#[ignore = "make t2 MODULE=windows.issuance"]
async fn issuance_recovery_and_enrollment_boundaries() -> anyhow::Result<()> {
    let w = windows()?;
    let csr = std::fs::read(root()?.join("device.csr"))?;
    certificate::Csr::verify(&csr)?;
    let mut absent = x509_cert::request::CertReq::from_der(&csr)?;
    absent.algorithm.parameters = None;
    certificate::Csr::verify(&absent.to_der()?)?;
    let trust = w.channel.ca.trust.public()?;
    ensure!(
        rss_mdm_device_trust::DeviceTrust::new(
            trust,
            rss_mdm_agent_wire::pki::Purpose::Windows,
            now() + 181 * 86400
        )
        .is_err()
    );
    let proof = admin(case_tenant(), "admin-a").await?;
    let (pool, source, audit_store) = crate::audit_test_support::request_store().await?;
    let registration_store = Arc::new(rss_mdm_registration_service::Store::from_pool(
        pool.clone(),
        Arc::new(crate::registration_lifecycle::Bridge),
    ));
    let authorization_store = Arc::new(rss_mdm_authorization_service::Store::from_pool(
        pool.clone(),
        Arc::new(crate::lifecycle::RuntimeTimer),
    ));
    let windows_store = Arc::new(rss_mdm_windows_channel::Store::from_pool(
        pool.clone(),
        registration_store.clone(),
        authorization_store,
    ));
    let registry = rss_mdm_pki_service::registry::Registry::new(
        pool.clone(),
        audit_store.clone(),
        vec![w.channel.ca.trust.clone()],
        fixture_providers()?,
    );
    registry
        .admit(rss_request_context::TenantId::parse(case_tenant())?, now())
        .await?;
    let mut pg = PgConnection::connect_with(&options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut pg)
        .await?;
    let password = Password::new(crate::enrollment::random())?;
    let key = Uuid::new_v4();
    let receipt = create(
        &audit_store,
        &proof,
        "windows-device",
        &password,
        Uuid::new_v4(),
        key,
    )
    .await?;
    let auth = crate::enrollment::store::enrollment_authorization(
        &registration_store.clone(),
        case_tenant(),
        receipt.enrollment_id,
        &password,
    )
    .await?;
    let intent = rss_mdm_windows_channel::issuance::issuance_intent(
        &audit_store,
        &windows_store.clone(),
        &w.channel,
        &auth,
        &proof,
        (
            &csr,
            rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
        ),
        now(),
    )
    .await?;
    let expired = intent;
    tokio::time::sleep(Duration::from_secs(61)).await;
    let resume = || {
        rss_mdm_windows_channel::issuance::issuance_intent(
            &audit_store,
            &windows_store,
            &w.channel,
            &auth,
            &proof,
            (
                &csr,
                rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
            ),
            now(),
        )
    };
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid")
            .bind(case_tenant())
            .fetch_one(&mut pg)
            .await?;
    pg.execute("REVOKE EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) FROM mdm_access").await?;
    let refused = resume().await;
    pg.execute("GRANT EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) TO mdm_access").await?;
    ensure!(refused.is_err(), "replacement ignored audit failure");
    let unchanged: bool = sqlx::query_scalar("SELECT state='prepared' AND successor IS NULL FROM mdm_pki.signing WHERE tenant_id=$1::uuid AND attempt=$2")
        .bind(case_tenant()).bind(expired.signing_attempt).fetch_one(&mut pg).await?;
    ensure!(unchanged, "audit failure left a partial replacement");
    sqlx::query("INSERT INTO mdm_access.registration_admission(tenant_id,channel,revision,paused) VALUES($1::uuid,'windows_mdm',1,true) ON CONFLICT(tenant_id,channel) DO UPDATE SET paused=true")
        .bind(case_tenant()).execute(&mut pg).await?;
    ensure!(
        resume().await.is_err(),
        "paused admission authorized a successor"
    );
    let unchanged: bool = sqlx::query_scalar("SELECT state='prepared' AND successor IS NULL FROM mdm_pki.signing WHERE tenant_id=$1::uuid AND attempt=$2")
        .bind(case_tenant()).bind(expired.signing_attempt).fetch_one(&mut pg).await?;
    ensure!(unchanged);
    sqlx::query("UPDATE mdm_access.registration_admission SET paused=false WHERE tenant_id=$1::uuid AND channel='windows_mdm'")
        .bind(case_tenant()).execute(&mut pg).await?;
    audit_store.inject_next_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    // Both callers begin while the original prepared row has no successor.
    let barrier = tokio::sync::Barrier::new(2);
    let (first, second) = tokio::join!(
        async {
            barrier.wait().await;
            resume().await
        },
        async {
            barrier.wait().await;
            resume().await
        }
    );
    let intent = match (first, second) {
        (Ok(i), Err(rss_mdm_windows_channel::Error::CommitUnknown))
        | (Err(rss_mdm_windows_channel::Error::CommitUnknown), Ok(i)) => i,
        _ => anyhow::bail!("first replacement race did not produce one committed successor"),
    };
    ensure!(resume().await?.signing_attempt == intent.signing_attempt);
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid")
            .bind(case_tenant())
            .fetch_one(&mut pg)
            .await?;
    ensure!(
        after == before + 1,
        "replacement audit must commit once with its successor"
    );
    ensure!(intent.signing_attempt != expired.signing_attempt);
    ensure!(
        intent.registration == expired.registration
            && intent.credential == expired.credential
            && intent.epoch == expired.epoch
            && intent.sealed == expired.sealed
    );
    let replaced: (String, Option<Uuid>) = sqlx::query_as(
        "SELECT state,successor FROM mdm_pki.signing WHERE tenant_id=$1::uuid AND attempt=$2",
    )
    .bind(case_tenant())
    .bind(expired.signing_attempt)
    .fetch_one(&mut pg)
    .await?;
    ensure!(replaced == ("superseded".into(), Some(intent.signing_attempt)));
    ensure!(
        sign_certificate(&pool, audit_store.clone(), &w.channel.ca, &expired)
            .await
            .is_err()
    );
    let profile = certificate::IssuanceProfile::decode(&intent.profile)?;
    let request = certificate::Csr::verify(&csr)?;
    let pem = request.pem()?;
    let digest = request.digest();
    let subject = intent.registration.to_string();
    let issuer = profile
        .issuer
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let provider = w
        .channel
        .providers
        .get(rss_mdm_agent_wire::pki::Purpose::Windows, &issuer)?;
    let signing = rss_mdm_pki_service::signing::SigningStore::new(audit_store.clone());
    let sign = rss_mdm_pki_service::Sign {
        attempt: intent.signing_attempt,
        csr_pem: &pem,
        csr_digest: &digest,
        subject: &subject,
        sans: &[],
        start: profile.start,
        end: profile.end,
        deadline: profile.start + 60,
    };
    let calls = provider.sign_request_count();
    let mut original = None;
    let result = signing
        .issue(
            Uuid::parse_str(case_tenant())?,
            ("windows", &issuer),
            provider,
            sign,
            &|| Ok(now()),
            |chain| {
                original = Some(chain.to_vec());
                audit_store.inject_next_fault(
                    rss_transactional_messaging_postgres::PgTransactionFault::CommitPending,
                );
                true
            },
        )
        .await;
    ensure!(result.is_err());
    let original =
        original.ok_or_else(|| anyhow::anyhow!("CA did not actually return a certificate"))?;
    ensure!(provider.sign_request_count() == calls + 1);
    let unresolved: bool = sqlx::query_scalar("SELECT state='signing' AND chain IS NULL AND successor IS NULL FROM mdm_pki.signing WHERE tenant_id=$1::uuid AND attempt=$2")
        .bind(case_tenant()).bind(intent.signing_attempt).fetch_one(&mut pg).await?;
    ensure!(
        unresolved,
        "CA result unexpectedly persisted despite failed result commit"
    );
    ensure!(
        signing
            .issue(
                Uuid::parse_str(case_tenant())?,
                ("windows", &issuer),
                provider,
                sign,
                &|| Ok(now()),
                |_| true
            )
            .await
            .is_err()
    );
    let codec = rss_mdm_query::cursor::CursorCodec::new(&[31; 32])?;
    let view = windows_store
        .certificate_request(&proof, "windows-device", intent.signing_attempt, now())
        .await?;
    let view = serde_json::to_value(view)?;
    ensure!(
        view["signing"]["state"] == "signing"
            && view["linked"] == false
            && view["activated"] == false
    );
    ensure!(
        view["requirements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "original_ca_response")
    );
    let old = windows_store
        .certificate_request(&proof, "windows-device", expired.signing_attempt, now())
        .await?;
    ensure!(serde_json::to_value(old)?["signing"]["state"] == "superseded");
    let page = windows_store
        .certificate_requests(
            &proof,
            "windows-device",
            &rss_mdm_windows_channel::certificate_queries::REQUESTS.parse("limit=1")?,
            &codec,
            now(),
        )
        .await?;
    let page = serde_json::to_value(page)?;
    ensure!(page["items"].as_array().unwrap().len() == 1 && page["nextCursor"].is_string());
    ensure!(
        windows_store
            .certificate_request(&proof, "another-device", intent.signing_attempt, now())
            .await
            .is_err()
    );
    use base64::Engine;
    let operation = Uuid::new_v4();
    let recovery_audit = audit(
        &proof,
        operation,
        "windows-device",
        "device_pki_signing_recover",
    );
    registry
        .recover(
            &proof,
            &rss_mdm_pki_service::recovery::Recovery {
                operation,
                attempt: intent.signing_attempt,
                chain: original
                    .iter()
                    .map(|c| base64::engine::general_purpose::STANDARD.encode(c))
                    .collect(),
            },
            &recovery_audit,
            now(),
        )
        .await?;
    recovery_audit.finalize(None);
    let identity = rss_mdm_pki_service::signing_queries::ReceiptIdentity {
        actor: proof.principal_id().into(),
        instance: proof.instance_id().into(),
    };
    let recovered = windows_store
        .certificate_recovery_operation(
            &proof,
            "windows-device",
            intent.signing_attempt,
            operation,
            &identity,
        )
        .await?
        .unwrap();
    ensure!(recovered.attempt == intent.signing_attempt);
    ensure!(
        windows_store
            .certificate_recovery_operation(
                &proof,
                "windows-device",
                intent.signing_attempt,
                Uuid::new_v4(),
                &identity
            )
            .await?
            .is_none()
    );
    let ops = windows_store
        .certificate_recovery_operations(
            &proof,
            "windows-device",
            intent.signing_attempt,
            &rss_mdm_pki_service::signing_queries::OPERATIONS.parse("")?,
            &codec,
        )
        .await?;
    ensure!(serde_json::to_value(ops)?["items"][0]["operationId"] == operation.to_string());
    let view = serde_json::to_value(
        windows_store
            .certificate_request(&proof, "windows-device", intent.signing_attempt, now())
            .await?,
    )?;
    ensure!(
        view["signing"]["state"] == "issued"
            && view["linked"] == false
            && view["activated"] == false
    );
    ensure!(
        provider.sign_request_count() == calls + 1,
        "read dispatched a second CA request"
    );

    let cached = signing
        .issue(
            Uuid::parse_str(case_tenant())?,
            ("windows", &issuer),
            provider,
            sign,
            &|| Ok(now()),
            |_| true,
        )
        .await?;
    ensure!(
        cached == original && provider.sign_request_count() == calls + 1,
        "recovery dispatched a second CA request"
    );
    let cert = sign_certificate(&pool, audit_store.clone(), &w.channel.ca, &intent).await?;
    ensure!(cert == original[0]);
    ensure!(cert == sign_certificate(&pool, audit_store.clone(), &w.channel.ca, &intent).await?);
    // CSR, enrollment context and protocol protection identity are immutable on retry.
    ensure!(
        rss_mdm_windows_channel::issuance::issuance_intent(
            &audit_store,
            &windows_store.clone(),
            &w.channel,
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
        rss_mdm_windows_channel::issuance::issuance_intent(
            &audit_store,
            &windows_store.clone(),
            &w.channel,
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
        w.channel
            .open_secrets_fixture(crate::test_support::case::peer(), auth.id, &intent.sealed)
            .is_err()
    );
    let mut altered = intent.sealed.clone();
    altered[15] ^= 1;
    ensure!(
        w.channel
            .open_secrets_fixture(case_tenant(), auth.id, &altered)
            .is_err()
    );
    ensure!(
        w.channel
            .ca
            .verify(&[CertificateDer::from(cert.as_slice())], now() + 91 * 86400)
            .is_err()
    );
    let mut wrong_usage = x509_cert::Certificate::from_der(&cert)?.tbs_certificate;
    wrong_usage
        .extensions
        .as_mut()
        .unwrap()
        .retain(|e| e.extn_id.to_string() != "2.5.29.37");
    let wrong_usage = sign_fixture(&wrong_usage)?;
    ensure!(
        w.channel
            .ca
            .verify(&[CertificateDer::from(wrong_usage)], now())
            .is_err()
    );

    let checked = w
        .channel
        .ca
        .verify(&[CertificateDer::from(cert.as_slice())], now())?;
    let credential = crate::device::ChannelMount::new(
        rss_request_context::TenantId::parse(case_tenant())?,
        rss_mdm_inventory::ReportSource::MdmWindows,
        rss_mdm_registration_service::Purpose::Primary,
    )
    .credential(checked.fingerprint())?;
    let service = crate::device::DeviceService::new(
        registration_store.clone(),
        case_tenant().into(),
        audit_store.clone(),
    );
    ensure!(
        service.management_principal(&credential).await.is_err(),
        "unbound signed certificate admitted"
    );
    let mut unrelated = x509_cert::Certificate::from_der(&cert)?.tbs_certificate;
    unrelated.subject = format!("CN={}", Uuid::new_v4()).parse()?;
    let unrelated = sign_fixture(&unrelated)?;
    w.channel
        .ca
        .verify(&[CertificateDer::from(unrelated.as_slice())], now())?;
    ensure!(matches!(
        complete(&audit_store, &w, &auth, &proof, &intent, &unrelated).await,
        Err(Error::Windows(rss_mdm_windows_channel::Error::Conflict))
    ));
    ensure!(service.management_principal(&credential).await.is_err());
    // Failed final write leaves only the exact immutable intent.
    audit_store
        .inject_next_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
    ensure!(
        complete(&audit_store, &w, &auth, &proof, &intent, &cert)
            .await
            .is_err()
    );
    ensure!(service.management_principal(&credential).await.is_err());
    let (restarted_pool, restarted_source, restarted_audit) =
        crate::audit_test_support::request_store().await?;
    let restarted_registration = Arc::new(rss_mdm_registration_service::Store::from_pool(
        restarted_pool.clone(),
        Arc::new(crate::registration_lifecycle::Bridge),
    ));
    let restarted_authorization = Arc::new(rss_mdm_authorization_service::Store::from_pool(
        restarted_pool.clone(),
        Arc::new(crate::lifecycle::RuntimeTimer),
    ));
    let restarted = Arc::new(rss_mdm_windows_channel::Store::from_pool(
        restarted_pool.clone(),
        restarted_registration,
        restarted_authorization,
    ));
    let restarted_ca = windows()?;
    let saved = rss_mdm_windows_channel::issuance::issuance_intent(
        &audit_store,
        &restarted.clone(),
        &restarted_ca.channel,
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
        saved.profile == intent.profile
            && saved.registration == intent.registration
            && sign_certificate(&pool, audit_store.clone(), &restarted_ca.channel.ca, &saved)
                .await?
                == cert
    );
    audit_store.inject_next_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    ensure!(matches!(
        complete(&audit_store, &w, &auth, &proof, &intent, &cert).await,
        Err(Error::Windows(
            rss_mdm_windows_channel::Error::CommitUnknown
        ))
    ));
    complete(
        restarted_audit.clone().as_ref(),
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
    let successes = crate::audit_test_support::read(&mut pg, crate::test_support::case::tenant())
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
            &audit_store,
            &proof,
            &device,
            &password,
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .await?;
        let a = crate::enrollment::store::enrollment_authorization(
            &registration_store.clone(),
            case_tenant(),
            r.enrollment_id,
            &password,
        )
        .await?;
        let i = rss_mdm_windows_channel::issuance::issuance_intent(
            &audit_store,
            &windows_store.clone(),
            &w.channel,
            &a,
            &proof,
            (
                &csr,
                rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
            ),
            now(),
        )
        .await?;
        let c = sign_certificate(&pool, audit_store.clone(), &w.channel.ca, &i).await?;
        audit_store.inject_next_fault(if fault == 3 {
            rss_transactional_messaging_postgres::PgTransactionFault::CommitPending
        } else {
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck
        });
        if fault == 3 {
            let request_audit = audit(&proof, a.operation, &a.device, "enrollment_issue");
            let mount = crate::device::ChannelMount::new(
                rss_request_context::TenantId::parse(case_tenant())?,
                rss_mdm_inventory::ReportSource::MdmWindows,
                rss_mdm_registration_service::Purpose::Primary,
            );
            {
                let mut pending = Box::pin(rss_mdm_windows_channel::issuance::complete_issuance(
                    &audit_store,
                    &w.channel,
                    &a,
                    &proof,
                    &i,
                    &c,
                    &request_audit,
                    now(),
                    &mount,
                    &crate::registration_lifecycle::Bridge,
                ));
                tokio::select! {
                    result = &mut pending => anyhow::bail!("issuance never reached pending commit: {result:?}"),
                    reached = tokio::time::timeout(Duration::from_secs(5), async {
                        while request_audit.snapshot().write_outcome != rss_mdm_audit_integration::WriteOutcome::Unknown {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    }) => reached?,
                }
                let result = tokio::time::timeout(Duration::from_millis(200), &mut pending).await;
                ensure!(
                    result.is_err(),
                    "pending commit completed without cancellation: {result:?}"
                );
            }
            request_audit.finalize(Some(rss_mdm_audit_integration::FailureReason::Cancelled));
        } else {
            ensure!(matches!(
                complete(&audit_store, &w, &a, &proof, &i, &c).await,
                Err(Error::Windows(
                    rss_mdm_windows_channel::Error::CommitUnknown
                ))
            ));
        }
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
        audit_store.clone().as_ref(),
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
            &registration_store.clone(),
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
    let resumed = crate::enrollment::store::enrollment_authorization(
        &registration_store.clone(),
        case_tenant(),
        auth.id,
        &next,
    )
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
            &audit_store,
            &proof,
            device,
            &password,
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .await?;
        let auth = crate::enrollment::store::enrollment_authorization(
            &registration_store.clone(),
            case_tenant(),
            pending.enrollment_id,
            &password,
        )
        .await?;
        let intent = rss_mdm_windows_channel::issuance::issuance_intent(
            &audit_store,
            &windows_store.clone(),
            &w.channel,
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
                audit_store.clone().as_ref(),
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
            crate::test_support::identity::change_grants(
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
            &sign_certificate(&pool, audit_store.clone(), &w.channel.ca, &intent).await?,
        )
        .await;
        if cause == "permission" {
            crate::test_support::identity::change_grants(
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
        &audit_store,
        &proof,
        "audit-race",
        &password,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await?;
    let a = crate::enrollment::store::enrollment_authorization(
        &registration_store.clone(),
        case_tenant(),
        r.enrollment_id,
        &password,
    )
    .await?;
    let i = rss_mdm_windows_channel::issuance::issuance_intent(
        &audit_store,
        &windows_store.clone(),
        &w.channel,
        &a,
        &proof,
        (
            &csr,
            rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
        ),
        now(),
    )
    .await?;
    let c = sign_certificate(&pool, audit_store.clone(), &w.channel.ca, &i).await?;
    pg.execute("REVOKE EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) FROM mdm_access")
        .await?;
    let failed = complete(&audit_store, &w, &a, &proof, &i, &c).await;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let rejected = rss_mdm_audit_integration::AuditStore::new(
        pool.clone(),
        rss_audit_postgres::Integrity::Plain,
        source.clone(),
        rss_request_context::TenantId::parse(case_tenant())?,
        &budget.control(),
    )
    .await
    .is_err();
    pg.execute("GRANT EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) TO mdm_access")
        .await?;
    ensure!(rejected);
    ensure!(matches!(
        failed,
        Err(Error::Windows(rss_mdm_windows_channel::Error::Unavailable(
            rss_mdm_windows_channel::Failure::Audit
        )))
    ));
    complete(&audit_store, &w, &a, &proof, &i, &c).await?;
    // Two accepted enrollments freeze the same base; only one final generation can win.
    let first = create(
        &audit_store,
        &proof,
        "concurrent-windows",
        &password,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await?;
    let second = create(
        &audit_store,
        &proof,
        "concurrent-windows",
        &password,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await?;
    let a1 = crate::enrollment::store::enrollment_authorization(
        &registration_store.clone(),
        case_tenant(),
        first.enrollment_id,
        &password,
    )
    .await?;
    let a2 = crate::enrollment::store::enrollment_authorization(
        &registration_store.clone(),
        case_tenant(),
        second.enrollment_id,
        &password,
    )
    .await?;
    let i1 = rss_mdm_windows_channel::issuance::issuance_intent(
        &audit_store,
        &windows_store.clone(),
        &w.channel,
        &a1,
        &proof,
        (
            &csr,
            rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
        ),
        now(),
    )
    .await?;
    let i2 = rss_mdm_windows_channel::issuance::issuance_intent(
        &audit_store,
        &windows_store.clone(),
        &w.channel,
        &a2,
        &proof,
        (
            &csr,
            rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
        ),
        now(),
    )
    .await?;
    let (c1, c2) = (
        sign_certificate(&pool, audit_store.clone(), &w.channel.ca, &i1).await?,
        sign_certificate(&pool, audit_store.clone(), &w.channel.ca, &i2).await?,
    );
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
            audit_store.clone().as_ref(),
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
    pg.close().await?;
    restarted_source.close().await;
    restarted_pool.close().await;
    source.close().await;
    pool.close().await;
    Ok(())
}

// Deliberately bypass the product issuer to exercise rejection of validly signed bad leaves.
fn sign_fixture(tbs: &x509_cert::TbsCertificate) -> anyhow::Result<Vec<u8>> {
    let key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &std::fs::read(
            PathBuf::from(std::env::var("MDM_WINDOWS_PKI_FIXTURES")?)
                .join("windows-issuer-test.pk8"),
        )?,
        &ring::rand::SystemRandom::new(),
    )
    .map_err(|_| anyhow::anyhow!("fixture issuer key"))?;
    let signature = key
        .sign(&ring::rand::SystemRandom::new(), &tbs.to_der()?)
        .map_err(|_| anyhow::anyhow!("fixture issuer signature"))?;
    Ok(x509_cert::Certificate {
        tbs_certificate: tbs.clone(),
        signature_algorithm: tbs.signature.clone(),
        signature: x509_cert::der::asn1::BitString::from_bytes(signature.as_ref())?,
    }
    .to_der()?)
}

#[tokio::test]
#[ignore = "make t2 MODULE=windows.issuance"]
async fn native_renewal_preserves_registration_and_activates_only_after_new_tls_proof()
-> anyhow::Result<()> {
    use base64::Engine;
    use rss_mdm_windows_mdm::{
        CodecLimits, Secret,
        soap::{self, Body},
    };
    use x509_cert::der::{EncodePem, pem::LineEnding};
    let mut host = Host::renewal_window().await?;
    host.listen().await?;
    let peer = host.enrolled_peer().await?;
    let ca = &host.windows.as_ref().channel.ca;
    let certificate = sign_certificate(
        &host.authority.pool.clone(),
        host.authority.audit.clone(),
        ca,
        &peer.intent,
    )
    .await?;
    let temporary = tempfile::tempdir()?;
    let signer = temporary.path().join("signer.pem");
    std::fs::write(
        &signer,
        x509_cert::Certificate::from_der(&certificate)?.to_pem(LineEnding::LF)?,
    )?;
    let signed = temporary.path().join("renew.p7");
    let mut child = tokio::process::Command::new("openssl")
        .args([
            "cms",
            "-sign",
            "-binary",
            "-nodetach",
            "-nosmimecap",
            "-md",
            "sha256",
            "-outform",
            "DER",
        ])
        .arg("-in")
        .arg(host.root.join("renew-device.csr"))
        .arg("-signer")
        .arg(&signer)
        .arg("-inkey")
        .arg(host.root.join("device.key"))
        .arg("-out")
        .arg(&signed)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let status = match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
        Ok(status) => status?,
        Err(error) => {
            child.kill().await?;
            child.wait().await?;
            return Err(error.into());
        }
    };
    ensure!(status.success(), "CMS fixture signing failed");
    let cms = std::fs::read(signed)?;
    let verified = ca.renewal(&cms, &certificate, now())?;
    ensure!(verified.csr() == std::fs::read(host.root.join("renew-device.csr"))?);
    let mut bad = cms.clone();
    *bad.last_mut().unwrap() ^= 1;
    ensure!(ca.renewal(&bad, &certificate, now()).is_err());
    // Stop after the production prepare transaction, before the first CA claim.
    let prepare_audit = rss_mdm_audit_integration::RequestAudit::new(
        case_tenant().to_owned(),
        "windows_renewal",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let (_, expired_attempt) = rss_mdm_windows_channel::issuance::fixture::prepare_renewal(
        &host.windows_state,
        &certificate,
        &cms,
        &prepare_audit,
        rss_mdm_registration_service::Purpose::Primary,
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(61)).await;
    let mut request = peer.issue.clone();
    request.header.security = None;
    let renewal_path = format!(
        "{}/EnrollmentServer/Enrollment.svc",
        host.windows.channel.management_origin
    );
    request.header.to = Some(renewal_path.clone());
    request.header.message_id = Some(format!("urn:uuid:{}", Uuid::new_v4()));
    let Body::Issue(input) = &mut request.body else {
        unreachable!()
    };
    input.request = soap::CertificateRequest::RenewalPkcs7(Secret(cms));
    input.additional_context.0.clear();
    let wire = soap::encode(&request, &CodecLimits::default())?;
    ensure!(
        host.client
            .post(&renewal_path)
            .header("content-type", "application/soap+xml")
            .body(wire.clone())
            .send()
            .await?
            .status()
            != axum::http::StatusCode::OK,
        "renewal without TLS identity"
    );
    let mut bootstrap_renewal = request.clone();
    bootstrap_renewal.header.to = Some(peer.path.clone());
    ensure!(
        peer.mutual
            .post(&peer.path)
            .header("content-type", "application/soap+xml")
            .body(soap::encode(&bootstrap_renewal, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            != axum::http::StatusCode::OK,
        "bootstrap admitted certificate renewal"
    );
    let send = || {
        peer.mutual
            .post(&renewal_path)
            .header("content-type", "application/soap+xml")
            .body(wire.clone())
            .send()
    };
    let first = send().await?;
    ensure!(
        first.status() == axum::http::StatusCode::OK,
        "renewal issuance {}",
        first.status()
    );
    let first = soap::decode_response(&request, &first.bytes().await?, &CodecLimits::default())?;
    let replay = soap::decode_response(
        &request,
        &send().await?.bytes().await?,
        &CodecLimits::default(),
    )?;
    let (Body::IssueResponse(first), Body::IssueResponse(replay)) = (first.body, replay.body)
    else {
        anyhow::bail!("renewal response")
    };
    ensure!(
        first.provisioning == replay.provisioning,
        "renewal replay minted another certificate"
    );
    let mut observed = PgConnection::connect_with(&options("postgres")?).await?;
    let replaced: (String, Option<Uuid>) = sqlx::query_as(
        "SELECT state,successor FROM mdm_pki.signing WHERE tenant_id=$1::uuid AND attempt=$2",
    )
    .bind(case_tenant())
    .bind(expired_attempt)
    .fetch_one(&mut observed)
    .await?;
    ensure!(replaced.0 == "superseded" && replaced.1.is_some());
    let state: String = sqlx::query_scalar(
        "SELECT state FROM mdm_pki.signing WHERE tenant_id=$1::uuid AND attempt=$2",
    )
    .bind(case_tenant())
    .bind(replaced.1.unwrap())
    .fetch_one(&mut observed)
    .await?;
    ensure!(state == "issued");
    let document = String::from_utf8(first.provisioning.0)?;
    ensure!(!document.contains("AAUTHSECRET") && !document.contains("EntDMID"));
    let encoded = document
        .split("name=\"EncodedCertificate\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .ok_or_else(|| anyhow::anyhow!("renewal certificate missing"))?;
    let der = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let new_certificate = x509_cert::Certificate::from_der(&der)?;
    ensure!(der != certificate);
    let identity = reqwest::Identity::from_pem(
        &[
            new_certificate.to_pem(LineEnding::LF)?.as_bytes(),
            &std::fs::read(host.root.join("renew-device.key"))?,
        ]
        .concat(),
    )?;
    let renewed = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(host.root_cert.clone())
        .identity(identity)
        .timeout(Duration::from_secs(12))
        .build()?;
    let initial = rss_mdm_windows_mdm::syncml::encode(&peer.message, &CodecLimits::default())?;
    ensure!(
        peer.mutual
            .post(&peer.url)
            .header("content-type", "application/vnd.syncml.dm+xml")
            .body(initial.clone())
            .send()
            .await?
            .status()
            == axum::http::StatusCode::OK,
        "old credential disabled before new proof"
    );
    let mut message = peer.message.clone();
    message.header.session_id = 1502;
    let active = renewed
        .post(&peer.url)
        .header("content-type", "application/vnd.syncml.dm+xml")
        .body(rss_mdm_windows_mdm::syncml::encode(
            &message,
            &CodecLimits::default(),
        )?)
        .send()
        .await?;
    ensure!(
        active.status() == axum::http::StatusCode::OK,
        "new identity activation {}",
        active.status()
    );
    ensure!(
        peer.mutual
            .post(&peer.url)
            .header("content-type", "application/vnd.syncml.dm+xml")
            .body(initial)
            .send()
            .await?
            .status()
            == axum::http::StatusCode::UNAUTHORIZED,
        "old credential survived activation"
    );
    let scope = host
        .devices
        .current_scope(
            &peer.proof,
            crate::test_support::case::name("tls-device"),
            crate::device::coordinates::Coordinates {
                source: rss_mdm_inventory::ReportSource::MdmWindows,
            },
        )
        .await?;
    ensure!(
        scope.registration().as_str() == peer.intent.registration.to_string(),
        "renewal created a new registration"
    );
    host.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=windows.issuance"]
async fn management_certificate_queries_follow_the_original_device() -> anyhow::Result<()> {
    use crate::test_support::{Method, StatusCode};
    let mut host = Host::open().await?;
    let result = async {
        host.listen().await?;
        let peer = host.enrolled_peer().await?;
        let mut browser = host.authority.browser("admin")?;
        let device = crate::test_support::case::name("tls-device");
        let list = format!("/api/v1/devices/{device}/windows-certificate-requests?limit=1");
        let (status, page) = browser
            .call(&host.browser, Method::GET, &list, None)
            .await?;
        ensure!(
            status == StatusCode::OK && page["items"].as_array().is_some_and(|v| !v.is_empty()),
            "Windows HTTP request directory unavailable"
        );
        let row = &page["items"][0];
        let attempt = row["attempt"].as_str().unwrap();
        ensure!(row["enrollmentId"] == peer.receipt.enrollment_id.to_string());
        let detail = format!("/api/v1/devices/{device}/windows-certificate-requests/{attempt}");
        let (status, row) = browser
            .call(&host.browser, Method::GET, &detail, None)
            .await?;
        ensure!(
            status == StatusCode::OK
                && row["signing"]["state"] == "issued"
                && row["linked"] == true
        );
        let ops = format!("{detail}/recovery-operations");
        ensure!(
            browser
                .call(&host.browser, Method::GET, &ops, None)
                .await?
                .0
                == StatusCode::OK
        );
        ensure!(
            browser
                .call(
                    &host.browser,
                    Method::GET,
                    &format!("{ops}/{}", Uuid::new_v4()),
                    None
                )
                .await?
                .0
                == StatusCode::BAD_REQUEST
        );
        let mut other = host.authority.browser("other")?;
        crate::test_support::http::change_device_grants(
            &mut other,
            "outside-device",
            &["credentials"],
        )
        .await?;
        ensure!(
            other
                .call(&host.browser, Method::GET, &detail, None)
                .await?
                .0
                == StatusCode::FORBIDDEN
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = host.close().await;
    result?;
    cleanup
}
