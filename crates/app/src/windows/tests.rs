use super::*;
use crate::{
    AccessStore,
    access::InventoryService,
    device::tests::{admin, options, policy},
    enrollment::{Authorization, Password},
    sessions::{Session, Sessions},
};
use anyhow::ensure;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_identity_client::{Clock, VerifiedIdentity};
use rss_mdm_windows_mdm::syncml::{self, Command, CommandName};
use sqlx::{Connection, Executor, PgConnection};
use std::{path::PathBuf, time::Duration};
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_cert::der::{Decode, Encode};
use zeroize::Zeroizing;
const TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
fn root() -> anyhow::Result<PathBuf> {
    Ok(std::env::var("MDM_WINDOWS_FIXTURES")?.into())
}
fn now() -> i64 {
    rss_identity_client::SystemClock.unix_seconds().unwrap()
}
fn windows() -> anyhow::Result<Windows> {
    let config = serde_json::from_slice(&std::fs::read(root()?.join("windows.json"))?)?;
    Ok(Windows::load(config, now())?)
}
fn audit(proof: &VerifiedIdentity, key: Uuid, device: &str, action: &'static str) -> Audit {
    let a = Audit::new(proof.tenant_id().into(), action);
    a.identify(proof);
    a.target(device);
    a.operation(key, action);
    a
}
async fn create(
    store: &AccessStore,
    proof: &VerifiedIdentity,
    device: &str,
    password: &Password,
    reference: Uuid,
    key: Uuid,
) -> anyhow::Result<crate::enrollment::Receipt> {
    let a = audit(proof, key, device, "enrollment_create");
    let receipt = store
        .create_enrollment(
            policy(TENANT, true, true).enrollment(proof, device)?,
            password,
            reference,
            key,
            &a,
        )
        .await;
    a.finalize(None);
    Ok(receipt?)
}
async fn complete(
    store: &AccessStore,
    w: &Windows,
    auth: &Authorization,
    proof: &VerifiedIdentity,
    intent: &issuance::Intent,
    cert: &[u8],
) -> Result<(), Error> {
    let a = audit(proof, auth.operation, &auth.device, "enrollment_issue");
    let result = store
        .complete_issuance(w, auth, proof, intent, cert, &a, now())
        .await;
    a.finalize(None);
    result
}
#[test]
fn digest_uses_binary_nonce_and_challenge_round_trips() {
    let nonce = [0u8; 32];
    assert_ne!(
        protection::digest("server", "password", &nonce),
        protection::digest("server", "password", STANDARD.encode(nonce).as_bytes())
    );
    let mut message = syncml::decode(
        include_bytes!("../../../windows-mdm/tests/fixtures/status-details.xml"),
        &CodecLimits::default(),
    )
    .unwrap();
    let Command::Status(status) = &mut message.commands[0] else {
        panic!()
    };
    status.challenge = Some(syncml::Challenge {
        media_type: "syncml:auth-md5".into(),
        nonce: Some(Secret(STANDARD.encode(nonce))),
    });
    let bytes = syncml::encode(&message, &CodecLimits::default()).unwrap();
    assert_eq!(
        syncml::decode(&bytes, &CodecLimits::default()).unwrap(),
        message
    );
    let bad = String::from_utf8(bytes)
        .unwrap()
        .replace(&STANDARD.encode(nonce), "bad!");
    assert!(syncml::decode(bad.as_bytes(), &CodecLimits::default()).is_err());
}
#[tokio::test]
#[ignore = "make t2: real signatures, PostgreSQL, minimum role and SDK over TLS"]
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
    let proof = admin(TENANT, "admin-a").await?;
    let other = admin(TENANT, "other-a").await?;
    let store = AccessStore::connect(options("mdm_access")?).await?;
    let mut pg = PgConnection::connect_with(&options("postgres")?).await?;
    let password = Password::new(crate::sessions::random())?;
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
    ensure!(
        create(
            &store,
            &proof,
            "windows-device",
            &password,
            Uuid::new_v4(),
            key
        )
        .await?
            == receipt
    );
    ensure!(
        create(&store, &proof, "different", &password, Uuid::new_v4(), key)
            .await
            .is_err()
    );
    ensure!(
        store
            .enrollment_target(&other, receipt.enrollment_id)
            .await
            .is_err()
    );
    ensure!(
        store
            .enrollment_authorization(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                receipt.enrollment_id,
                &password
            )
            .await
            .is_err()
    );
    ensure!(
        store
            .enrollment_authorization(
                TENANT,
                receipt.enrollment_id,
                &Password::new(crate::sessions::random())?
            )
            .await
            .is_err()
    );
    let auth = store
        .enrollment_authorization(TENANT, receipt.enrollment_id, &password)
        .await?;
    let intent = store
        .issuance_intent(
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
        store
            .issuance_intent(
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
        store
            .issuance_intent(
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
            .open(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                auth.id,
                &intent.sealed
            )
            .is_err()
    );
    let mut altered = intent.sealed.clone();
    altered[15] ^= 1;
    ensure!(w.protection.open(TENANT, auth.id, &altered).is_err());
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
        rss_request_context::TenantId::parse(TENANT)?,
        &checked,
    );
    let access = Arc::new(store);
    let service = crate::device::DeviceService::new(
        access.clone(),
        policy(TENANT, true, true),
        None,
        monotonic(),
    );
    ensure!(
        service.management_principal(&credential).await.is_err(),
        "unbound signed certificate admitted"
    );
    // Failed final write leaves only the exact immutable intent.
    access.fail_next(1);
    ensure!(
        complete(&access, &w, &auth, &proof, &intent, &cert)
            .await
            .is_err()
    );
    ensure!(service.management_principal(&credential).await.is_err());
    let restarted = AccessStore::connect(options("mdm_access")?).await?;
    let restarted_ca = windows()?;
    let saved = restarted
        .issuance_intent(
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
    access.fail_next(2);
    ensure!(matches!(
        complete(&access, &w, &auth, &proof, &intent, &cert).await,
        Err(Error::CommitUnknown)
    ));
    complete(&restarted, &restarted_ca, &auth, &proof, &saved, &cert).await?;
    ensure!(
        service
            .management_principal(&credential)
            .await?
            .registration()
            == intent.registration
    );
    let successes:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.audit WHERE tenant_id=$1::uuid AND action='enrollment_issue' AND operation_id=$2::uuid AND result='success'").bind(TENANT).bind(auth.operation.to_string()).fetch_one(&mut pg).await?;
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
        let a = access
            .enrollment_authorization(TENANT, r.enrollment_id, &password)
            .await?;
        let i = access
            .issuance_intent(
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
        access.fail_next(fault);
        ensure!(
            tokio::time::timeout(
                Duration::from_millis(200),
                complete(&access, &w, &a, &proof, &i, &c)
            )
            .await
            .is_err()
        );
        complete(&access, &w, &a, &proof, &i, &c).await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2",
        )
        .bind(TENANT)
        .bind(&device)
        .fetch_one(&mut pg)
        .await?;
        ensure!(count == 1);
    }
    // Rotation invalidates an in-flight authorization without replacing the CSR or generation.
    let next = Password::new(crate::sessions::random())?;
    let resume_key = Uuid::new_v4();
    let a = audit(&proof, resume_key, "windows-device", "enrollment_resume");
    access
        .change_enrollment(
            policy(TENANT, true, true).enrollment(&proof, "windows-device")?,
            auth.id,
            Some((&next, Uuid::new_v4())),
            resume_key,
            &a,
        )
        .await?;
    a.finalize(None);
    ensure!(
        access
            .enrollment_authorization(TENANT, auth.id, &password)
            .await
            .is_err()
    );
    ensure!(
        complete(&access, &w, &auth, &proof, &intent, &cert)
            .await
            .is_err()
    );
    let resumed = access
        .enrollment_authorization(TENANT, auth.id, &next)
        .await?;
    ensure!(
        resumed.operation == auth.operation
            && resumed.expected_generation == auth.expected_generation
    );
    complete(&access, &w, &resumed, &proof, &intent, &cert).await?;
    // Cancelled/expired authorizations cannot publish an already computed signature.
    for (device, cancel) in [("cancel-race", true), ("expiry-race", false)] {
        let pending = create(
            &access,
            &proof,
            device,
            &password,
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .await?;
        let auth = access
            .enrollment_authorization(TENANT, pending.enrollment_id, &password)
            .await?;
        let intent = access
            .issuance_intent(
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
        if cancel {
            let key = Uuid::new_v4();
            let a = audit(&proof, key, device, "enrollment_cancel");
            access
                .change_enrollment(
                    policy(TENANT, true, true).enrollment(&proof, device)?,
                    auth.id,
                    None,
                    key,
                    &a,
                )
                .await?;
            a.finalize(None);
        } else {
            sqlx::query("UPDATE mdm_access.requests SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(TENANT).bind(auth.id.to_string()).execute(&mut pg).await?;
        }
        ensure!(
            complete(
                &access,
                &w,
                &auth,
                &proof,
                &intent,
                &w.ca.sign(&intent.tbs)?
            )
            .await
            .is_err()
        );
    }
    // Audit failure rolls back the entire final binding, then the same intent can finish.
    let r = create(
        &access,
        &proof,
        "audit-race",
        &password,
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .await?;
    let a = access
        .enrollment_authorization(TENANT, r.enrollment_id, &password)
        .await?;
    let i = access
        .issuance_intent(
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
    pg.execute("REVOKE INSERT ON mdm_access.audit FROM mdm_access")
        .await?;
    let failed = complete(&access, &w, &a, &proof, &i, &c).await;
    ensure!(AccessStore::connect(options("mdm_access")?).await.is_err());
    pg.execute("GRANT INSERT ON mdm_access.audit TO mdm_access")
        .await?;
    ensure!(matches!(failed, Err(Error::Unavailable(Failure::Audit))));
    complete(&access, &w, &a, &proof, &i, &c).await?;
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
    let a1 = access
        .enrollment_authorization(TENANT, first.enrollment_id, &password)
        .await?;
    let a2 = access
        .enrollment_authorization(TENANT, second.enrollment_id, &password)
        .await?;
    let i1 = access
        .issuance_intent(
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
    let i2 = access
        .issuance_intent(
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
        complete(&access, &w, &a1, &proof, &i1, &c1),
        complete(&access, &w, &a2, &proof, &i2, &c2)
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
        complete(&access, &w, &resumed, &proof, &intent, &cert)
            .await
            .is_err()
    );
    let key = Uuid::new_v4();
    let a = audit(&proof, key, "windows-device", "enrollment_resume");
    ensure!(
        access
            .change_enrollment(
                policy(TENANT, true, true).enrollment(&proof, "windows-device")?,
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
            "GRANT SELECT ON mdm_access.audit TO mdm_access",
            "REVOKE SELECT ON mdm_access.audit FROM mdm_access",
        ),
    ] {
        pg.execute(grant).await?;
        let rejected = AccessStore::connect(options("mdm_access")?).await.is_err();
        pg.execute(revoke).await?;
        ensure!(rejected);
    }
    pg.close().await?;
    restarted.close().await;
    access.close().await;
    Ok(())
}
#[allow(clippy::disallowed_methods, reason = "test composition root")]
fn monotonic() -> Arc<dyn rss_observation::Clock> {
    Arc::new(crate::Monotonic(std::time::Instant::now))
}

struct Running {
    stop: tokio_util::sync::CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<Result<(), rss_runtime::ShutdownError>>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Running {
    async fn close(mut self) -> anyhow::Result<()> {
        self.stop.cancel();
        for task in self.tasks.drain(..) {
            tokio::time::timeout(Duration::from_secs(10), task).await???;
        }
        Ok(())
    }
}
#[tokio::test]
#[ignore = "make t2: native HTTPS enrollment and mTLS management with real PG"]
async fn native_tls_enrollment_management_replay_and_revoke() -> anyhow::Result<()> {
    use x509_cert::der::{EncodePem, pem::LineEnding};
    let root = root()?;
    let enroll = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let manage = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))?;
    value["windows"] = serde_json::from_slice(&std::fs::read(root.join("windows.json"))?)?;
    value["windows"]["enrollment"]["origin"] =
        serde_json::json!(format!("https://localhost:{}", enroll.local_addr()?.port()));
    value["windows"]["enrollment"]["listen"] = serde_json::json!(enroll.local_addr()?.to_string());
    value["windows"]["management"]["origin"] =
        serde_json::json!(format!("https://localhost:{}", manage.local_addr()?.port()));
    value["windows"]["management"]["listen"] = serde_json::json!(manage.local_addr()?.to_string());
    value["identity"]["origin"] = serde_json::json!(std::env::var("MDM_TEST_IDENTITY")?);
    value["identity"]["issuer"] = value["identity"]["origin"].clone();
    value["identity"]["tenant_id"] = serde_json::json!(TENANT);
    value["identity"]["audience"] = serde_json::json!("rss-mdm");
    value["identity"]["oidc_secret_file"] = serde_json::json!(root.join("oidc-windows-secret"));
    value["identity"]["validation_secret_file"] =
        serde_json::json!(root.join("validation-windows-secret"));
    value["identity"]["ca_file"] = serde_json::json!(root.join("ca.crt"));
    let config: crate::config::Config = serde_json::from_value(value)?;
    let clock = Arc::new(rss_identity_client::SystemClock);
    let identity = crate::identity::Identity::connect(&config, clock.clone()).await?;
    let sessions = Sessions::new(clock, 100, 100);
    let session = sessions.establish(
        None,
        Session {
            credential: Zeroizing::new("admin-a".into()),
            subject: "administrator".into(),
            identity_session: "11111111-1111-4111-8111-111111111111".into(),
            csrf: crate::sessions::random(),
            expires: now() + 600,
        },
    )?;
    let reference = sessions.reference(&sessions.get(&session)?)?;
    ensure!(
        sessions.get(&reference.to_string()).is_err(),
        "non-login reference was a login cookie"
    );
    let store = Arc::new(AccessStore::connect(options("mdm_access")?).await?);
    let policy = policy(TENANT, true, true);
    let devices = Arc::new(crate::device::DeviceService::new(
        store.clone(),
        policy.clone(),
        None,
        monotonic(),
    ));
    let reader =
        Arc::new(rss_mdm_inventory_postgres::InventoryReader::connect(options("mdm_api")?).await?);
    let app = Arc::new(App {
        identity,
        sessions,
        policy,
        inventory: InventoryService::new(reader.clone(), devices.clone()),
        devices,
        access: store.clone(),
        origin: config.product_origin,
        requests: Arc::new(tokio::sync::Semaphore::new(4)),
        windows: Windows::load(config.windows, now())?,
    });
    let (enrollment, management) = routers(app.clone(), monotonic());
    let stop = tokio_util::sync::CancellationToken::new();
    let running = Running {
        stop: stop.clone(),
        tasks: vec![
            tokio::spawn(tls::serve(
                enroll,
                enrollment,
                store.clone(),
                TENANT.into(),
                "mdm-enrollment-tls",
                stop.clone(),
            )),
            tokio::spawn(tls::serve(
                manage,
                management,
                store.clone(),
                TENANT.into(),
                "mdm-management-tls",
                stop,
            )),
        ],
    };
    let root_cert = reqwest::Certificate::from_pem(&std::fs::read(root.join("ca.crt"))?)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(root_cert.clone())
        .timeout(Duration::from_secs(12))
        .build()?;
    let proof = admin(TENANT, "admin-a").await?;
    let plain = crate::sessions::random();
    let password = Password::new(plain.clone())?;
    let receipt = create(
        &store,
        &proof,
        "tls-device",
        &password,
        reference,
        Uuid::new_v4(),
    )
    .await?;
    let path = format!(
        "{}/EnrollmentServer/Enrollment.svc",
        app.windows.config.enrollment.origin
    );
    let mut issue = soap::decode(
        include_bytes!("../../../windows-mdm/tests/fixtures/issue-request.xml"),
        Operation::Issue,
        &CodecLimits::default(),
    )?;
    issue.header.to = Some(path.clone());
    let token = issue
        .header
        .security
        .as_mut()
        .unwrap()
        .username
        .as_mut()
        .unwrap();
    token.username = Secret(receipt.enrollment_id.to_string());
    token.password = Secret(plain);
    let Body::Issue(body) = &mut issue.body else {
        panic!()
    };
    body.csr = Secret(std::fs::read(root.join("device.csr"))?);
    for (key, value) in &mut body.additional_context.0 {
        if key == "DeviceID" {
            *value = "tls-device".into();
        }
    }
    let wire = soap::encode(&issue, &CodecLimits::default())?;
    let response = client
        .post(&path)
        .header("content-type", "application/soap+xml")
        .body(wire.clone())
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "WSTEP failed: {:?}",
        response.status()
    );
    let first = response.bytes().await?;
    let decoded = soap::decode_response(&issue, &first, &CodecLimits::default())?;
    let Body::IssueResponse(result) = decoded.body else {
        panic!()
    };
    ensure!(String::from_utf8_lossy(&result.provisioning.0).contains("AAUTHLEVEL"));
    // Lost HTTP response: retry the exact enrollment, certificate and secrets remain identical.
    let retry = client
        .post(&path)
        .header("content-type", "application/soap+xml")
        .body(wire)
        .send()
        .await?;
    ensure!(retry.status() == StatusCode::OK);
    let replay = soap::decode_response(&issue, &retry.bytes().await?, &CodecLimits::default())?;
    let Body::IssueResponse(replay) = replay.body else {
        panic!()
    };
    ensure!(replay.provisioning == result.provisioning);
    let auth = store
        .enrollment_authorization(TENANT, receipt.enrollment_id, &password)
        .await?;
    let csr = std::fs::read(root.join("device.csr"))?;
    let intent = store
        .issuance_intent(
            &app.windows,
            &auth,
            &proof,
            (
                &csr,
                rss_mdm_windows_mdm::provisioning::EnrollmentType::Device,
            ),
            now(),
        )
        .await?;
    let cert = app.windows.ca.sign(&intent.tbs)?;
    let cert_pem = x509_cert::Certificate::from_der(&cert)?.to_pem(LineEnding::LF)?;
    let identity = reqwest::Identity::from_pem(
        &[
            cert_pem.as_bytes(),
            &std::fs::read(root.join("device.key"))?,
        ]
        .concat(),
    )?;
    let mutual = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(root_cert)
        .identity(identity)
        .timeout(Duration::from_secs(12))
        .build()?;
    let url = app.windows.management_url();
    ensure!(
        client
            .post(&url)
            .body("no certificate")
            .send()
            .await
            .is_err(),
        "management accepted an anonymous TLS handshake"
    );
    let mut message = syncml::decode(
        include_bytes!("../../../windows-mdm/tests/fixtures/initialization.xml"),
        &CodecLimits::default(),
    )?;
    message.header.target = url.clone();
    message.header.source = "tls-device".into();
    let secrets = app
        .windows
        .protection
        .open(TENANT, auth.id, &intent.sealed)?;
    message.header.credential = Some(syncml::Credential {
        meta: syncml::Meta {
            format: Some("b64".into()),
            media_type: Some("syncml:auth-basic".into()),
            ..Default::default()
        },
        data: Secret(STANDARD.encode(format!(
            "{}:{}",
            intent.registration,
            secrets.client_password.as_str()
        ))),
    });
    for command in &mut message.commands {
        if let Command::DevInfo { items, .. } = command {
            for item in items {
                if item.source.as_deref() == Some("./DevInfo/DevId") {
                    item.data = Some(Secret("tls-device".into()));
                }
            }
        }
    }
    let wire = syncml::encode(&message, &CodecLimits::default())?;
    let post = |bytes: Vec<u8>| {
        mutual
            .post(&url)
            .header("content-type", "application/vnd.syncml.dm+xml")
            .body(bytes)
    };
    store.fail_next(1);
    ensure!(post(wire.clone()).send().await?.status() == StatusCode::SERVICE_UNAVAILABLE);
    store.fail_next(2);
    ensure!(post(wire.clone()).send().await?.status() == StatusCode::SERVICE_UNAVAILABLE);
    let first = post(wire.clone()).send().await?;
    ensure!(first.status() == StatusCode::OK);
    let first = first.bytes().await?;
    let response = syncml::decode(&first, &CodecLimits::default())?;
    ensure!(
        response.header.credential.as_ref().unwrap().data.0
            == protection::digest("RSS-MDM", &secrets.server_password, &secrets.server_nonce)
    );
    ensure!(post(wire.clone()).send().await?.bytes().await? == first);
    let mut wrong = message.clone();
    wrong.header.source = "another-device".into();
    ensure!(
        post(syncml::encode(&wrong, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::FORBIDDEN
    );
    let mut changed = message.clone();
    changed.header.meta = Some(syncml::Meta {
        max_message_size: Some(65536),
        ..Default::default()
    });
    ensure!(
        post(syncml::encode(&changed, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::CONFLICT
    );
    ensure!(
        post(wire.clone())
            .header("x-ssl-client-cert", "forged")
            .send()
            .await?
            .status()
            == StatusCode::UNAUTHORIZED
    );
    let next_nonce = [7u8; 16];
    let followup = syncml::Message {
        header: syncml::Header {
            message_id: 2,
            credential: None,
            ..message.header.clone()
        },
        commands: vec![Command::Status(syncml::Status {
            credential: None,
            id: 1,
            message_ref: 1,
            command_ref: 0,
            command: CommandName::SyncHdr,
            target_refs: vec![],
            source_refs: vec![],
            code: 212,
            items: vec![],
            challenge: Some(syncml::Challenge {
                media_type: "syncml:auth-md5".into(),
                nonce: Some(Secret(STANDARD.encode(next_nonce))),
            }),
        })],
        final_message: true,
    };
    let followup = syncml::encode(&followup, &CodecLimits::default())?;
    let finished = post(followup.clone()).send().await?;
    ensure!(finished.status() == StatusCode::OK);
    let finished = finished.bytes().await?;
    ensure!(
        syncml::decode(&finished, &CodecLimits::default())?
            .header
            .credential
            .unwrap()
            .data
            .0
            == protection::digest("RSS-MDM", &secrets.server_password, &secrets.server_nonce)
    );
    ensure!(post(followup.clone()).send().await?.bytes().await? == finished);
    // The 212 NextNonce is persisted for the next session, while current-session
    // responses and retransmissions continue using the old digest.
    let mut next_session = message.clone();
    next_session.header.session_id += 1;
    let next_response = post(syncml::encode(&next_session, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(next_response.status() == StatusCode::OK);
    let next_response = syncml::decode(&next_response.bytes().await?, &CodecLimits::default())?;
    ensure!(
        next_response.header.credential.unwrap().data.0
            == protection::digest("RSS-MDM", &secrets.server_password, &next_nonce)
    );
    // Existing TLS keepalive connections do not cache the active mapping.
    app.devices
        .revoke(&proof, "tls-device", intent.registration, Uuid::new_v4())
        .await?;
    ensure!(post(followup).send().await?.status() == StatusCode::UNAUTHORIZED);
    app.sessions
        .remove(&session, &app.sessions.get(&session)?.csrf)?;
    ensure!(app.sessions.by_reference(reference).is_err());
    running.close().await?;
    reader.close().await;
    store.close().await;
    Ok(())
}
