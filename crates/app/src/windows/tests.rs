use super::*;
use crate::{
    AccessStore,
    access::CollectionService,
    device::tests::{admin, options},
    enrollment::{Authorization, Password},
};
use crate::{clock::Clock, identity::Principal};
use anyhow::ensure;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_windows_mdm::syncml::{self, Command, CommandName};
use sqlx::{Connection, Executor, PgConnection};
use std::{path::PathBuf, time::Duration};
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_cert::der::{Decode, Encode};
const TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
#[tokio::test]
async fn invalid_csr_has_certificate_request_fault() -> anyhow::Result<()> {
    let error = certificate::Csr::verify(b"invalid-csr").err().unwrap();
    let response = fault(None, error);
    let bytes = axum::body::to_bytes(response.into_body(), 8192).await?;
    let message = soap::decode(&bytes, Operation::Fault, &CodecLimits::default())?;
    ensure!(matches!(
        message.body,
        Body::Fault(soap::FaultKind::CertificateRequest)
    ));
    Ok(())
}
fn root() -> anyhow::Result<PathBuf> {
    Ok(std::env::var("MDM_WINDOWS_FIXTURES")?.into())
}
fn now() -> i64 {
    crate::clock::SystemClock.unix_seconds().unwrap()
}
fn windows() -> anyhow::Result<Windows> {
    let config = serde_json::from_slice(&std::fs::read(root()?.join("windows.json"))?)?;
    Ok(Windows::load(config, now())?)
}
fn audit(proof: &Principal, key: Uuid, device: &str, action: &'static str) -> Audit {
    let a = Audit::new(proof.tenant_id().into(), action);
    a.identify(proof);
    a.target(device);
    a.operation(key, action);
    a
}
async fn create(
    store: &AccessStore,
    proof: &Principal,
    device: &str,
    password: &Password,
    reference: Uuid,
    key: Uuid,
) -> anyhow::Result<crate::enrollment::Receipt> {
    let a = audit(proof, key, device, "enrollment_create");
    let receipt = store
        .create_enrollment(
            proof.enrollment(device)?,
            password,
            rss_mdm_inventory::ReportSource::MdmWindows,
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
    proof: &Principal,
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
                &Password::new(crate::enrollment::random())?
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
    let service = crate::device::DeviceService::new(access.clone(), TENANT.into());
    ensure!(
        service.management_principal(&credential).await.is_err(),
        "unbound signed certificate admitted"
    );
    let mut unrelated = x509_cert::TbsCertificate::from_der(&intent.tbs)?;
    unrelated.subject = "CN=another-intent".parse()?;
    let unrelated = w.ca.sign(&unrelated.to_der()?)?;
    w.ca.verify(&[CertificateDer::from(unrelated.as_slice())], now())?;
    ensure!(matches!(
        complete(&access, &w, &auth, &proof, &intent, &unrelated).await,
        Err(Error::Conflict)
    ));
    ensure!(service.management_principal(&credential).await.is_err());
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
    let next = Password::new(crate::enrollment::random())?;
    let resume_key = Uuid::new_v4();
    let a = audit(&proof, resume_key, "windows-device", "enrollment_resume");
    access
        .change_enrollment(
            proof.enrollment("windows-device")?,
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
        if cause == "cancel" {
            let key = Uuid::new_v4();
            let a = audit(&proof, key, device, "enrollment_cancel");
            access
                .change_enrollment(proof.enrollment(device)?, auth.id, None, key, &a)
                .await?;
            a.finalize(None);
        } else if cause == "expiry" {
            sqlx::query("UPDATE mdm_access.requests SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(TENANT).bind(auth.id.to_string()).execute(&mut pg).await?;
        }
        let current = if cause == "permission" {
            crate::identity_fixture::set_grants(TENANT, crate::identity_fixture::ADMIN, vec![])
                .await?;
            Some(admin(TENANT, "admin-a").await?)
        } else {
            None
        };
        let result = complete(
            &access,
            &w,
            &auth,
            current.as_ref().unwrap_or(&proof),
            &intent,
            &w.ca.sign(&intent.tbs)?,
        )
        .await;
        if cause == "permission" {
            crate::identity_fixture::set_grants(
                TENANT,
                crate::identity_fixture::ADMIN,
                crate::identity_fixture::device_grants(
                    None,
                    &["inventory_read", "enrollment", "credentials"],
                )?,
            )
            .await?;
        }
        ensure!(result.is_err());
        let bound: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND request_id=$2::uuid")
            .bind(TENANT).bind(auth.id.to_string()).fetch_one(&mut pg).await?;
        ensure!(bound == 0);
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
pub(super) fn monotonic() -> Arc<dyn rss_observation::Clock> {
    Arc::new(crate::Monotonic(std::time::Instant::now))
}
struct IngressClock(std::sync::Mutex<Option<std::time::Instant>>);
impl rss_observation::Clock for IngressClock {
    #[allow(
        clippy::disallowed_methods,
        reason = "T2 ingress clock uses real time until the deterministic burst test"
    )]
    fn now(&self) -> std::time::Instant {
        self.0
            .lock()
            .unwrap()
            .unwrap_or_else(std::time::Instant::now)
    }
}
impl IngressClock {
    #[allow(
        clippy::disallowed_methods,
        reason = "T2 composition root controls only ingress refill time, while TLS/HTTP/PG remain real"
    )]
    fn new() -> Arc<Self> {
        Arc::new(Self(std::sync::Mutex::new(None)))
    }
    fn advance(&self) {
        let now = rss_observation::Clock::now(self);
        *self.0.lock().unwrap() = Some(now + Duration::from_secs(60));
    }
}

async fn ingress_burst(
    client: &reqwest::Client,
    app: &App,
    clock: &IngressClock,
) -> anyhow::Result<()> {
    let url = format!(
        "{}/EnrollmentServer/Discovery.svc",
        app.windows()?.config.enrollment.origin
    );
    let mut request = soap::decode(
        include_bytes!("../../../windows-mdm/tests/fixtures/discovery-request.xml"),
        Operation::Discover,
        &CodecLimits::default(),
    )?;
    request.header.to = Some(url.clone());
    let bytes = soap::encode(&request, &CodecLimits::default())?;
    let mut pg = PgConnection::connect_with(&options("postgres")?).await?;
    let before:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.audit WHERE tenant_id=$1::uuid AND action='windows_discovery'").bind(TENANT).fetch_one(&mut pg).await?;
    // Freeze refill time only for the deterministic burst assertions.
    clock.advance();
    let mut accepted = 0i64;
    let mut refused = 0;
    for index in 0..128 {
        let response = client
            .post(&url)
            .header("content-type", "application/soap+xml")
            .header("x-forwarded-for", format!("198.51.100.{}", index + 1))
            .body(bytes.clone())
            .send()
            .await?;
        match response.status() {
            StatusCode::OK => {
                accepted += 1;
                let _ = response.bytes().await?;
            }
            StatusCode::TOO_MANY_REQUESTS => {
                refused += 1;
                ensure!(response.headers()["cache-control"] == "no-store");
                ensure!(response.json::<serde_json::Value>().await?["code"] == "request_limited");
            }
            code => anyhow::bail!("unexpected burst response: {code}"),
        }
    }
    ensure!(
        refused >= 64 && accepted <= 64,
        "forwarded headers bypassed peer admission"
    );
    let after:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.audit WHERE tenant_id=$1::uuid AND action='windows_discovery'").bind(TENANT).fetch_one(&mut pg).await?;
    ensure!(
        after - before == accepted,
        "capacity denials amplified persistent audit"
    );
    clock.advance();
    ensure!(
        client
            .post(&url)
            .header("content-type", "application/soap+xml")
            .body(bytes)
            .send()
            .await?
            .status()
            == StatusCode::OK
    );
    pg.close().await?;
    Ok(())
}

struct Running(rss_runtime::ShutdownStack);
impl Running {
    async fn close(self) -> anyhow::Result<()> {
        let receipt = self.0.shutdown().join().await?;
        ensure!(receipt.is_clean(), "TLS owner failed to drain");
        Ok(())
    }
}
#[allow(
    clippy::cognitive_complexity,
    reason = "integration matrix keeps actual Discovery/XCEP success and denial assertions together"
)]
async fn discover_and_policy(
    client: &reqwest::Client,
    app: &App,
    enrollment: Uuid,
    password: &str,
) -> anyhow::Result<()> {
    let origin = &app.windows()?.config.enrollment.origin;
    let mut discovery = soap::decode(
        include_bytes!("../../../windows-mdm/tests/fixtures/discovery-request.xml"),
        Operation::Discover,
        &CodecLimits::default(),
    )?;
    let discovery_url = format!("{origin}/EnrollmentServer/Discovery.svc");
    discovery.header.to = Some(discovery_url.clone());
    let response = client
        .post(&discovery_url)
        .header("content-type", "application/soap+xml")
        .body(soap::encode(&discovery, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let discovery_audit = response.headers()["x-request-id"].to_str()?.to_owned();
    let decoded = soap::decode_response(
        &discovery,
        &response.bytes().await?,
        &CodecLimits::default(),
    )?;
    let Body::DiscoverResponse(found) = decoded.body else {
        anyhow::bail!("not Discovery response")
    };
    ensure!(found.enrollment_version == "4.0");
    ensure!(found.policy_url == format!("{origin}/EnrollmentServer/Policy.svc"));
    ensure!(found.enrollment_url == format!("{origin}/EnrollmentServer/Enrollment.svc"));
    let mut policy = soap::decode(
        include_bytes!("../../../windows-mdm/tests/fixtures/policy-request.xml"),
        Operation::GetPolicies,
        &CodecLimits::default(),
    )?;
    policy.header.to = Some(found.policy_url.clone());
    let token = policy
        .header
        .security
        .as_mut()
        .unwrap()
        .username
        .as_mut()
        .unwrap();
    token.username = Secret(enrollment.to_string());
    token.password = Secret(password.to_owned());
    let response = client
        .post(&found.policy_url)
        .header("content-type", "application/soap+xml")
        .body(soap::encode(&policy, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let policy_audit = response.headers()["x-request-id"].to_str()?.to_owned();
    let decoded =
        soap::decode_response(&policy, &response.bytes().await?, &CodecLimits::default())?;
    let Body::GetPoliciesResponse(found_policy) = decoded.body else {
        anyhow::bail!("not XCEP response")
    };
    ensure!(found_policy.minimum_key_length == 2048 && found_policy.validity_seconds == 90 * 86400);
    for (request, url) in [(&discovery, &discovery_url), (&policy, &found.policy_url)] {
        let mut bad = request.clone();
        bad.header.to = Some("https://outside.invalid/EnrollmentServer/Policy.svc".into());
        for (message, host) in [(&bad, None), (request, Some("outside.invalid"))] {
            let mut call = client
                .post(url)
                .header("content-type", "application/soap+xml")
                .body(soap::encode(message, &CodecLimits::default())?);
            if let Some(host) = host {
                call = call.header("host", host);
            }
            let response = call.send().await?;
            ensure!(response.status() == StatusCode::INTERNAL_SERVER_ERROR);
            let fault = soap::decode(
                &response.bytes().await?,
                Operation::Fault,
                &CodecLimits::default(),
            )?;
            ensure!(matches!(
                fault.body,
                Body::Fault(soap::FaultKind::MessageFormat)
            ));
        }
    }
    policy
        .header
        .security
        .as_mut()
        .unwrap()
        .username
        .as_mut()
        .unwrap()
        .password = Secret(crate::enrollment::random());
    let denied = client
        .post(&found.policy_url)
        .header("content-type", "application/soap+xml")
        .body(soap::encode(&policy, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(denied.status() == StatusCode::INTERNAL_SERVER_ERROR);
    let fault = soap::decode(
        &denied.bytes().await?,
        Operation::Fault,
        &CodecLimits::default(),
    )?;
    ensure!(matches!(
        fault.body,
        Body::Fault(soap::FaultKind::Authentication)
    ));
    let mut pg = PgConnection::connect_with(&options("postgres")?).await?;
    for (request, action) in [
        (discovery_audit, "windows_discovery"),
        (policy_audit, "windows_policy"),
    ] {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.audit WHERE tenant_id=$1::uuid AND request_id=$2::uuid AND action=$3 AND result='success'").bind(TENANT).bind(request).bind(action).fetch_one(&mut pg).await?;
        ensure!(count == 1);
    }
    pg.close().await?;
    Ok(())
}
async fn rejected_csrs(
    client: &reqwest::Client,
    path: &str,
    issue: &soap::Message,
) -> anyhow::Result<()> {
    let Body::Issue(original) = &issue.body else {
        anyhow::bail!("expected Issue")
    };
    let mut trailing = original.csr.0.clone();
    trailing.push(0);
    let mut bad_proof = original.csr.0.clone();
    *bad_proof.last_mut().unwrap() ^= 1;
    for csr in [trailing, bad_proof] {
        let mut request = issue.clone();
        let Body::Issue(body) = &mut request.body else {
            unreachable!()
        };
        body.csr = Secret(csr);
        let response = client
            .post(path)
            .header("content-type", "application/soap+xml")
            .body(soap::encode(&request, &CodecLimits::default())?)
            .send()
            .await?;
        ensure!(response.status() == StatusCode::INTERNAL_SERVER_ERROR);
        let fault = soap::decode(
            &response.bytes().await?,
            Operation::Fault,
            &CodecLimits::default(),
        )?;
        ensure!(matches!(
            fault.body,
            Body::Fault(soap::FaultKind::CertificateRequest)
        ));
    }
    Ok(())
}
#[tokio::test]
#[ignore = "make t2: native HTTPS enrollment and mTLS management with real PG"]
async fn native_tls_enrollment_management_replay_and_revoke() -> anyhow::Result<()> {
    native_matrix(false).await
}
#[tokio::test]
#[ignore = "command T2: authenticated HTTP operation and native mTLS participant"]
async fn native_command_operations_and_observation() -> anyhow::Result<()> {
    native_matrix(true).await
}
#[allow(
    clippy::cognitive_complexity,
    reason = "sequential native HTTP authentication, failure and recovery matrix"
)]
async fn native_matrix(with_commands: bool) -> anyhow::Result<()> {
    use x509_cert::der::{EncodePem, pem::LineEnding};
    let root = root()?;
    let enroll = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let manage = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))?;
    value["native_protocols"]["windows"] =
        serde_json::from_slice(&std::fs::read(root.join("windows.json"))?)?;
    value["native_protocols"]["windows"]["enrollment"]["origin"] =
        serde_json::json!(format!("https://localhost:{}", enroll.local_addr()?.port()));
    value["native_protocols"]["windows"]["enrollment"]["listen"] =
        serde_json::json!(enroll.local_addr()?.to_string());
    value["native_protocols"]["windows"]["management"]["origin"] =
        serde_json::json!(format!("https://localhost:{}", manage.local_addr()?.port()));
    value["native_protocols"]["windows"]["management"]["listen"] =
        serde_json::json!(manage.local_addr()?.to_string());
    value["identity"] = serde_json::from_slice::<serde_json::Value>(&std::fs::read(
        std::env::var("MDM_TEST_CONFIG")?,
    )?)?["identity"]
        .clone();
    value["identity"]["tenant_id"] = serde_json::json!(TENANT);
    let db: sqlx::postgres::PgConnectOptions = std::env::var("DATABASE_URL")?.parse()?;
    let management_password = root.join("management-password");
    std::fs::write(&management_password, "runtime-fixture")?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&management_password, std::fs::Permissions::from_mode(0o600))?;
    value["management"]["database"] = serde_json::json!({"host":"localhost","port":db.get_port(),"name":db.get_database().unwrap(),"user":"mdm_management_runtime","password_file":management_password,"ca_file":root.join("ca.crt")});
    value["command_database"] = value["management"]["database"].clone();
    value["command_database"]["user"] = "mdm_command_runtime".into();
    let config: crate::config::Config = serde_json::from_value(value)?;
    let clock = Arc::new(crate::clock::SystemClock);
    let identity_management = Arc::new(crate::access::IdentityManagementPolicy::new(
        TENANT,
        crate::identity_fixture::INSTANCE,
        config.identity_management.clone(),
    )?);
    let identity =
        crate::identity::Identity::connect(&config, identity_management.clone(), |_| {}).await?;
    let secret = crate::identity_fixture::login(&identity, "admin").await?;
    let credentials = crate::enrollment_credentials::Credentials::new(monotonic(), 100);
    let reference = credentials.insert(rss_identity_core::session::SessionSecret::parse(
        secret.expose().into(),
    )?)?;
    let store = Arc::new(AccessStore::connect(options("mdm_access")?).await?);
    let devices = Arc::new(crate::device::DeviceService::new(
        store.clone(),
        TENANT.into(),
    ));
    let reader =
        Arc::new(rss_mdm_inventory_postgres::InventoryReader::connect(options("mdm_api")?).await?);
    let runtime = crate::inventory_runtime::InventoryRuntime::fixture(
        options("mdm_runtime")?,
        store.clone(),
        rss_request_context::TenantId::parse(TENANT)?,
        monotonic(),
    )
    .await?;
    let management = config
        .management
        .open(
            rss_request_context::TenantId::parse(TENANT)?,
            Arc::new(crate::clock::SystemClock),
            |_| {},
        )
        .await
        .map_err(|e| anyhow::anyhow!("management startup: {e:?}"))?;
    let commands = crate::commands::Commands::open(&config)
        .await
        .map_err(|e| anyhow::anyhow!("command startup: {e:?}"))?;
    let app = Arc::new(App {
        apple: None,
        commands,
        management,
        identity,
        credentials,
        clock,
        identity_management,
        collection: CollectionService::new(devices.clone(), store.clone(), runtime.clone()),
        readiness: runtime.readiness.clone(),
        devices,
        access: store.clone(),
        requests: Arc::new(tokio::sync::Semaphore::new(4)),
        windows: Some(Arc::new(Windows::load(
            config
                .native_protocols
                .windows
                .expect("Windows test configuration"),
            now(),
        )?)),
    });
    tls::verify_tls_lifecycle(store.clone(), app.windows()?.enrollment_tls.clone(), &root).await?;
    let ingress_clock = IngressClock::new();
    let crate::native::Routers {
        browser,
        mut listeners,
        ..
    } = crate::api::from_state(
        app.clone(),
        "mdm.example.test".into(),
        ingress_clock.clone(),
    );
    let (_, management) = listeners.pop().expect("management listener");
    let (_, mut enrollment) = listeners.pop().expect("enrollment listener");
    let mut task_client = if with_commands {
        Some(crate::commands::tests::Client::start(browser, app.clone()).await?)
    } else {
        None
    };
    enrollment.router = enrollment.router.route(
        "/accepted-peer",
        axum::routing::get(
            |axum::Extension(info): axum::Extension<
                rss_axum::AcceptedConnectionInfo<(tls::Peer, admission::RequestGate)>,
            >| async move { info.socket_peer().ip().to_string() },
        ),
    );
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    {
        let mut launch = owner.startup()?.commit();
        launch.stage_task_with_token(
            tls::registration(
                enroll,
                enrollment,
                store.clone(),
                TENANT.into(),
                crate::native::NativeListenerKind::WindowsEnrollment,
            )
            .critical(),
        );
        launch.stage_task_with_token(
            tls::registration(
                manage,
                management,
                store.clone(),
                TENANT.into(),
                crate::native::NativeListenerKind::WindowsManagement,
            )
            .critical(),
        );
        launch.stage_deferred_task_with_token(runtime.clone().registration().critical());
        launch.finish();
    }
    let running = Running(owner);
    let root_cert = reqwest::Certificate::from_pem(&std::fs::read(root.join("ca.crt"))?)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(root_cert.clone())
        .timeout(Duration::from_secs(12))
        .build()?;
    ensure!(
        client
            .get(format!(
                "{}/accepted-peer",
                app.windows()?.config.enrollment.origin
            ))
            .header("x-forwarded-for", "198.51.100.23")
            .send()
            .await?
            .text()
            .await?
            == "127.0.0.1",
        "TLS requests lost the RSS-owned accepted peer"
    );
    let proof = admin(TENANT, "admin-a").await?;
    let plain = crate::enrollment::random();
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
    discover_and_policy(&client, &app, receipt.enrollment_id, &plain).await?;
    let path = format!(
        "{}/EnrollmentServer/Enrollment.svc",
        app.windows()?.config.enrollment.origin
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
    rejected_csrs(&client, &path, &issue).await?;
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
            app.windows()?,
            &auth,
            &proof,
            (
                &csr,
                rss_mdm_windows_mdm::provisioning::EnrollmentType::Device,
            ),
            now(),
        )
        .await?;
    let cert = app.windows()?.ca.sign(&intent.tbs)?;
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
        .add_root_certificate(root_cert.clone())
        .identity(identity)
        .timeout(Duration::from_secs(12))
        .build()?;
    let url = app.windows()?.management_url();
    ensure!(
        client
            .post(&url)
            .body("no certificate")
            .send()
            .await
            .is_err(),
        "management accepted an anonymous TLS handshake"
    );
    let rogue_identity = reqwest::Identity::from_pem(
        &[
            std::fs::read(root.join("rogue-client.pem"))?,
            std::fs::read(root.join("device.key"))?,
        ]
        .concat(),
    )?;
    let rogue = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(root_cert.clone())
        .identity(rogue_identity)
        .timeout(Duration::from_secs(12))
        .build()?;
    ensure!(
        rogue
            .post(&url)
            .body("untrusted chain")
            .send()
            .await
            .is_err(),
        "management accepted an untrusted client CA"
    );
    if let Some(client) = &mut task_client {
        client.accept().await?;
    }
    let mut message = syncml::decode(
        include_bytes!("../../../windows-mdm/tests/fixtures/initialization.xml"),
        &CodecLimits::default(),
    )?;
    message.header.target = url.clone();
    message.header.source = "tls-device".into();
    let secrets = app
        .windows()?
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
    #[cfg(feature = "integration")]
    {
        app.commands
            .inject_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
        ensure!(post(wire.clone()).send().await?.status() == StatusCode::SERVICE_UNAVAILABLE);
        app.commands.inject_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
        );
        ensure!(post(wire.clone()).send().await?.status() == StatusCode::SERVICE_UNAVAILABLE);
    }
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
    let get_request = syncml::decode(&finished, &CodecLimits::default())?;
    let gets: Vec<_> = get_request
        .commands
        .iter()
        .filter_map(|c| match c {
            Command::Get { id, items, .. } => Some((*id, items[0].target.clone().unwrap())),
            _ => None,
        })
        .collect();
    ensure!(
        gets.len() == 4 + usize::from(with_commands)
            && gets[0].1 == "./DevInfo/Mod"
            && gets[1].1 == "./DevDetail/SwV"
    );
    let packet = |message_id, previous, index: usize, value: &str| {
        let mut result = syncml::Message {
            header: syncml::Header {
                message_id,
                credential: None,
                ..message.header.clone()
            },
            commands: vec![
                Command::Status(syncml::Status {
                    id: 1,
                    message_ref: previous,
                    command_ref: 0,
                    command: CommandName::SyncHdr,
                    target_refs: vec![],
                    source_refs: vec![],
                    code: 200,
                    items: vec![],
                    challenge: None,
                    credential: None,
                }),
                Command::Status(syncml::Status {
                    id: 2,
                    message_ref: 2,
                    command_ref: gets[index].0,
                    command: CommandName::Get,
                    target_refs: vec![],
                    source_refs: vec![],
                    code: 200,
                    items: vec![],
                    challenge: None,
                    credential: None,
                }),
                Command::Results(syncml::Results {
                    id: 3,
                    message_ref: Some(2),
                    command_ref: Some(gets[index].0),
                    command: Some(CommandName::Get),
                    meta: None,
                    items: vec![syncml::Item {
                        source: Some(gets[index].1.clone()),
                        target: None,
                        meta: None,
                        data: Some(Secret(value.into())),
                    }],
                }),
            ],
            final_message: true,
        };
        if with_commands && index == 0 {
            let mut status = result.commands[1].clone();
            if let Command::Status(s) = &mut status {
                s.id = 4;
                s.command_ref = gets[4].0;
            }
            result.commands.push(status);
            let mut value = result.commands[2].clone();
            if let Command::Results(r) = &mut value {
                r.id = 5;
                r.command_ref = Some(gets[4].0);
            }
            result.commands.push(value);
        }
        result
    };
    let extra = u32::from(with_commands);
    if let Some(client) = &mut task_client {
        let mut received = packet(3, 2, 0, "Model-TLS");
        received
            .commands
            .retain(|c| !matches!(c, Command::Results(_)));
        ensure!(
            post(syncml::encode(&received, &CodecLimits::default())?)
                .send()
                .await?
                .status()
                == StatusCode::OK
        );
        client.received().await?;
    }
    let model = syncml::encode(
        &packet(3 + extra, 2 + extra, 0, "Model-TLS"),
        &CodecLimits::default(),
    )?;
    let first_fragment = post(model.clone()).send().await?;
    ensure!(first_fragment.status() == StatusCode::OK);
    let first_fragment = first_fragment.bytes().await?;
    ensure!(post(model.clone()).send().await?.bytes().await? == first_fragment);
    if let Some(client) = &mut task_client {
        let (revocation, replay) = tokio::join!(client.observed(), post(followup.clone()).send());
        revocation?;
        ensure!(matches!(
            replay?.status(),
            StatusCode::OK | StatusCode::FORBIDDEN
        ));
        ensure!(
            post(followup.clone()).send().await?.status() == StatusCode::FORBIDDEN,
            "revoked cached dispatch replayed"
        );
    }
    let scope = app
        .devices
        .current_scope(
            &proof,
            "tls-device",
            crate::access::Coordinates {
                source: rss_mdm_inventory::ReportSource::MdmWindows,
            },
        )
        .await?;
    let pending = store.collection(&scope, None).await?.unwrap();
    ensure!(pending.result == crate::collection::RunResult::Pending && pending.batch().is_none());
    ensure!(
        reader
            .read(scope.tenant(), std::slice::from_ref(&scope))
            .await?
            .is_empty(),
        "fragment projected before complete collection"
    );
    let mut conflicting = packet(4 + extra, 3 + extra, 0, "changed");
    ensure!(
        post(syncml::encode(&conflicting, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::CONFLICT
    );
    conflicting = packet(4 + extra, 3 + extra, 1, "10.0.26100");
    let final_fragment = syncml::encode(&conflicting, &CodecLimits::default())?;
    #[cfg(feature = "integration")]
    {
        app.commands.inject_fault(
            rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
        );
        ensure!(
            post(final_fragment.clone()).send().await?.status() == StatusCode::SERVICE_UNAVAILABLE
        );
    }
    let replay = post(final_fragment.clone()).send().await?;
    ensure!(replay.status() == StatusCode::OK);
    let replay = syncml::decode(&replay.bytes().await?, &CodecLimits::default())?;
    ensure!(
        replay
            .commands
            .iter()
            .any(|c| matches!(c, Command::Status(s) if s.command == CommandName::Results))
    );
    let sealed = store.collection(&scope, None).await?.unwrap();
    ensure!(sealed.id == pending.id && sealed.result == crate::collection::RunResult::Snapshot);
    let bytes = sealed.batch().unwrap().encode().to_vec();
    ensure!(post(final_fragment).send().await?.status() == StatusCode::OK);
    ensure!(
        store
            .collection(&scope, None)
            .await?
            .unwrap()
            .batch()
            .unwrap()
            .encode()
            == bytes
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if runtime.inspect(&sealed).await?.projection
                == crate::inventory_runtime::ProjectionStatus::Projected
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, Error>(())
    })
    .await??;
    let fields = reader
        .read(scope.tenant(), std::slice::from_ref(&scope))
        .await?;
    ensure!(
        fields.len() == 2
            && fields[0].fact.state
                == rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String(
                    "Model-TLS".into()
                ))
            && fields[1].fact.state
                == rss_mdm_inventory::State::Known(rss_mdm_inventory::Scalar::String(
                    "10.0.26100".into()
                ))
    );
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
    // A newer session supersedes the prior unfinished session. Its stored response remains replayable,
    // but a delayed 212 from that older session cannot overwrite the latest next nonce.
    let old_initial = syncml::encode(&next_session, &CodecLimits::default())?;
    let old_response = post(old_initial.clone()).send().await?.bytes().await?;
    let mut newer_session = next_session.clone();
    newer_session.header.session_id += 1;
    ensure!(
        post(syncml::encode(&newer_session, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::OK
    );
    ensure!(post(old_initial).send().await?.bytes().await? == old_response);
    let mut older_ack = syncml::decode(&followup, &CodecLimits::default())?;
    older_ack.header.session_id = next_session.header.session_id;
    ensure!(
        post(syncml::encode(&older_ack, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::CONFLICT
    );
    older_ack.header.session_id = newer_session.header.session_id;
    let Command::Status(s) = &mut older_ack.commands[0] else {
        panic!()
    };
    s.challenge.as_mut().unwrap().nonce = Some(Secret(STANDARD.encode([9u8; 32])));
    ensure!(
        post(syncml::encode(&older_ack, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::OK
    );
    let mut unsent = newer_session.clone();
    unsent.header.session_id += 1;
    unsent.commands.insert(0, older_ack.commands[0].clone());
    for (index, command) in unsent.commands.iter_mut().enumerate() {
        match command {
            Command::Status(s) => s.id = index as u32 + 1,
            Command::Alert { id, .. } | Command::DevInfo { id, .. } => *id = index as u32 + 1,
            _ => unreachable!(),
        }
    }
    ensure!(
        post(syncml::encode(&unsent, &CodecLimits::default())?)
            .send()
            .await?
            .status()
            == StatusCode::CONFLICT
    );
    newer_session.header.session_id += 2;
    let current = post(syncml::encode(&newer_session, &CodecLimits::default())?)
        .send()
        .await?;
    ensure!(current.status() == StatusCode::OK);
    let current = syncml::decode(&current.bytes().await?, &CodecLimits::default())?;
    ensure!(
        current.header.credential.unwrap().data.0
            == protection::digest("RSS-MDM", &secrets.server_password, &[9u8; 32])
    );
    if let Some(client) = &mut task_client {
        client
            .reobserve(
                &mutual,
                &url,
                &message,
                &syncml::decode(&followup, &CodecLimits::default())?,
                &model,
            )
            .await?;
    }
    // Existing TLS keepalive connections do not cache the active mapping.
    app.devices
        .revoke(&proof, "tls-device", intent.registration, Uuid::new_v4())
        .await?;
    ensure!(post(followup).send().await?.status() == StatusCode::UNAUTHORIZED);
    retention_tests::verify(&store, TENANT, intent.registration).await?;
    if let Some(client) = &mut task_client {
        client.retained_and_recovered().await?;
        // Real WSTEP issuance creates generation 2, then the old authenticated TLS
        // keepalive submits a delayed native Results against the new task authority.
        let plain = crate::enrollment::random();
        let password = Password::new(plain.clone())?;
        let next = create(
            &store,
            &proof,
            "tls-device",
            &password,
            reference,
            Uuid::new_v4(),
        )
        .await?;
        let mut issue = issue.clone();
        issue.header.message_id = Some(format!("urn:uuid:{}", Uuid::new_v4()));
        let token = issue
            .header
            .security
            .as_mut()
            .unwrap()
            .username
            .as_mut()
            .unwrap();
        token.username = Secret(next.enrollment_id.to_string());
        token.password = Secret(plain);
        let issued = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(root_cert.clone())
            .build()?
            .post(&path)
            .header("content-type", "application/soap+xml")
            .body(soap::encode(&issue, &CodecLimits::default())?)
            .send()
            .await?;
        ensure!(
            issued.status() == StatusCode::OK,
            "second registration {}",
            issued.status()
        );
        let current = client.new_registration_operation().await?;
        ensure!(post(model.clone()).send().await?.status() == StatusCode::UNAUTHORIZED);
        client.unchanged(&current).await?;
    }
    ingress_burst(&client, &app, &ingress_clock).await?;
    let actor = app
        .identity
        .authority
        .authenticate_session(app.identity.tenant, secret, crate::identity::deadline())
        .await?;
    app.identity
        .authority
        .revoke_current_session(actor, crate::identity::deadline())
        .await?;
    ensure!(
        app.identity
            .authenticate(app.credentials.get(reference)?)
            .await
            .is_err()
    );
    running.close().await?;
    runtime.close_fixture().await?;
    reader.close().await;
    store.close().await;
    Ok(())
}
