//! Real due-certificate preparation and persisted callback/activation transactions.
use super::*;
use anyhow::{Context as _, ensure};
use rss_mdm_apple_channel::{HttpState, renewal};
use sha2::{Digest, Sha256};
use std::time::Duration;

#[allow(
    clippy::disallowed_methods,
    reason = "integration supplies the production monotonic clock"
)]
async fn state(
    c: &Context,
    a: &Fixture,
    providers: Arc<rss_mdm_pki_service::providers::Providers>,
) -> Result<HttpState> {
    Ok(HttpState {
        pki: Arc::new(rss_mdm_pki_service::registry::Registry::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            c.operator.clone(),
            c.audit.clone(),
            c.execution(),
            providers.clone(),
        )),
        providers,
        credential_receipts: None,
        storage: c.execution().storage(),
        expected_epoch: c.execution().epoch(),
        query_cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            &[7; 32],
        )),
        material_roots: Arc::new(vec![]),
        authentication: rss_mdm_apple_channel::account_enrollment::Authentication {
            authority: c.authority.clone(),
            http: rss_identity_http_axum::HttpConfig::new(
                "https://localhost",
                Duration::from_secs(8),
            )?,
            origin: "https://localhost".into(),
        },
        account_authority: rss_mdm_apple_channel::account_enrollment::authority(),
        mount: crate::device::ChannelMount::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            rss_mdm_inventory::ReportSource::MdmApple,
            rss_mdm_registration_service::Purpose::Primary,
        ),
        audit_store: c.audit.clone(),
        access: c.database.apple_store(),
        apple: None,
        clock: Arc::new(identity::Clock),
        delivery: Arc::new(delivery(c, a).await?),
        enrollment_authority: a.registration.enrollment.clone(),
        departure: Arc::new(crate::assembly::apple_business::AppleBusiness(
            a.service.clone(),
            a.configuration.clone(),
            a.collections.clone(),
            a.software.service.clone(),
            a.registration.native.clone(),
            None,
        )),
        protection: a.resources.protection.clone(),
        credentials: Arc::new(
            rss_mdm_registration_service::enrollment::credentials::Credentials::new(
                Arc::new(crate::Monotonic(std::time::Instant::now)),
                32,
            ),
        ),
        devices: Arc::new(crate::device::DeviceService::new(
            c.database.registration(),
            c.audit.clone(),
        )),
        identity: a.resources.sessions.clone(),
        requests: Arc::new(tokio::sync::Semaphore::new(8)),
    })
}
#[tokio::test]
#[ignore = "T2: real PG renewal SQL, signed InstallProfile, verified CSR/certificate and credential switch"]
async fn due_identity_prepares_then_activates_the_original_epoch() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let result = async {
        let a = Fixture::open(&c).await?;
        let result = exercise(&c, &a).await;
        let cleanup = a.close().await;
        result.and(cleanup)
    }
    .await;
    c.close().await;
    result
}
#[allow(
    clippy::cognitive_complexity,
    reason = "one original renewal is followed through real preparation, callbacks and credential activation"
)]
async fn exercise(c: &Context, a: &Fixture) -> Result<()> {
    let n = identity::seed(c, "apple").await?;
    let issuer = format!("{:x}", Sha256::digest(&n.root));
    let providers = Arc::new(rss_mdm_pki_service::providers::Providers::new(vec![
        rss_mdm_pki_service::providers::Provider {
            purpose: rss_mdm_agent_wire::pki::Purpose::Apple,
            issuer: issuer.clone(),
            scep_url: Some("https://localhost/scep/rss-agent".into()),
            client: Arc::new(rss_mdm_pki_service::StepCa::new(
                rss_mdm_pki_service::Configuration {
                    origin: "https://localhost".into(),
                    provisioner: "rss-agent".into(),
                    kid: "task-trust".into(),
                },
                &std::fs::read(c.inputs.directory.join("task-trust-ca/ca.pem"))?,
                &std::fs::read(n.directory.join("runtime.pk8"))?,
            )?),
        },
    ])?);
    let (apple, principal) = support::apple_with_providers(
        c,
        &n,
        a.resources.protection.clone(),
        &[],
        providers.clone(),
    )
    .await?;
    let mut app = state(c, a, providers).await?;
    app.apple = Some(Arc::new(
        rss_mdm_apple_channel::runtime_materials::runtime::Runtime::new(
            "https://localhost".into(),
            None,
        ),
    ));
    app.material_roots = Arc::new(vec![std::fs::read(
        c.inputs.directory.join("task-trust-ca/ca.pem"),
    )?]);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let configuration = rss_mdm_apple_channel::protocol_identity(&rss_mdm_apple_channel::Config {
        management: rss_mdm_apple_channel::Origin {
            origin: "https://localhost".into(),
        },
        apns_topic: "com.apple.mgmt.rss-t2".into(),
        identity_seed: rss_mdm_apple_channel::IdentitySeed {
            challenge_id: "challenge".into(),
            notify_id: "notify".into(),
        },
    });
    let csr = rss_mdm_certificate::apple::csr(&n.csr)?;
    // A legal already-bound predecessor, due within its lifetime. The new attempt must be created by maintain.
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("INSERT INTO mdm_apple.scep_attempts(expected_epoch,tenant_id,id,enrollment,authorization_version,configuration,state,transaction_id,csr_digest,spki,issuer,fingerprint,serial,certificate,device,expires_at,not_before,not_after,access_rights,scep_url,scep_provisioner) VALUES(1,$1::uuid,$2,$3,1,$4,'bound','original',$5,$6,$7,$8,$9,$10,$11,to_timestamp($12),$13,$12,8191,'https://localhost/scep/rss-agent','rss-agent')")
        .bind(c.tenant.to_string()).bind(n.attempt).bind(n.request).bind(configuration.as_slice()).bind(csr.digest().as_slice()).bind(csr.spki().as_slice()).bind(Sha256::digest(&n.root).as_slice()).bind(Sha256::digest(&n.certificate).as_slice()).bind(vec![1u8]).bind(&n.certificate).bind(n.device.into_uuid()).bind(now+600).bind(now-1800).execute(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        renewal::maintain(c.execution(), &apple, &c.audit, now).await? > 0,
        "due candidate prepared"
    );
    renewal::maintain(c.execution(), &apple, &c.audit, now).await?;
    let mut tx = command::seed_transaction(c).await?;
    let attempts: Vec<(Uuid,Uuid,i64)> = sqlx::query_as("SELECT id,device,expected_epoch FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND renewal_of=$2").bind(c.tenant.to_string()).bind(n.attempt).fetch_all(&mut *tx).await?;
    tx.rollback().await?;
    ensure!(
        attempts.len() == 1 && attempts[0].1 == n.device.into_uuid() && attempts[0].2 == 1,
        "one original-epoch UUID attempt"
    );
    let attempt = attempts[0].0;
    let mut idle = plist::Dictionary::new();
    idle.insert("UDID".into(), n.device.to_string().into());
    idle.insert("Status".into(), "Idle".into());
    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, &idle)?;
    let command = renewal::management(&app, &principal, &idle, &bytes, &audit(c))
        .await?
        .context("renewal delivery")?;
    let command: plist::Value = plist::from_bytes(&command)?;
    let signed = command.as_dictionary().unwrap()["Command"]
        .as_dictionary()
        .unwrap()["Payload"]
        .as_data()
        .context("signed profile")?;
    let mut profile = Vec::new();
    openssl::cms::CmsContentInfo::from_der(signed)?.verify(
        None,
        None,
        None,
        Some(&mut profile),
        openssl::cms::CMSOptions::NOVERIFY,
    )?;
    let profile: plist::Value = plist::from_bytes(&profile)?;
    let secret = profile.as_dictionary().unwrap()["PayloadContent"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|payload| {
            let payload = payload.as_dictionary()?;
            (payload.get("PayloadType")?.as_string()? == "com.apple.security.scep")
                .then(|| {
                    payload
                        .get("PayloadContent")?
                        .as_dictionary()?
                        .get("Challenge")?
                        .as_string()
                })
                .flatten()
        })
        .context("actual SCEP challenge")?;
    let output = tokio::process::Command::new("python3")
        .args([
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../hack/native_protocol_materials.py"
            ),
            c.inputs.directory.to_str().unwrap(),
            "apple",
            &n.device.to_string(),
            &n.request.to_string(),
            &attempt.to_string(),
            "renewal",
        ])
        .output()
        .await?;
    ensure!(
        output.status.success(),
        "renewal certificate fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let path = std::path::Path::new(output["directory"].as_str().unwrap());
    let csr =
        rss_mdm_certificate::apple::csr(&identity::der("req", &path.join("client.csr")).await?)?;
    ensure!(
        renewal::challenge(
            &app,
            &apple,
            &csr,
            "wrong",
            "renewal",
            "rss-agent",
            &issuer,
            &audit(c)
        )
        .await
        .is_err(),
        "wrong challenge denied"
    );
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query(
        "UPDATE mdm_apple.scep_attempts SET expected_epoch=2 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(attempt)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    ensure!(
        renewal::challenge(
            &app,
            &apple,
            &csr,
            secret,
            "renewal",
            "rss-agent",
            &issuer,
            &audit(c)
        )
        .await
        .is_err(),
        "mismatched original epoch denied"
    );
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("UPDATE mdm_apple.scep_attempts SET expected_epoch=1 WHERE tenant_id=$1::uuid AND id=$2 AND state='prepared'").bind(c.tenant.to_string()).bind(attempt).execute(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        renewal::challenge(
            &app,
            &apple,
            &csr,
            secret,
            "renewal",
            "rss-agent",
            &issuer,
            &audit(c)
        )
        .await?,
        "original epoch challenge consumed"
    );
    let trust = rss_mdm_device_trust::apple::AppleDeviceTrust::from_trust(
        rss_mdm_device_trust::DeviceTrust::new(
            n.trust.clone(),
            rss_mdm_agent_wire::pki::Purpose::Apple,
            now,
        )?,
    )?;
    let leaf = trust.verify(
        &[tokio_rustls::rustls::pki_types::CertificateDer::from(
            identity::der("x509", &path.join("client.pem")).await?,
        )],
        now,
    )?;
    for _ in 0..2 {
        ensure!(
            renewal::notify(&app, &apple, &leaf, &csr, "renewal", &audit(c)).await?,
            "notify and replay"
        );
    }
    for _ in 0..2 {
        renewal::activate(&app, c.execution(), &apple, &leaf, &n.device.to_string()).await?;
    }
    let mut tx = command::seed_transaction(c).await?;
    let states: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id,state FROM mdm_apple.scep_attempts WHERE tenant_id=$1::uuid AND id=ANY($2)",
    )
    .bind(c.tenant.to_string())
    .bind(vec![n.attempt, attempt])
    .fetch_all(&mut *tx)
    .await?;
    ensure!(
        states.contains(&(n.attempt, "superseded".into()))
            && states.contains(&(attempt, "bound".into())),
        "predecessor is atomically superseded"
    );
    let revoked: bool = sqlx::query_scalar(
        "SELECT state<>'active' FROM mdm_access.credentials WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(n.credential)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(revoked, "old authenticated credential is fenced");
    tx.rollback().await?;
    profile_url(c, app).await?;
    Ok(())
}

#[allow(
    clippy::disallowed_methods,
    reason = "integration supplies the production monotonic clock"
)]
async fn profile_url(c: &Context, app: HttpState) -> Result<()> {
    use rss_mdm_registration_service::enrollment as e;
    let account = c
        .account(&[rss_mdm_authorization_service::Permission::Enrollment])
        .await?;
    let proof = c.authenticate(&account).await?;
    let password = e::random();
    let service = e::EnrollmentService::new(
        c.database.registration(),
        app.credentials.clone(),
        c.audit.clone(),
    );
    let operation = Uuid::new_v4();
    let request = audit(c);
    proof.bind_audit(&request)?;
    request.owned_operation(
        rss_mdm_audit_integration::operation::OperationOwner::Registration,
        operation,
        "enrollment_create",
        AuditIntent::Management,
    );
    let created = service
        .create(
            &proof,
            &e::Create {
                password: e::Password::new(password.clone())?,
                source: rss_mdm_inventory::ReportSource::MdmApple,
                windows_profile: None,
            },
            &account.credential()?,
            operation,
            &request,
        )
        .await
        .context("create profile enrollment")?;
    let status = service
        .status(
            &proof,
            created.enrollment_id,
            &audit(c),
            &crate::enrollment_progress::EnrollmentProgress {
                sessions: app.identity.clone(),
                windows: None,
                apple: true,
            },
        )
        .await?;
    let status = serde_json::to_value(status)?;
    let path = status["instructions"]["profileUrl"]
        .as_str()
        .context("production profileUrl")?;
    let monotonic = Arc::new(crate::Monotonic(std::time::Instant::now));
    let envelope = rss_mdm_apple_channel::boundary::Envelope {
        request_budget: rss_axum::RequestBudget::new(Duration::from_secs(8))?,
        admission: Arc::new(tokio::sync::Semaphore::new(8)),
        host: "localhost".into(),
        clock: monotonic,
        audit_store: c.audit.clone(),
        requests: app.requests.clone(),
    };
    let mut lifecycle = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let (control, gate) = lifecycle
        .startup()?
        .commit()
        .finish_with_admission("apple-profile-t2", Duration::from_secs(10));
    control.open()?;
    let router = rss_mdm_apple_channel::browser_routes(Arc::new(app), envelope)
        .into_checked_axum(rss_mdm_http_contract::module::Listener::Browser)
        .layer(axum::Extension(gate));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
    });
    let result = async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()?;
        let response = client
            .post(format!("http://{address}{path}"))
            .header("host", "localhost")
            .json(&serde_json::json!({"password":e::random()}))
            .send()
            .await?;
        ensure!(
            matches!(response.status().as_u16(), 401 | 403),
            "wrong enrollment password denied at returned URL"
        );
        let response = client
            .post(format!("http://{address}{path}"))
            .header("host", "localhost")
            .json(&serde_json::json!({"password":password}))
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "returned profile URL: {}",
            response.status()
        );
        let mut profile = Vec::new();
        openssl::cms::CmsContentInfo::from_der(&response.bytes().await?)?.verify(
            None,
            None,
            None,
            Some(&mut profile),
            openssl::cms::CMSOptions::NOVERIFY,
        )?;
        let profile: plist::Value = plist::from_bytes(&profile)?;
        ensure!(
            profile.as_dictionary().unwrap()["PayloadType"].as_string() == Some("Configuration"),
            "real signed configuration returned"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(15), task).await???;
    ensure!(
        lifecycle.shutdown().join().await?.is_clean(),
        "native profile ingress drained"
    );
    result
}
