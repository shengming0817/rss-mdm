//! Pinned CA, durable grant/issuance state and real TLS possession.
mod maintenance;
use crate::device::test_support::{admin, case_a, case_b, options};
use crate::test_support::agent_http::{agent_http, connect_agent};
use crate::test_support::agent_tls::peer;
use crate::{
    Database,
    clock::{Clock, SystemClock},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::{enroll as wire, runtime};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_certificate::agent::VerifiedAgentCsr;
use rss_mdm_registration_service::agent::{Assembly, NativeAdmission, Pending, Service};
use sqlx::Connection;
use std::{path::PathBuf, sync::Arc, time::Duration};
use uuid::Uuid;
use x509_cert::der::Decode;
pub(crate) fn root() -> PathBuf {
    PathBuf::from(std::env::var("MDM_AGENT_PKI_FIXTURES").unwrap())
}
pub(crate) fn now() -> i64 {
    SystemClock.unix_seconds().unwrap()
}
pub(crate) fn deployment() -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(
            root()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("agent-pki.json"),
        )
        .unwrap(),
    )
    .unwrap()
}
struct NoNative;
impl NativeAdmission for NoNative {
    fn bootstrap<'a>(
        &'a self,
        _: &'a mut sqlx::PgConnection,
        _: &'a rss_mdm_registration_service::agent::native::Source,
    ) -> Pending<'a, ()> {
        Box::pin(async { Err(rss_mdm_registration_service::Error::Forbidden) })
    }
    fn grant<'a>(
        &'a self,
        _: &'a mut sqlx::PgConnection,
        _: &'a rss_mdm_registration_service::agent::native::Source,
        _: &'a rss_mdm_agent_wire::enroll::NativeGrantRequest,
    ) -> Pending<'a, (rss_mdm_agent_wire::enroll::GrantReceipt, bool)> {
        Box::pin(async { Err(rss_mdm_registration_service::Error::Forbidden) })
    }

    fn validate<'a>(
        &'a self,
        _c: &'a mut sqlx::PgConnection,
        _source: &'a rss_mdm_registration_service::agent::native::Source,
    ) -> Pending<'a, ()> {
        Box::pin(async { Err(rss_mdm_registration_service::Error::Forbidden) })
    }
}
pub(crate) async fn service(value: serde_json::Value) -> anyhow::Result<Arc<Service>> {
    service_with_provider(value, None).await
}
async fn service_with_provider(
    value: serde_json::Value,
    kid: Option<&str>,
) -> anyhow::Result<Arc<Service>> {
    let db = Database::connect(options("mdm_access")?).await?;
    let audit = db.audit_store(&crate::config::AuditConfig::Plain).await?;
    let providers = if let Some(kid) = kid {
        let mut config: Vec<crate::device_pki::Provider> = serde_json::from_slice(&std::fs::read(
            root()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("device-pki.json"),
        )?)?;
        for p in &mut config {
            if p.purpose == rss_mdm_agent_wire::pki::Purpose::Agent {
                p.kid = kid.into();
            }
        }
        crate::device_pki::providers(&config)?
    } else {
        fixture_providers()?
    };
    let config: crate::agent_pki::Config = serde_json::from_value(value)?;
    let pki = config
        .load(audit.clone(), Arc::new(SystemClock), providers.clone())?
        .unwrap();
    let registry = rss_mdm_pki_service::registry::Registry::new(
        db.archive_pool(),
        audit.clone(),
        vec![pki.issuer.trust().trust.clone()],
        fixture_providers()?,
    );
    registry
        .admit(rss_request_context::TenantId::parse(case_a())?, now())
        .await?;
    Ok(Arc::new(Service::new(Assembly {
        tenant: rss_request_context::TenantId::parse(case_a())?,
        store: db.registration(),
        audit,
        issuer: pki.issuer.clone(),
        clock: pki.pki_clock.clone(),
        origin: pki.origin.clone(),
        configuration_signer: Arc::new(crate::test_support::agent::fixture_signer()?),
        installations: Arc::new(crate::agent_configurations::Installations),
        bootstrap: None,
        binding: Arc::new(crate::agent::Bindings),
        native: Arc::new(NoNative),
    })?))
}
pub(crate) fn audit() -> RequestAudit {
    RequestAudit::new(case_a().into(), "agent_request")
}
pub(crate) fn grant() -> anyhow::Result<wire::GrantRequest> {
    Ok(wire::GrantRequest {
        wire_version: 1,
        operation_id: Uuid::new_v4(),
        secret: runtime::Secret::parse(&crate::enrollment::random())?,
        platform: runtime::TaskPlatform::Macos,
        csr: STANDARD.encode(std::fs::read(root().join("agent.der"))?),
    })
}
pub(crate) fn signing(
    g: &wire::GrantRequest,
    id: Uuid,
) -> anyhow::Result<wire::CertificateRequest> {
    Ok(wire::CertificateRequest {
        wire_version: 1,
        operation_id: Uuid::new_v4(),
        grant_id: id,
        secret: g.secret.clone(),
        csr: g.csr.clone(),
        runtime: serde_json::from_value(
            crate::test_support::json!({"capabilities":["inventory.collect.v1"],"platform":"macos","architecture":"aarch64","executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs)}),
        )?,
    })
}
pub(crate) fn chain(c: &wire::Candidate) -> anyhow::Result<Vec<Vec<u8>>> {
    Ok(c.certificate_chain
        .iter()
        .map(|v| STANDARD.decode(v))
        .collect::<Result<_, _>>()?)
}

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki: renewal grant response lost before predecessor expiry"]
async fn renewal_grant_lookup_survives_expired_identity_without_writing_authority()
-> anyhow::Result<()> {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicI64, Ordering};
    use tower::ServiceExt;
    struct Time(AtomicI64);
    impl rss_mdm_registration_service::agent_pki::Clock for Time {
        fn unix_seconds(&self) -> Result<i64, rss_mdm_registration_service::Error> {
            Ok(self.0.load(Ordering::Acquire))
        }
    }
    async fn lookup(
        router: &Router,
        input: &wire::RenewalStatusRequest,
    ) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/v1/agent/enroll/renewal-grants/status")
                    .header("host", "mdm.example.test")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(input)?))?,
            )
            .await?;
        Ok((
            response.status(),
            serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?,
        ))
    }
    let original = service(deployment()).await?;
    let db = Database::connect(options("mdm_access")?).await?;
    let audit_store = db.audit_store(&crate::config::AuditConfig::Plain).await?;
    let pki = serde_json::from_value::<crate::agent_pki::Config>(deployment())?
        .load(
            audit_store.clone(),
            Arc::new(SystemClock),
            fixture_providers()?,
        )?
        .unwrap();
    let time = Arc::new(Time(AtomicI64::new(now())));
    let assemble = |tenant: &str| -> anyhow::Result<Arc<Service>> {
        Ok(Arc::new(Service::new(Assembly {
            tenant: rss_request_context::TenantId::parse(tenant)?,
            store: db.registration(),
            audit: audit_store.clone(),
            issuer: pki.issuer.clone(),
            clock: time.clone(),
            origin: pki.origin.clone(),
            configuration_signer: Arc::new(crate::test_support::agent::fixture_signer()?),
            installations: Arc::new(crate::agent_configurations::Installations),
            bootstrap: None,
            binding: Arc::new(crate::agent::Bindings),
            native: Arc::new(NoNative),
        })?))
    };
    let s = assemble(case_a())?;
    let p = admin(case_a(), "admin-a").await?;
    let initial = grant()?;
    let r = authorize_request(&original, &p, &initial, &audit()).await?;
    let candidate = original
        .issue(&signing(&initial, r.grant_id)?, &audit())
        .await?;
    let evidence = peer(original.trust(), &chain(&candidate)?, &root()).await?;
    original
        .activate(
            &evidence,
            &wire::ActivationRequest {
                wire_version: 1,
                issuance_id: candidate.issuance_id,
                operation_id: Uuid::new_v4(),
            },
            &audit(),
        )
        .await?;
    let expiry = original
        .trust()
        .verify_peer(&evidence, now())?
        .metadata()
        .not_after;
    let renewal = grant()?;
    // Certificate issuance uses the database clock; start the frozen verifier only
    // after activation so it cannot precede the certificate's validity window.
    time.0.store(now(), Ordering::Release);
    s.authenticate(&evidence).await?;
    audit_store.inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    let lost = s.renew(&evidence, &renewal, &audit()).await.unwrap_err();
    assert_eq!(lost.code, wire::ErrorCode::ActivationUnknown);
    assert!(
        matches!(
            &lost.source,
            Some(rss_mdm_registration_service::Error::CommitUnknown)
        ),
        "{lost:?}"
    );
    // No renewal receipt was received. Advance the credential verifier to its exact expiry;
    // the already committed grant retains its original database deadline.
    time.0.store(expiry, Ordering::Release);
    assert_eq!(
        s.renew(&evidence, &renewal, &audit())
            .await
            .err()
            .unwrap()
            .code,
        wire::ErrorCode::CertificateExpired
    );
    let router = Router::new().nest(
        "/api/v1/agent/enroll",
        rss_mdm_agent_channel::enroll::router(s.clone(), envelope("mdm.example.test").await?),
    );
    let request = wire::RenewalStatusRequest {
        wire_version: 1,
        operation_id: renewal.operation_id,
        secret: renewal.secret.clone(),
    };
    let snapshot = || {
        crate::test_support::pg_tenant(
            case_a(),
            &format!(
                "SELECT (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM mdm_access.agent_grants g WHERE tenant_id='{tenant}'),(SELECT jsonb_agg(to_jsonb(i) ORDER BY id) FROM mdm_access.agent_issuances i WHERE tenant_id='{tenant}'),(SELECT jsonb_agg(to_jsonb(k) ORDER BY id) FROM mdm_access.credentials k WHERE tenant_id='{tenant}')",
                tenant = case_a()
            ),
        )
    };
    let before = snapshot()?;
    let (status, recovered) = lookup(&router, &request).await?;
    assert_eq!(status, StatusCode::OK, "{recovered}");
    let receipt: wire::GrantReceipt = serde_json::from_value(recovered.clone())?;
    assert_eq!(receipt.state, wire::GrantState::Available);
    assert_eq!(
        lookup(&router, &request).await?,
        (status, recovered.clone())
    );
    let mut wrong = request.clone();
    wrong.secret = runtime::Secret::parse(&crate::enrollment::random())?;
    let denied = lookup(&router, &wrong).await?;
    assert_eq!(denied.0, StatusCode::UNAUTHORIZED);
    wrong = request.clone();
    wrong.operation_id = Uuid::new_v4();
    assert_eq!(lookup(&router, &wrong).await?, denied);
    // An existing non-renewal operation cannot be consumed through this endpoint.
    wrong.operation_id = initial.operation_id;
    wrong.secret = initial.secret;
    assert_eq!(lookup(&router, &wrong).await?, denied);
    assert_eq!(
        assemble(case_b())?
            .renewal_status(&request)
            .await
            .err()
            .unwrap()
            .code,
        wire::ErrorCode::InvalidIdentity
    );
    assert_eq!(
        snapshot()?,
        before,
        "lookup changed grant, issuance or credential facts"
    );
    // Revocation and expiry remain observable; neither query refreshes a deadline.
    s.revoke(&p, receipt.grant_id, Uuid::new_v4(), &audit())
        .await?;
    let revoked = lookup(&router, &request).await?;
    assert_eq!(revoked.0, StatusCode::OK);
    assert_eq!(revoked.1["state"], "revoked");
    assert_eq!(revoked.1["expiresAt"], recovered["expiresAt"]);
    let another = grant()?;
    let retained = original.renew(&evidence, &another, &audit()).await?;
    crate::test_support::pg_tenant(
        case_a(),
        &format!(
            "UPDATE mdm_access.agent_grants SET created_at=clock_timestamp()-interval '25 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE tenant_id='{}' AND id='{}'",
            case_a(),
            retained.grant_id
        ),
    )?;
    let expired_request = wire::RenewalStatusRequest {
        wire_version: 1,
        operation_id: another.operation_id,
        secret: another.secret,
    };
    let before = snapshot()?;
    let expired = lookup(&router, &expired_request).await?;
    assert_eq!(expired.0, StatusCode::OK);
    assert_eq!(expired.1["state"], "expired");
    assert_eq!(snapshot()?, before);
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki"]
async fn explicit_development_limit_and_unknown_result_remain_auditable() -> anyhow::Result<()> {
    let p = admin(case_a(), "admin-a").await?;
    let mut value = deployment();
    value["lifetime"] = serde_json::json!({"mode":"development","days":3650});
    let s = service(value.clone()).await?;
    let g = grant()?;
    let r = authorize_request(&s, &p, &g, &audit()).await?;
    let c = s.issue(&signing(&g, r.grant_id)?, &audit()).await?;
    let evidence = peer(s.trust(), &chain(&c)?, &root()).await?;
    let metadata = s.trust().verify_peer(&evidence, now())?;
    assert_eq!(
        metadata.metadata().not_after - metadata.metadata().not_before,
        3650 * 86400
    );
    let production = service(deployment()).await?;
    assert!(matches!(
        production.trust().verify_peer(&evidence, now()),
        Err(rss_mdm_certificate::Error::Unauthorized)
    ));
    let control = grant()?;
    let authorized = authorize_request(&production, &p, &control, &audit()).await?;
    let signed = production
        .issue(&signing(&control, authorized.grant_id)?, &audit())
        .await?;
    let accepted = peer(production.trust(), &chain(&signed)?, &root()).await?;
    production.trust().verify_peer(&accepted, now())?;
    let value = deployment();
    let unknown = service_with_provider(value, Some("absent-agent-key")).await?;
    let g = grant()?;
    let r = authorize_request(&unknown, &p, &g, &audit()).await?;
    let input = signing(&g, r.grant_id)?;
    use axum::{Router, body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let router = Router::new().nest(
        "/api/v1/agent/enroll",
        rss_mdm_agent_channel::enroll::router(unknown.clone(), envelope("mdm.example.test").await?),
    );
    let mut failures = Vec::new();
    let mut owner =
        <sqlx::PgConnection as sqlx::Connection>::connect_with(&options("postgres")?).await?;
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/v1/agent/enroll/certificates")
                    .header("host", "mdm.example.test")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&input)?))?,
            )
            .await?;
        assert_eq!(response.status(), 503);
        let id = response.headers()["x-request-id"].to_str()?.to_owned();
        failures.push(serde_json::from_slice::<wire::ErrorBody>(
            &response.into_body().collect().await?.to_bytes(),
        )?);
        let records = crate::audit_test_support::read(&mut owner).await?;
        let facts: Vec<_> = records
            .iter()
            .filter(|r| r.request() == Some(id.as_str()))
            .collect();
        let settlements: Vec<_> = facts
            .iter()
            .filter(|r| r.source() == "mdm.request")
            .collect();
        assert_eq!(settlements.len(), 1);
        assert_eq!(settlements[0].status(), 503);
        assert_eq!(settlements[0].result(), "failed");
        if failures.len() == 1 {
            assert!(
                records.iter().any(|r| r.source() == "mdm.business"
                    && r.operation() == Some(input.operation_id.to_string().as_str())
                    && r.status() == 200),
                "durable claim fact must survive final CA failure settlement"
            );
        }
    }
    let first = &failures[0];
    let retry = &failures[1];
    assert_eq!(first.code, wire::ErrorCode::IssuanceUnknown);
    assert_eq!(first.issuance_id, retry.issuance_id);
    let restarted = service(deployment()).await?;
    let recovered = restarted
        .recover_issuance(
            &p,
            first.issuance_id.unwrap(),
            &wire::RecoverIssuance {
                wire_version: 1,
                operation_id: Uuid::new_v4(),
                certificate_chain: vec![],
            },
            &audit(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(
        recovered.code,
        wire::ErrorCode::MalformedRequest,
        "empty recovery chains fail before adopting any signing result"
    );
    let still_unknown = restarted.issue(&input, &audit()).await.unwrap_err();
    assert_eq!(still_unknown.code, wire::ErrorCode::IssuanceUnknown);
    assert_eq!(still_unknown.issuance_id, first.issuance_id);
    let mut changed = input.clone();
    changed.operation_id = Uuid::new_v4();
    assert_eq!(
        unknown.issue(&changed, &audit()).await.unwrap_err().code,
        wire::ErrorCode::OperationConflict
    );
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki"]
async fn provisioner_rejects_substituted_csr_and_consumed_token() -> anyhow::Result<()> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ring::{rand::SystemRandom, signature};
    use sha2::{Digest, Sha256};
    let csr = VerifiedAgentCsr::verify(&std::fs::read(root().join("agent.der"))?)?;
    let url = format!("{}/sign", std::env::var("MDM_STEP_CA_URL")?);
    let key =
        signature::RsaKeyPair::from_pkcs8(&std::fs::read(root().join("agent-provisioner.pk8"))?)
            .unwrap();
    let identity =
        rss_mdm_certificate::agent::identity(Uuid::parse_str(case_a())?, "provider-binding")?;
    let token = || -> anyhow::Result<String> {
        let claims = serde_json::json!({"iss":"rss-agent","aud":[url],"sub":"rss-mdm-agent","sans":[identity],"iat":now(),"nbf":now(),"exp":now()+60,"jti":Uuid::new_v4().to_string(),"cnf":{"x5rt#S256":URL_SAFE_NO_PAD.encode(Sha256::digest(csr.der()))}});
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(
                &serde_json::json!({"alg":"RS256","kid":"agent-t2-key"})
            )?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
        );
        let mut signature = vec![0; key.public().modulus_len()];
        key.sign(
            &signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            message.as_bytes(),
            &mut signature,
        )
        .unwrap();
        Ok(format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature)))
    };
    let client = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            root().join("step/certs/root_ca.crt"),
        )?)?)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let control = client
        .post(&url)
        .json(&serde_json::json!({"csr":csr.pem()?,"ott":token()?}))
        .send()
        .await?;
    assert_eq!(control.status(), reqwest::StatusCode::CREATED);
    let issued: serde_json::Value = control.json().await?;
    assert!(!issued["crt"].as_str().unwrap().is_empty());
    let token = token()?;
    // Different correctly signed RSA key/CSR with the same CN: only cnf binding
    // rejects substitution. step-ca consumes the token before CSR validation.
    // Another valid Agent CSR uses an independent SHA256 RSA key.
    let other = x509_cert::request::CertReq::from_der(&std::fs::read(root().join("other.der"))?)?;
    use x509_cert::der::{EncodePem, pem::LineEnding};
    let substituted = other.to_pem(LineEnding::LF)?;
    let response = client
        .post(&url)
        .json(&serde_json::json!({"csr":substituted,"ott":token}))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let response = client
        .post(&url)
        .json(&serde_json::json!({"csr":csr.pem()?,"ott":token}))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    Ok(())
}

async fn envelope(host: &str) -> anyhow::Result<rss_mdm_agent_channel::boundary::Envelope> {
    let db = Database::connect(options("mdm_access")?).await?;
    Ok(rss_mdm_agent_channel::boundary::Envelope {
        admission: Arc::new(tokio::sync::Semaphore::new(32)),
        host: host.into(),
        clock: crate::test_support::monotonic(),
        audit_store: db.audit_store(&crate::config::AuditConfig::Plain).await?,
        requests: Arc::new(tokio::sync::Semaphore::new(4)),
        tenant: case_a().into(),
    })
}

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki"]
async fn agent_ingress_holds_one_global_permit_per_request() -> anyhow::Result<()> {
    use axum::{Router, body::Body, http::Request, middleware, routing::get};
    use tokio::sync::{Barrier, mpsc};
    use tower::ServiceExt;
    let envelope = envelope("mdm.example.test").await?;
    let requests = envelope.requests.clone();
    let admission = crate::native::admission::Admission::new(
        envelope.clock.clone(),
        requests.clone(),
        "mdm-agent",
    );
    let first = admission.connection("127.0.0.1".parse()?).unwrap();
    let second = admission.connection("127.0.0.2".parse()?).unwrap();
    let third = admission.connection("127.0.0.3".parse()?).unwrap();
    let release = Arc::new(Barrier::new(5));
    let (entered, mut entries) = mpsc::channel(4);
    let handler_release = release.clone();
    let ready_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ready_counter = ready_calls.clone();
    let held = get(move || {
        let entered = entered.clone();
        let release = handler_release.clone();
        async move {
            entered.send(()).await.unwrap();
            release.wait().await;
            "done"
        }
    });
    let router = rss_mdm_agent_channel::boundary::wrap(
        Router::new().route("/held", held).route(
            "/ready",
            get(move || {
                let calls = ready_counter.clone();
                async move {
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    axum::http::StatusCode::NO_CONTENT
                }
            }),
        ),
        envelope,
    )
    .layer(middleware::from_fn(crate::native::admission::admit_agent));
    let mut running = Vec::new();
    for gate in [first.gate(), first.gate(), second.gate(), second.gate()] {
        let request = Request::get("/held")
            .header("host", "mdm.example.test")
            .extension(gate)
            .body(Body::empty())?;
        let router = router.clone();
        running.push(tokio::spawn(async move { router.oneshot(request).await }));
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        for _ in 0..4 {
            entries.recv().await.unwrap();
        }
    })
    .await?;
    assert_eq!(requests.available_permits(), 0);
    let response = router
        .clone()
        .oneshot(
            Request::get("/ready")
                .header("host", "mdm.example.test")
                .extension(third.gate())
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        response.status(),
        503,
        "fifth peer reaches the global body budget"
    );
    assert_eq!(ready_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    release.wait().await;
    let mut completed = Vec::new();
    for task in running {
        let response = task.await??;
        assert_eq!(response.status(), 200);
        completed.push(response.headers()["x-request-id"].to_str()?.to_owned());
    }
    let mut observer =
        <sqlx::PgConnection as sqlx::Connection>::connect_with(&options("postgres")?).await?;
    let records = crate::audit_test_support::read(&mut observer).await?;
    for id in completed {
        assert_eq!(
            records
                .iter()
                .filter(|r| r.request() == Some(id.as_str()) && r.status() == 200)
                .count(),
            1
        );
    }
    observer.close().await?;
    assert_eq!(requests.available_permits(), 4);
    let response = router
        .oneshot(
            Request::get("/ready")
                .header("host", "mdm.example.test")
                .extension(third.gate())
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), 204);
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki"]
async fn production_agent_listener_bootstraps_activates_and_rechecks_revocation()
-> anyhow::Result<()> {
    let host = crate::windows::test_support::Host::open().await?;
    let routers = crate::api::from_state(
        host.app.clone(),
        "mdm.example.test".into(),
        crate::test_support::monotonic(),
    );
    let (_, router) = routers
        .listeners
        .into_iter()
        .find(|(kind, _)| *kind == crate::native::NativeListenerKind::Agent)
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut owner = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(5))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    owner
        .startup()?
        .stage_task_with_token(crate::native::tls::registration(
            listener,
            router,
            host.app.audit_store.clone(),
            case_a().into(),
            crate::native::NativeListenerKind::Agent,
        ));
    let g = grant()?;
    let mut anonymous = connect_agent(address, None).await?;
    let (status, body) = agent_http(
        &mut anonymous,
        "POST",
        "/api/v1/agent/enroll/requests",
        Some(serde_json::to_value(&g)?),
    )
    .await?;
    assert_eq!(status, 200, "anonymous TLS bootstrap: {body}");
    let receipt: wire::GrantReceipt = serde_json::from_value(body)?;
    let p = admin(case_a(), "admin-a").await?;
    host.app
        .agent_enrollment
        .as_ref()
        .unwrap()
        .authorize(&p, receipt.grant_id, Uuid::new_v4(), &audit())
        .await?;
    let (status, body) = agent_http(
        &mut anonymous,
        "POST",
        "/api/v1/agent/enroll/certificates",
        Some(serde_json::to_value(signing(&g, receipt.grant_id)?)?),
    )
    .await?;
    assert_eq!(status, 200, "anonymous signing: {body}");
    let candidate: wire::Candidate = serde_json::from_value(body)?;
    let path = format!("/api/v1/agent/runtime/reports/{}", Uuid::new_v4());
    let (status, body) = agent_http(&mut anonymous, "GET", &path, None).await?;
    assert_eq!(status, 401);
    assert_eq!(body["code"], "invalid_identity");
    let mut certified = connect_agent(address, Some(&chain(&candidate)?)).await?;
    let (status, body) = agent_http(&mut certified, "GET", &path, None).await?;
    assert_eq!(status, 401);
    assert_eq!(
        body["code"], "invalid_identity",
        "candidate is not an active identity"
    );
    let (status, body) = agent_http(
        &mut certified,
        "POST",
        "/api/v1/agent/enroll/activate",
        Some(serde_json::to_value(wire::ActivationRequest {
            wire_version: 1,
            issuance_id: candidate.issuance_id,
            operation_id: Uuid::new_v4(),
        })?),
    )
    .await?;
    assert_eq!(status, 200, "activation through real TLS proof: {body}");
    let active: wire::ActivationReceipt = serde_json::from_value(body)?;
    let (status, body) = agent_http(&mut certified, "GET", &path, None).await?;
    assert_eq!(status, 404);
    assert_eq!(
        body["code"], "report_not_found",
        "active identity reaches report lookup"
    );
    let (status, body) =
        agent_http(&mut anonymous, "GET", "/api/v1/agent/enroll/trust", None).await?;
    assert_eq!(status, 200);
    let trust: rss_mdm_agent_wire::pki::Trust = serde_json::from_value(body)?;
    let observation_path = "/api/v1/agent/enroll/trust/observations";
    let observation = serde_json::json!({"operation":Uuid::new_v4(),"version":1,
        "registration":active.runtime.registration_id,"generation":active.runtime.generation,
        "sequence":2,"target_revision":trust.revision,"target_digest":trust.installation_digest(),
        "actual_revision":trust.revision,"actual_digest":trust.installation_digest(),
        "state":"applied","reason":null,"observed_at":1});
    assert_eq!(
        agent_http(
            &mut anonymous,
            "POST",
            observation_path,
            Some(observation.clone())
        )
        .await?
        .0,
        401
    );
    for _ in 0..2 {
        let (status, body) = agent_http(
            &mut certified,
            "POST",
            observation_path,
            Some(observation.clone()),
        )
        .await?;
        assert_eq!(status, 200, "observation: {body}");
        assert_eq!(body, observation);
    }
    let mut invalid = observation.clone();
    invalid["generation"] = serde_json::json!(active.runtime.generation + 1);
    assert_eq!(
        agent_http(&mut certified, "POST", observation_path, Some(invalid))
            .await?
            .0,
        403
    );
    let mut conflict = observation.clone();
    conflict["observed_at"] = serde_json::json!(2);
    assert_eq!(
        agent_http(&mut certified, "POST", observation_path, Some(conflict))
            .await?
            .0,
        409
    );
    let mut older = observation.clone();
    older["operation"] = serde_json::json!(Uuid::new_v4());
    older["sequence"] = serde_json::json!(1);
    older["state"] = serde_json::json!("failed");
    older["reason"] = serde_json::json!("storage");
    assert_eq!(
        agent_http(&mut certified, "POST", observation_path, Some(older))
            .await?
            .0,
        200
    );
    let secret = crate::test_support::identity::login(&host.app.identity, "other").await?;
    let mut observer = crate::test_support::Browser {
        cookies: std::collections::BTreeMap::from([(
            "__Host-identity-session".into(),
            secret.expose().into(),
        )]),
        csrf: Some(secret.csrf()),
        ..Default::default()
    };
    let subject = crate::test_support::browser_subject(&observer, &host.browser).await?;
    let query_path = format!(
        "/api/v1/pki/agent/trust/devices/{}/observation",
        active.runtime.device_id
    );
    crate::test_support::identity::set_grants(
        case_a(),
        &subject,
        crate::test_support::identity::device_grants(
            Some(&active.runtime.device_id),
            &["inventory_read"],
        )?,
    )
    .await?;
    let (status, body) = observer
        .call(&host.browser, axum::http::Method::GET, &query_path, None)
        .await?;
    assert_eq!(status, 200, "management observation: {body}");
    assert_eq!(body["observation"], observation);
    crate::test_support::identity::set_grants(
        case_a(),
        &subject,
        crate::test_support::identity::device_grants(Some("another-device"), &["inventory_read"])?,
    )
    .await?;
    assert_eq!(
        observer
            .call(&host.browser, axum::http::Method::GET, &query_path, None)
            .await?
            .0,
        403
    );
    let ack = rss_mdm_agent_wire::pki::Acknowledgement {
        operation: Uuid::new_v4(),
        version: 1,
        revision: trust.revision,
        digest: trust.installation_digest(),
    };
    let mut tx = host.store.archive_pool().begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_a())
        .execute(&mut *tx)
        .await?;
    let latest =
        rss_mdm_pki_service::observations::latest_in(&mut tx, case_a(), &active.runtime.device_id)
            .await?
            .expect("persisted observation");
    assert_eq!(serde_json::to_value(latest.observation)?, observation);
    assert!(latest.received_at > 0);
    let installations = "SELECT count(*) FROM mdm_pki.installations WHERE tenant_id=$1::uuid AND purpose='agent' AND registration=$2";
    assert_eq!(
        sqlx::query_scalar::<_, i64>(installations)
            .bind(case_a())
            .bind(active.runtime.registration_id)
            .fetch_one(&mut *tx)
            .await?,
        0
    );
    for (field, value, expected) in [
        ("version", serde_json::json!(2), 400),
        ("operation", serde_json::json!(Uuid::nil()), 400),
        (
            "operation",
            serde_json::json!(ack.operation.simple().to_string()),
            400,
        ),
        ("revision", serde_json::json!(0), 400),
        ("revision", serde_json::json!(i64::MAX as u64 + 1), 400),
        ("digest", serde_json::json!("A".repeat(64)), 400),
        ("digest", serde_json::json!("0".repeat(64)), 409),
        ("purpose", serde_json::json!("agent"), 400),
    ] {
        let mut invalid = serde_json::to_value(&ack)?;
        invalid[field] = value;
        let (status, _) = agent_http(
            &mut certified,
            "POST",
            "/api/v1/agent/enroll/trust/acknowledgements",
            Some(invalid),
        )
        .await?;
        assert_eq!(status, expected, "{field}");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(installations)
                .bind(case_a())
                .bind(active.runtime.registration_id)
                .fetch_one(&mut *tx)
                .await?,
            0
        );
    }
    for _ in 0..2 {
        let (status, _) = agent_http(
            &mut certified,
            "POST",
            "/api/v1/agent/enroll/trust/acknowledgements",
            Some(serde_json::to_value(&ack)?),
        )
        .await?;
        assert_eq!(status, 204, "valid ACK and exact retry");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(installations)
                .bind(case_a())
                .bind(active.runtime.registration_id)
                .fetch_one(&mut *tx)
                .await?,
            1
        );
    }
    let service = host.app.agent_enrollment.as_ref().unwrap();
    let evidence = peer(service.trust(), &chain(&candidate)?, &root()).await?;
    let mut invalid = ack;
    invalid.version = 2;
    assert_eq!(
        service
            .acknowledge_trust(&evidence, &invalid, &audit())
            .await
            .unwrap_err()
            .code,
        wire::ErrorCode::MalformedRequest,
        "direct Rust ACK is checked before replay"
    );
    tx.rollback().await?;
    host.app
        .devices
        .revoke(
            &p,
            &active.runtime.device_id,
            active.runtime.registration_id,
            Uuid::new_v4(),
        )
        .await?;
    let (status, body) = agent_http(&mut certified, "GET", &path, None).await?;
    assert_eq!(status, 401);
    assert_eq!(
        body["code"], "credential_revoked",
        "same TLS connection must recheck revoked credentials"
    );
    crate::test_support::identity::set_grants(
        case_a(),
        &subject,
        crate::test_support::identity::device_grants(
            Some(&active.runtime.device_id),
            &["inventory_read"],
        )?,
    )
    .await?;
    assert_eq!(
        observer
            .call(&host.browser, axum::http::Method::GET, &query_path, None)
            .await?,
        (axum::http::StatusCode::OK, serde_json::Value::Null)
    );
    // Minimal successor fixture for the read boundary; this does not reactivate a credential.
    let mut c = sqlx::PgConnection::connect_with(&options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_a())
        .execute(&mut c)
        .await?;
    sqlx::query("UPDATE mdm_access.registrations SET state='active',generation=generation+1 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_a()).bind(active.runtime.registration_id).execute(&mut c).await?;
    assert_eq!(
        observer
            .call(&host.browser, axum::http::Method::GET, &query_path, None)
            .await?,
        (axum::http::StatusCode::OK, serde_json::Value::Null)
    );
    let mut next: rss_mdm_agent_wire::pki::Observation = serde_json::from_value(observation)?;
    next.operation = Uuid::new_v4();
    next.generation += 1;
    next.sequence = 1;
    rss_mdm_pki_service::observations::record_in(&mut c, case_a(), &next).await?;
    let (status, current) = observer
        .call(&host.browser, axum::http::Method::GET, &query_path, None)
        .await?;
    assert_eq!(status, 200);
    assert_eq!(current["observation"], serde_json::to_value(next)?);
    c.close().await?;
    drop(certified);
    drop(anonymous);
    assert!(owner.shutdown().join().await?.is_clean());
    host.close().await?;
    Ok(())
}

fn fixture_providers() -> anyhow::Result<Arc<rss_mdm_pki_service::providers::Providers>> {
    let config: Vec<crate::device_pki::Provider> = serde_json::from_slice(&std::fs::read(
        root()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("device-pki.json"),
    )?)?;
    Ok(crate::device_pki::providers(&config)?)
}

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki: actual second CA, TLS ACK and durable rotation"]
async fn rotation_requires_installed_trust_and_published_revocation_before_retirement()
-> anyhow::Result<()> {
    use rss_mdm_agent_wire::pki::{Acknowledgement, Mode, Purpose, Trust};
    use rss_mdm_pki_service::registry::{Action, Registry, Rotation, Transition};
    let s = service(deployment()).await?;
    let p = admin(case_a(), "admin-a").await?;
    let g = grant()?;
    let r = authorize_request(&s, &p, &g, &audit()).await?;
    let request = signing(&g, r.grant_id)?;
    let candidate = s.issue(&request, &audit()).await?;
    let evidence = peer(s.trust(), &chain(&candidate)?, &root()).await?;
    let activation = wire::ActivationRequest {
        wire_version: 1,
        issuance_id: candidate.issuance_id,
        operation_id: Uuid::new_v4(),
    };
    let receipt = s.activate(&evidence, &activation, &audit()).await?;
    let db = Database::connect(options("mdm_access")?).await?;
    let audit_store = db.audit_store(&crate::config::AuditConfig::Plain).await?;
    let binding = s.trust().trust.clone();
    let registry = Registry::new(
        db.archive_pool(),
        audit_store.clone(),
        vec![binding.clone()],
        fixture_providers()?,
    );
    let previous = registry.trust(Purpose::Agent)?;
    for purpose in [Purpose::Windows, Purpose::Apple] {
        let mut wrong = previous.clone();
        wrong.purpose = purpose;
        assert!(wrong.validate().is_ok());
        assert!(matches!(
            rss_mdm_device_trust::DeviceTrust::new(wrong, Purpose::Agent, now()),
            Err(rss_mdm_device_trust::Error::Malformed)
        ));
    }
    let mut duplicate = previous.clone();
    let mut issuer = duplicate.issuers[0].clone();
    issuer.mode = Mode::VerifyOnly;
    duplicate.issuers.push(issuer);
    assert!(duplicate.validate().is_ok());
    assert!(matches!(
        rss_mdm_device_trust::DeviceTrust::new(duplicate, Purpose::Agent, now()),
        Err(rss_mdm_device_trust::Error::Conflict)
    ));
    let next_root = PathBuf::from(std::env::var("MDM_AGENT_PKI_CANDIDATE_FIXTURES")?);
    let next: Trust = serde_json::from_slice(&std::fs::read(next_root.join("agent-trust.json"))?)?;
    let new_digest = next.issuers[0].digest.clone();
    assert_ne!(new_digest, previous.issuers[0].digest);
    let mut proposal = previous.clone();
    proposal.revision += 1;
    let mut added = next.issuers[0].clone();
    added.mode = Mode::Prepared;
    proposal.issuers.push(added);
    let rotation = Rotation {
        id: Uuid::new_v4(),
        purpose: Purpose::Agent,
        expected_revision: previous.revision,
        candidate: proposal,
    };
    registry.prepare(&p, &rotation, &audit(), now()).await?;
    let mut approve = Transition {
        id: rotation.id,
        expected_revision: registry.trust(Purpose::Agent)?.revision,
        action: Action::Approve,
    };
    assert!(matches!(
        registry
            .transition(&p, Purpose::Agent, &approve, &audit(), now())
            .await,
        Err(rss_mdm_pki_service::Error::Conflict)
    ));
    let state = crate::test_support::pg(&format!(
        "SELECT jsonb_build_array((SELECT state FROM mdm_pki.rotations WHERE tenant_id='{tenant}' AND id='{rotation}'),(SELECT count(*) FROM mdm_pki.installations WHERE tenant_id='{tenant}' AND purpose='agent' AND registration='{registration}'))::text",
        tenant = case_a(),
        rotation = rotation.id,
        registration = receipt.runtime.registration_id
    ))?;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&state)?,
        serde_json::json!(["distributing", 0])
    );
    let trust = registry.trust(Purpose::Agent)?;
    s.acknowledge_trust(
        &evidence,
        &Acknowledgement {
            operation: Uuid::new_v4(),
            version: 1,
            revision: trust.revision,
            digest: trust.installation_digest(),
        },
        &audit(),
    )
    .await?;
    registry
        .transition(&p, Purpose::Agent, &approve, &audit(), now())
        .await?;
    let trust = registry.trust(Purpose::Agent)?;
    s.acknowledge_trust(
        &evidence,
        &Acknowledgement {
            operation: Uuid::new_v4(),
            version: 1,
            revision: trust.revision,
            digest: trust.installation_digest(),
        },
        &audit(),
    )
    .await?;
    approve.expected_revision = trust.revision;
    approve.action = Action::Activate;
    registry
        .transition(&p, Purpose::Agent, &approve, &audit(), now())
        .await?;
    assert_eq!(binding.active()?.digest, new_digest);
    // An actual CA request follows the newly active generation.
    let newer = grant()?;
    let grant_receipt = authorize_request(&s, &p, &newer, &audit()).await?;
    let issued = s
        .issue(&signing(&newer, grant_receipt.grant_id)?, &audit())
        .await?;
    let verified = binding.verify(
        &chain(&issued)?
            .into_iter()
            .map(tokio_rustls::rustls::pki_types::CertificateDer::from)
            .collect::<Vec<_>>(),
        now(),
    )?;
    assert_eq!(verified.digest, new_digest);
    let retire = Transition {
        id: rotation.id,
        expected_revision: registry.trust(Purpose::Agent)?.revision,
        action: Action::Retire,
    };
    assert!(
        matches!(
            registry
                .transition(&p, Purpose::Agent, &retire, &audit(), now())
                .await,
            Err(rss_mdm_pki_service::Error::Conflict)
        ),
        "live old certificate cannot retire"
    );
    assert_eq!(crate::test_support::pg(&format!("SELECT count(*) FROM mdm_pki.certificates WHERE tenant_id='{}' AND issuer='{}' AND registration='{}' AND not_after>{}",case_a(),previous.issuers[0].digest,receipt.runtime.registration_id,now()))?.trim(), "1");
    let devices =
        crate::device::DeviceService::new(db.registration(), case_a().into(), audit_store.clone());
    devices
        .revoke(
            &p,
            &receipt.runtime.device_id,
            receipt.runtime.registration_id,
            Uuid::new_v4(),
        )
        .await?;
    assert!(
        matches!(
            registry
                .transition(&p, Purpose::Agent, &retire, &audit(), now())
                .await,
            Err(rss_mdm_pki_service::Error::Conflict)
        ),
        "revoke submission is not publication"
    );
    let pending = crate::test_support::pg(&format!(
        "SELECT count(*) FROM mdm_pki.revocations WHERE tenant_id='{}' AND issuer='{}' AND state<>'published'",
        case_a(),
        previous.issuers[0].digest
    ))?;
    assert_eq!(pending.trim(), "1");
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            registry.sweep(|| Ok(now())).await?;
            if registry
                .transition(&p, Purpose::Agent, &retire, &audit(), now())
                .await
                .is_ok()
            {
                return anyhow::Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("actual signed revoke publication did not unblock retirement")
    })??;
    let final_trust = registry.trust(Purpose::Agent)?;
    assert_eq!(final_trust.issuers.len(), 1);
    assert_eq!(final_trust.issuers[0].digest, new_digest);
    let restarted = service(deployment()).await?;
    assert_eq!(restarted.trust().trust.public()?, final_trust);

    // A management replay returns the original receipt after restart, never a new rotation.
    let restored = Registry::new(
        db.archive_pool(),
        audit_store,
        vec![restarted.trust().trust.clone()],
        fixture_providers()?,
    );
    assert_eq!(
        restored
            .prepare(&p, &rotation, &audit(), now())
            .await?
            .revision,
        previous.revision + 1
    );
    db.close().await;
    Ok(())
}

// Only signed publication fixtures use the disposable CA keys; positive issuance uses step-ca.
async fn publication_fixture(
    root: &std::path::Path,
    encoded: &str,
    offline: bool,
    at: i64,
    revoked: impl IntoIterator<Item = Vec<u8>>,
) -> anyhow::Result<String> {
    use x509_cert::{
        crl::{CertificateList, RevokedCert},
        der::{Encode, asn1::OctetString},
        ext::pkix::crl::CrlNumber,
        serial_number::SerialNumber,
        time::Time,
    };
    let mut list = CertificateList::from_der(&STANDARD.decode(encoded)?)?;
    let time = |n: i64| Time::try_from(std::time::UNIX_EPOCH + Duration::from_secs(n as u64));
    list.tbs_cert_list.this_update = time(at)?;
    list.tbs_cert_list.next_update = Some(time(at + 86400)?);
    for extension in list.tbs_cert_list.crl_extensions.as_mut().unwrap() {
        if extension.extn_id.to_string() == "2.5.29.20" {
            let number = CrlNumber::from_der(extension.extn_value.as_bytes())?;
            let old = number
                .0
                .as_bytes()
                .iter()
                .fold(0_u64, |n, b| n * 256 + u64::from(*b));
            extension.extn_value = OctetString::new(
                CrlNumber(x509_cert::der::asn1::Uint::new(&(old + 1).to_be_bytes())?).to_der()?,
            )?;
        }
    }
    let revoked = revoked
        .into_iter()
        .map(|serial| {
            Ok(RevokedCert {
                serial_number: SerialNumber::new(&serial)?,
                revocation_date: time(at)?,
                crl_entry_extensions: None,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    list.tbs_cert_list.revoked_certificates = (!revoked.is_empty()).then_some(revoked);
    let scratch = tempfile::tempdir()?;
    let input = scratch.path().join("publication-tbs.der");
    let output = scratch.path().join("signature.der");
    std::fs::write(&input, list.tbs_cert_list.to_der()?)?;
    let owner = if offline {
        root.parent().unwrap().join(format!(
            "{}-offline",
            root.file_name().unwrap().to_str().unwrap()
        ))
    } else {
        root.to_owned()
    };
    let key = if offline {
        owner.join("root_ca_key")
    } else {
        owner.join("step/secrets/intermediate_ca_key")
    };
    let password = owner.join(if offline {
        "root-password"
    } else {
        "step-password"
    });
    let status = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new("openssl")
            .arg("dgst")
            .arg("-sha256")
            .arg("-sign")
            .arg(key)
            .arg("-passin")
            .arg(format!("file:{}", password.display()))
            .arg("-out")
            .arg(&output)
            .arg(&input)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status(),
    )
    .await??;
    anyhow::ensure!(status.success(), "fixture CRL signing failed");
    list.signature = x509_cert::der::asn1::BitString::from_bytes(&std::fs::read(output)?)?;
    Ok(STANDARD.encode(list.to_der()?))
}

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki: actual offline root signature and durable CRL"]
async fn root_revocation_is_accepted_durably_and_denies_live_issuer_without_erasing_history()
-> anyhow::Result<()> {
    use rss_mdm_agent_wire::pki::Purpose;
    use rss_mdm_pki_service::{
        maintenance::{Publication, PublicationSet},
        registry::Registry,
    };
    let s = service(deployment()).await?;
    let p = admin(case_a(), "admin-a").await?;
    let g = grant()?;
    let r = authorize_request(&s, &p, &g, &audit()).await?;
    let candidate = s.issue(&signing(&g, r.grant_id)?, &audit()).await?;
    let bytes = chain(&candidate)?;
    let db = Database::connect(options("mdm_access")?).await?;
    let registry = Registry::new(
        db.archive_pool(),
        db.audit_store(&crate::config::AuditConfig::Plain).await?,
        vec![s.trust().trust.clone()],
        fixture_providers()?,
    );
    let trust = registry.trust(Purpose::Agent)?;
    let issuer = &trust.issuers[0];
    let certificate = x509_cert::Certificate::from_der(&STANDARD.decode(&issuer.certificate)?)?;
    let crl = publication_fixture(
        &root(),
        &issuer.root_crl,
        true,
        now(),
        Some(
            certificate
                .tbs_certificate
                .serial_number
                .as_bytes()
                .to_vec(),
        ),
    )
    .await?;
    registry
        .publish(
            &p,
            &PublicationSet {
                operation: Uuid::new_v4(),
                purpose: Purpose::Agent,
                publications: vec![Publication {
                    issuer: issuer.digest.clone(),
                    crl: issuer.crl.clone(),
                    root_crl: crl.clone(),
                }],
            },
            &audit(),
            now(),
        )
        .await?;
    assert_eq!(registry.trust(Purpose::Agent)?.issuers[0].root_crl, crl);
    assert!(matches!(
        s.trust().trust.active(),
        Err(rss_mdm_device_trust::Error::Revoked)
    ));
    assert!(matches!(
        s.trust().trust.verify(
            &bytes
                .iter()
                .cloned()
                .map(tokio_rustls::rustls::pki_types::CertificateDer::from)
                .collect::<Vec<_>>(),
            now()
        ),
        Err(rss_mdm_device_trust::Error::Revoked)
    ));
    s.trust().trust.verify_history(&bytes[0], &issuer.digest)?;
    let restart = service(deployment()).await?;
    assert_eq!(restart.trust().trust.public()?.issuers[0].root_crl, crl);
    assert!(matches!(
        restart.trust().trust.active(),
        Err(rss_mdm_device_trust::Error::Revoked)
    ));
    db.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki: multiple expired offline publications recover atomically"]
async fn multiple_expired_publications_require_one_atomic_set_and_replay_exactly()
-> anyhow::Result<()> {
    use rss_mdm_agent_wire::pki::{Mode, Purpose, Trust};
    use rss_mdm_pki_service::{
        maintenance::{Publication, PublicationSet},
        registry::{Registry, Rotation},
    };
    let s = service(deployment()).await?;
    let p = admin(case_a(), "admin-a").await?;
    let db = Database::connect(options("mdm_access")?).await?;
    let registry = Registry::new(
        db.archive_pool(),
        db.audit_store(&crate::config::AuditConfig::Plain).await?,
        vec![s.trust().trust.clone()],
        fixture_providers()?,
    );
    let next_root = PathBuf::from(std::env::var("MDM_AGENT_PKI_CANDIDATE_FIXTURES")?);
    let second: Trust =
        serde_json::from_slice(&std::fs::read(next_root.join("agent-trust.json"))?)?;
    let mut trust = registry.trust(Purpose::Agent)?;
    let expected = trust.revision;
    trust.revision += 1;
    let mut added = second.issuers[0].clone();
    added.mode = Mode::Prepared;
    trust.issuers.push(added);
    registry
        .prepare(
            &p,
            &Rotation {
                id: Uuid::new_v4(),
                purpose: Purpose::Agent,
                expected_revision: expected,
                candidate: trust.clone(),
            },
            &audit(),
            now(),
        )
        .await?;
    let later = now() + 31 * 86400;
    assert!(rss_mdm_device_trust::DeviceTrust::new(trust.clone(), Purpose::Agent, later).is_err());
    let mut publications = Vec::new();
    for (issuer, owner) in trust.issuers.iter().zip([root(), next_root]) {
        publications.push(Publication {
            issuer: issuer.digest.clone(),
            crl: publication_fixture(&owner, &issuer.crl, false, later, None).await?,
            root_crl: publication_fixture(&owner, &issuer.root_crl, true, later, None).await?,
        });
    }
    let durable_before = crate::test_support::pg(&format!(
        "SELECT encode(body,'hex') FROM mdm_pki.trust WHERE tenant_id='{}' AND purpose='agent'",
        case_a()
    ))?;
    let partial = PublicationSet {
        operation: Uuid::new_v4(),
        purpose: Purpose::Agent,
        publications: vec![Publication {
            issuer: publications[0].issuer.clone(),
            crl: publications[0].crl.clone(),
            root_crl: publications[0].root_crl.clone(),
        }],
    };
    assert!(matches!(
        registry.publish(&p, &partial, &audit(), later).await,
        Err(rss_mdm_pki_service::Error::Request)
    ));
    assert_eq!(registry.trust(Purpose::Agent)?, trust);
    assert_eq!(
        crate::test_support::pg(&format!(
            "SELECT encode(body,'hex') FROM mdm_pki.trust WHERE tenant_id='{}' AND purpose='agent'",
            case_a()
        ))?,
        durable_before
    );

    let mut input = PublicationSet {
        operation: Uuid::new_v4(),
        purpose: Purpose::Agent,
        publications,
    };
    registry.publish(&p, &input, &audit(), later).await?;
    let accepted = registry.trust(Purpose::Agent)?;
    rss_mdm_device_trust::DeviceTrust::new(accepted.clone(), Purpose::Agent, later)?;
    let durable: Trust = serde_json::from_str(&crate::test_support::pg(&format!(
        "SELECT convert_from(body,'UTF8') FROM mdm_pki.trust WHERE tenant_id='{}' AND purpose='agent'",
        case_a()
    ))?)?;
    assert_eq!(durable, accepted);
    let registry = Registry::new(
        db.archive_pool(),
        db.audit_store(&crate::config::AuditConfig::Plain).await?,
        vec![rss_mdm_device_trust::DeviceTrust::restore(
            durable,
            Purpose::Agent,
            later,
        )?],
        fixture_providers()?,
    );
    registry.synchronize(later).await?;
    input.publications.reverse();
    registry.publish(&p, &input, &audit(), later).await?;
    assert_eq!(registry.trust(Purpose::Agent)?, accepted);
    db.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki: real rejected CA dispatch retains unknown retirement fence"]
async fn unknown_original_ca_result_blocks_retirement_after_rotation() -> anyhow::Result<()> {
    use rss_mdm_agent_wire::pki::{Mode, Purpose, Trust};
    use rss_mdm_pki_service::registry::{Action, Registry, Rotation, Transition};
    let s = service_with_provider(deployment(), Some("unapproved-token-key")).await?;
    let p = admin(case_a(), "admin-a").await?;
    let g = grant()?;
    let receipt = authorize_request(&s, &p, &g, &audit()).await?;
    assert_eq!(
        s.issue(&signing(&g, receipt.grant_id)?, &audit())
            .await
            .err()
            .unwrap()
            .code,
        wire::ErrorCode::IssuanceUnknown
    );
    let db = Database::connect(options("mdm_access")?).await?;
    let registry = Registry::new(
        db.archive_pool(),
        db.audit_store(&crate::config::AuditConfig::Plain).await?,
        vec![s.trust().trust.clone()],
        fixture_providers()?,
    );
    let next_root = PathBuf::from(std::env::var("MDM_AGENT_PKI_CANDIDATE_FIXTURES")?);
    let second: Trust =
        serde_json::from_slice(&std::fs::read(next_root.join("agent-trust.json"))?)?;
    let mut trust = registry.trust(Purpose::Agent)?;
    let expected = trust.revision;
    trust.revision += 1;
    let mut added = second.issuers[0].clone();
    added.mode = Mode::Prepared;
    trust.issuers.push(added);
    let id = Uuid::new_v4();
    registry
        .prepare(
            &p,
            &Rotation {
                id,
                purpose: Purpose::Agent,
                expected_revision: expected,
                candidate: trust,
            },
            &audit(),
            now(),
        )
        .await?;
    for action in [Action::Approve, Action::Activate] {
        registry
            .transition(
                &p,
                Purpose::Agent,
                &Transition {
                    id,
                    expected_revision: registry.trust(Purpose::Agent)?.revision,
                    action,
                },
                &audit(),
                now(),
            )
            .await?;
    }
    let active = registry.trust(Purpose::Agent)?;
    assert_eq!(s.trust().trust.active()?.digest, second.issuers[0].digest);
    let durable_before = crate::test_support::pg(&format!(
        "SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(s) ORDER BY attempt) FROM mdm_pki.signing s WHERE tenant_id='{tenant}'),(SELECT to_jsonb(r) FROM mdm_pki.rotations r WHERE tenant_id='{tenant}' AND id='{id}'))::text",
        tenant = case_a()
    ))?;
    let facts: serde_json::Value = serde_json::from_str(&durable_before)?;
    assert_eq!(facts[0].as_array().unwrap().len(), 1);
    assert_eq!(facts[0][0]["state"], "unknown");
    assert_eq!(facts[1]["state"], "activated");
    assert_eq!(facts[0][0]["issuer"], facts[1]["previous"]);
    assert!(matches!(
        registry
            .transition(
                &p,
                Purpose::Agent,
                &Transition {
                    id,
                    expected_revision: registry.trust(Purpose::Agent)?.revision,
                    action: Action::Retire
                },
                &audit(),
                now()
            )
            .await,
        Err(rss_mdm_pki_service::Error::Conflict)
    ));
    assert_eq!(registry.trust(Purpose::Agent)?, active);
    assert_eq!(
        crate::test_support::pg(&format!(
            "SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(s) ORDER BY attempt) FROM mdm_pki.signing s WHERE tenant_id='{tenant}'),(SELECT to_jsonb(r) FROM mdm_pki.rotations r WHERE tenant_id='{tenant}' AND id='{id}'))::text",
            tenant = case_a()
        ))?,
        durable_before
    );
    db.close().await;
    Ok(())
}

pub(crate) async fn authorize_request(
    s: &Service,
    p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    g: &wire::GrantRequest,
    a: &RequestAudit,
) -> Result<wire::GrantReceipt, rss_mdm_registration_service::agent::Failure> {
    if p.tenant_id() != a.tenant() {
        return Err(rss_mdm_registration_service::Error::Forbidden.into());
    }
    let request = s.request(g, a).await?;
    s.authorize(p, request.grant_id, g.operation_id, a).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki"]
async fn management_crl_publication_accepts_large_signed_material_and_rejects_overflow()
-> anyhow::Result<()> {
    use crate::test_support::{Body, Browser, Method, Request, StatusCode};
    use rss_mdm_agent_wire::pki::Purpose;
    use tower::ServiceExt;
    let host = crate::windows::test_support::Host::open().await?;
    let trust = host.app.pki.trust(Purpose::Agent)?;
    let issuer = &trust.issuers[0];
    let raw = (1_u64..=80_000).map(|i| i.to_be_bytes().to_vec());
    let crl = publication_fixture(&root(), &issuer.crl, false, now(), raw).await?;
    let body = serde_json::json!({"operation":Uuid::new_v4(),"purpose":"agent","publications":[{"issuer":issuer.digest,"crl":crl,"root_crl":issuer.root_crl}]});
    anyhow::ensure!(serde_json::to_vec(&body)?.len() > 2 * 1024 * 1024);
    let secret = crate::test_support::identity::login(&host.app.identity, "admin").await?;
    let mut browser = Browser {
        cookies: std::collections::BTreeMap::from([(
            "__Host-identity-session".into(),
            secret.expose().into(),
        )]),
        csrf: Some(secret.csrf()),
        ..Default::default()
    };
    let (status, result) = browser
        .call(
            &host.browser,
            Method::POST,
            "/api/v1/pki/crls",
            Some(body.clone()),
        )
        .await?;
    anyhow::ensure!(
        status == StatusCode::NO_CONTENT,
        "large CRL: {status} {result}"
    );
    anyhow::ensure!(
        browser
            .call(&host.browser, Method::POST, "/api/v1/pki/crls", Some(body))
            .await?
            .0
            == StatusCode::NO_CONTENT
    );
    let mut connection =
        <sqlx::PgConnection as sqlx::Connection>::connect_with(&options("mdm_access")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_a())
        .execute(&mut connection)
        .await?;
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT der FROM mdm_pki.crls WHERE tenant_id=$1::uuid AND purpose='agent' AND issuer=$2",
    )
    .bind(case_a())
    .bind(&issuer.digest)
    .fetch_one(&mut connection)
    .await?;
    anyhow::ensure!(stored == STANDARD.decode(&crl)?);
    <sqlx::PgConnection as sqlx::Connection>::close(connection).await?;

    // Actual chunked HTTP body, bounded before JSON parsing or authorization; no giant fixture file.
    let chunks = futures::stream::iter(
        (0..65).map(|i| Ok::<_, std::io::Error>(vec![b' '; if i == 64 { 1 } else { 1024 * 1024 }])),
    );
    let response = host
        .browser
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/pki/crls")
                .header("host", "mdm.example.test")
                .header("content-type", "application/json")
                .body(Body::from_stream(chunks))?,
        )
        .await?;
    anyhow::ensure!(response.status() == StatusCode::PAYLOAD_TOO_LARGE);
    anyhow::ensure!(
        response.headers().contains_key("x-request-id")
            && response.headers()["cache-control"] == "no-store"
            && response.headers()["x-content-type-options"] == "nosniff"
    );
    let bytes = axum::body::to_bytes(response.into_body(), 1024).await?;
    anyhow::ensure!(
        serde_json::from_slice::<serde_json::Value>(&bytes)?["code"] == "request_too_large"
    );
    host.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki: bootstrap selection follows current registry issuer with retained overlap"]
async fn bootstrap_sources_select_current_issuer_and_reject_missing_application()
-> anyhow::Result<()> {
    use rss_mdm_agent_wire::pki::{Mode, Purpose, Trust};
    use rss_mdm_registration_service::agent::bootstrap::Deployment;
    let mut previous: Trust =
        serde_json::from_slice(&std::fs::read(root().join("agent-trust.json"))?)?;
    let candidate = PathBuf::from(std::env::var("MDM_AGENT_PKI_CANDIDATE_FIXTURES")?);
    let next: Trust = serde_json::from_slice(&std::fs::read(candidate.join("agent-trust.json"))?)?;
    previous.purpose = Purpose::AgentBootstrap;
    let mut added = next.issuers[0].clone();
    added.mode = Mode::Prepared;
    previous.issuers.push(added);
    for issuer in &mut previous.issuers {
        issuer.provisioner = "rss-agent-bootstrap".into();
        issuer.kid.clear();
    }
    let old = previous.issuers[0].digest.clone();
    let new = previous.issuers[1].digest.clone();
    let endpoints = std::collections::BTreeMap::from([
        (
            old.clone(),
            "https://old.example.test/scep/rss-agent-bootstrap".into(),
        ),
        (
            new.clone(),
            "https://new.example.test/scep/rss-agent-bootstrap".into(),
        ),
    ]);
    let frozen = Deployment::select(previous.clone(), &endpoints, now())?;
    assert_eq!(frozen.issuer, old);
    previous.issuers[0].mode = Mode::VerifyOnly;
    previous.issuers[1].mode = Mode::Active;
    previous.revision += 1;
    let current = Deployment::select(previous.clone(), &endpoints, now())?;
    assert_eq!(current.issuer, new);
    assert_ne!(frozen.root, current.root);
    let old_only = std::collections::BTreeMap::from([(old.clone(), endpoints[&old].clone())]);
    assert!(Deployment::select(previous, &old_only, now()).is_err());
    // A pre-existing operation retains its original issuer after the new selection.
    assert_eq!(frozen.issuer, old);
    Ok(())
}
