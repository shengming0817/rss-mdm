//! Pinned CA, durable grant/issuance state and real TLS possession.
mod maintenance;
use crate::device::test_support::{admin, case_a, case_b, options};
use crate::test_support::agent_tls::peer;
use crate::{
    Database,
    clock::{Clock, SystemClock},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::{enroll as wire, runtime};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_certificate::agent::{PROFILE, VerifiedAgentCsr};
use rss_mdm_registration_service::agent::{Assembly, NativeAdmission, Pending, Service};
use std::{path::PathBuf, sync::Arc, time::Duration};
use uuid::Uuid;
use x509_cert::der::Decode;
fn root() -> PathBuf {
    PathBuf::from(std::env::var("MDM_AGENT_PKI_FIXTURES").unwrap())
}
fn now() -> i64 {
    SystemClock.unix_seconds().unwrap()
}
fn deployment() -> serde_json::Value {
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
    fn validate<'a>(
        &'a self,
        _c: &'a mut sqlx::PgConnection,
        _source: &'a rss_mdm_registration_service::agent::native::Source,
    ) -> Pending<'a, ()> {
        Box::pin(async { Err(rss_mdm_registration_service::Error::Forbidden) })
    }
}
async fn service(value: serde_json::Value) -> anyhow::Result<Arc<Service>> {
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
        policy: pki.policy.clone(),
        binding: Arc::new(crate::agent::Bindings),
        native: Arc::new(NoNative),
    })?))
}
fn audit() -> RequestAudit {
    RequestAudit::new(case_a().into(), "agent_request")
}
fn grant() -> anyhow::Result<wire::GrantRequest> {
    Ok(wire::GrantRequest {
        wire_version: 1,
        operation_id: Uuid::new_v4(),
        secret: runtime::Secret::parse(&crate::enrollment::random())?,
        platform: runtime::TaskPlatform::Macos,
        lifetime_seconds: None,
        csr: Some(STANDARD.encode(std::fs::read(root().join("agent.der"))?)),
    })
}
fn signing(g: &wire::GrantRequest, id: Uuid) -> anyhow::Result<wire::CertificateRequest> {
    Ok(wire::CertificateRequest {
        wire_version: 1,
        operation_id: Uuid::new_v4(),
        grant_id: id,
        secret: g.secret.clone(),
        csr: g.csr.clone().unwrap(),
        runtime: serde_json::from_value(
            crate::test_support::json!({"capabilities":["inventory.collect.v1"],"platform":"macos","architecture":"aarch64","executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs)}),
        )?,
    })
}
fn chain(c: &wire::Candidate) -> anyhow::Result<Vec<Vec<u8>>> {
    Ok(c.certificate_chain
        .iter()
        .map(|v| STANDARD.decode(v))
        .collect::<Result<_, _>>()?)
}

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki"]
async fn restored_ca_signs_only_live_authorized_agent_csrs_and_tls_preserves_purpose()
-> anyhow::Result<()> {
    assert!(root().join("agent-backup-restored").exists());
    let s = service(deployment()).await?;
    let p = admin(case_a(), "admin-a").await?;
    let foreign = admin(case_b(), "admin-b").await?;
    for name in ["weak", "sha1", "ec", "subject", "san", "ca", "server"] {
        assert!(
            VerifiedAgentCsr::verify(&std::fs::read(root().join(format!("{name}.der")))?).is_err()
        )
    }
    let g = grant()?;
    assert!(s.create(&foreign, &g, &audit()).await.is_err());
    let receipt = s.create(&p, &g, &audit()).await?;
    let input = signing(&g, receipt.grant_id)?;
    let mut wrong = input.clone();
    wrong.secret = runtime::Secret::parse(&crate::enrollment::random())?;
    assert!(s.issue(&wrong, &audit()).await.is_err());
    let candidate = s.issue(&input, &audit()).await?;
    let replay = s.issue(&input, &audit()).await?;
    assert_eq!(
        serde_json::to_value(&candidate)?,
        serde_json::to_value(replay)?
    );
    let evidence = peer(s.trust(), &chain(&candidate)?, &root()).await?;
    let verified = s.trust().verify_peer(&evidence, now())?;
    assert_eq!(verified.metadata().profile, PROFILE);
    assert_eq!(
        verified.metadata().not_after - verified.metadata().not_before,
        365 * 86400
    );
    assert!(
        s.authenticate(&evidence).await.is_err(),
        "candidate entered runtime before activation"
    );
    let activate = wire::ActivationRequest {
        wire_version: 1,
        issuance_id: candidate.issuance_id,
        operation_id: Uuid::new_v4(),
    };
    let active = s.activate(&evidence, &activate, &audit()).await?;
    let retry = s.activate(&evidence, &activate, &audit()).await?;
    assert_eq!(serde_json::to_value(&active)?, serde_json::to_value(retry)?);
    assert_eq!(
        s.authenticate(&evidence).await?.registration(),
        active.runtime.registration_id
    );
    let db = Database::connect(options("mdm_access")?).await?;
    let devices = crate::device::DeviceService::new(
        db.registration(),
        case_a().into(),
        db.audit_store(&crate::config::AuditConfig::Plain).await?,
    );
    devices
        .revoke(
            &p,
            &active.runtime.device_id,
            active.runtime.registration_id,
            Uuid::new_v4(),
        )
        .await?;
    assert_eq!(
        s.authenticate(&evidence).await.err().unwrap().code,
        wire::ErrorCode::CredentialRevoked
    );
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
    let r = s.create(&p, &g, &audit()).await?;
    let c = s.issue(&signing(&g, r.grant_id)?, &audit()).await?;
    let evidence = peer(s.trust(), &chain(&c)?, &root()).await?;
    let metadata = s.trust().verify_peer(&evidence, now())?;
    assert_eq!(
        metadata.metadata().not_after - metadata.metadata().not_before,
        3650 * 86400
    );
    assert!(
        service(deployment())
            .await?
            .trust()
            .verify_peer(&evidence, now())
            .is_err()
    );
    value["lifetime"]["days"] = 3651.into();
    assert!(service(value).await.is_err());
    let value = deployment();
    let unknown = service_with_provider(value, Some("absent-agent-key")).await?;
    let g = grant()?;
    let r = unknown.create(&p, &g, &audit()).await?;
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
    let token = format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature));
    let client = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            root().join("step/certs/root_ca.crt"),
        )?)?)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
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
    assert!(!response.status().is_success());
    let response = client
        .post(&url)
        .json(&serde_json::json!({"csr":csr.pem()?,"ott":token}))
        .send()
        .await?;
    assert!(!response.status().is_success());
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
            get(|| async { axum::http::StatusCode::NO_CONTENT }),
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
    release.wait().await;
    for task in running {
        assert_eq!(task.await??.status(), 200);
    }
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

type AgentHttp = tokio::io::BufReader<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;
async fn connect_agent(
    address: std::net::SocketAddr,
    chain: Option<&[Vec<u8>]>,
) -> anyhow::Result<AgentHttp> {
    use tokio_rustls::{
        TlsConnector,
        rustls::{
            self,
            pki_types::{
                CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject,
            },
        },
    };
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&std::fs::read(root().join("ca.crt"))?) {
        roots.add(cert?)?;
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots);
    let config = match chain {
        Some(chain) => builder.with_client_auth_cert(
            chain.iter().cloned().map(CertificateDer::from).collect(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(
                root().join("agent.pk8"),
            )?)),
        )?,
        None => builder.with_no_client_auth(),
    };
    let stream = tokio::net::TcpStream::connect(address).await?;
    Ok(tokio::io::BufReader::new(
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost")?, stream)
            .await?,
    ))
}
async fn agent_http(
    io: &mut AgentHttp,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> anyhow::Result<(u16, serde_json::Value)> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    let body = body
        .map(|v| serde_json::to_vec(&v))
        .transpose()?
        .unwrap_or_default();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: mdm.example.test:9445\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    io.get_mut().write_all(head.as_bytes()).await?;
    io.get_mut().write_all(&body).await?;
    io.get_mut().flush().await?;
    let mut line = String::new();
    io.read_line(&mut line).await?;
    let status = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("missing HTTP status"))?
        .parse()?;
    let mut length = None;
    loop {
        line.clear();
        anyhow::ensure!(
            io.read_line(&mut line).await? != 0,
            "truncated HTTP headers"
        );
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = Some(value.trim().parse::<usize>()?);
        }
    }
    let mut bytes = vec![0; length.ok_or_else(|| anyhow::anyhow!("missing HTTP content-length"))?];
    io.read_exact(&mut bytes).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
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
        .approve(&p, receipt.grant_id, Uuid::new_v4(), &audit())
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
    let r = s.create(&p, &g, &audit()).await?;
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
    assert!(
        registry
            .transition(&p, Purpose::Agent, &approve, &audit(), now())
            .await
            .is_err()
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
    let grant_receipt = s.create(&p, &newer, &audit()).await?;
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
        registry
            .transition(&p, Purpose::Agent, &retire, &audit(), now())
            .await
            .is_err(),
        "live old certificate cannot retire"
    );
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
        registry
            .transition(&p, Purpose::Agent, &retire, &audit(), now())
            .await
            .is_err(),
        "revoke submission is not publication"
    );
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
    revoked: Option<Vec<u8>>,
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
    list.tbs_cert_list.revoked_certificates = revoked.map(|serial| {
        vec![RevokedCert {
            serial_number: SerialNumber::new(&serial).unwrap(),
            revocation_date: time(at).unwrap(),
            crl_entry_extensions: None,
        }]
    });
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
    let r = s.create(&p, &g, &audit()).await?;
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
    assert!(restart.trust().trust.active().is_err());
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
    let partial = PublicationSet {
        operation: Uuid::new_v4(),
        purpose: Purpose::Agent,
        publications: vec![Publication {
            issuer: publications[0].issuer.clone(),
            crl: publications[0].crl.clone(),
            root_crl: publications[0].root_crl.clone(),
        }],
    };
    assert!(
        registry
            .publish(&p, &partial, &audit(), later)
            .await
            .is_err()
    );
    assert_eq!(registry.trust(Purpose::Agent)?, trust);
    let mut input = PublicationSet {
        operation: Uuid::new_v4(),
        purpose: Purpose::Agent,
        publications,
    };
    registry.publish(&p, &input, &audit(), later).await?;
    let accepted = registry.trust(Purpose::Agent)?;
    rss_mdm_device_trust::DeviceTrust::new(accepted.clone(), Purpose::Agent, later)?;
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
    let receipt = s.create(&p, &g, &audit()).await?;
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
    assert!(
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
            .await
            .is_err()
    );
    db.close().await;
    Ok(())
}
