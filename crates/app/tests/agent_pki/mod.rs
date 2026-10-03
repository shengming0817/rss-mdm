//! Pinned CA, durable grant/issuance state and real TLS possession.
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
    PathBuf::from(std::env::var("MDM_APPLE_FIXTURES").unwrap())
}
fn now() -> i64 {
    SystemClock.unix_seconds().unwrap()
}
fn deployment() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(root().join("agent-pki.json")).unwrap()).unwrap()
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
    let db = Database::connect(options("mdm_access")?).await?;
    let audit = db.audit_store(&crate::config::AuditConfig::Plain).await?;
    let config: crate::agent_pki::Config = serde_json::from_value(value)?;
    let pki = config.load(audit.clone(), Arc::new(SystemClock))?.unwrap();
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
            crate::test_support::json!({"capabilities":["inventory.collect.v6"],"platform":"macos","architecture":"aarch64","executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs)}),
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
    let mut value = deployment();
    value["kid"] = "absent-agent-key".into();
    let unknown = service(value).await?;
    let g = grant()?;
    let r = unknown.create(&p, &g, &audit()).await?;
    let input = signing(&g, r.grant_id)?;
    use axum::{Router, body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let router = Router::new().nest(
        "/api/agent/enroll/v1",
        rss_mdm_agent_channel::enroll::router(unknown.clone(), envelope("mdm.example.test").await?),
    );
    let mut failures = Vec::new();
    let mut owner =
        <sqlx::PgConnection as sqlx::Connection>::connect_with(&options("postgres")?).await?;
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/agent/enroll/v1/certificates")
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
        wire::ErrorCode::PermissionDenied,
        "a new provisioner cannot replace the original unknown issuer"
    );
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
    let value = deployment();
    let url = format!("{}/sign", value["ca_url"].as_str().unwrap());
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
        "/api/agent/enroll/v1/requests",
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
        "/api/agent/enroll/v1/certificates",
        Some(serde_json::to_value(signing(&g, receipt.grant_id)?)?),
    )
    .await?;
    assert_eq!(status, 200, "anonymous signing: {body}");
    let candidate: wire::Candidate = serde_json::from_value(body)?;
    let path = format!("/api/agent/runtime/v1/reports/{}", Uuid::new_v4());
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
        "/api/agent/enroll/v1/activate",
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
