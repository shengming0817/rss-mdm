//! Pinned CA, durable grant/issuance state and real TLS possession.
use crate::device::test_support::{admin, case_a, case_b, options};
use crate::{
    Database,
    clock::{Clock, SystemClock},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::{enroll as wire, runtime};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_certificate::{
    HandshakePeer,
    agent::{AgentTrust, PROFILE, VerifiedAgentCsr},
};
use rss_mdm_registration_service::agent::{Assembly, NativeAdmission, Pending, Service};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        self,
        pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject,
        },
    },
};
use uuid::Uuid;
use x509_cert::der::{Decode, DecodePem, Encode};
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
pub(crate) async fn peer(
    trust: &AgentTrust,
    chain: &[Vec<u8>],
    root: &Path,
) -> anyhow::Result<HandshakePeer> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certificates = CertificateDer::pem_slice_iter(&std::fs::read(root.join("server.crt"))?)
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(
        root.join("apple-tls.pk8"),
    )?));
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(trust.verifier())
        .with_single_cert(certificates, key)?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(
        x509_cert::Certificate::from_pem(&std::fs::read(root.join("ca.crt"))?)?.to_der()?,
    ))?;
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_client_auth_cert(
            chain.iter().cloned().map(CertificateDer::from).collect(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(
                root.join("agent.pk8"),
            )?)),
        )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let accept = async {
        let (stream, _) = listener.accept().await?;
        let tls = TlsAcceptor::from(Arc::new(server)).accept(stream).await?;
        Ok::<_, anyhow::Error>(HandshakePeer::from_completed_tls(tls.get_ref().1)?)
    };
    let connect = async {
        let stream = tokio::net::TcpStream::connect(address).await?;
        Ok::<_, anyhow::Error>(
            TlsConnector::from(Arc::new(client))
                .connect(ServerName::try_from("localhost")?, stream)
                .await?,
        )
    };
    let (peer, client) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(accept, connect)
    })
    .await?;
    client?;
    peer
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
    let first = unknown.issue(&input, &audit()).await.unwrap_err();
    let retry = unknown.issue(&input, &audit()).await.unwrap_err();
    assert_eq!(first.code, wire::ErrorCode::IssuanceUnknown);
    assert_eq!(first.issuance_id, retry.issuance_id);
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
