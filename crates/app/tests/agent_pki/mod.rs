//! Real pinned step-ca, PG authorization/audit and completed TLS evidence.
use crate::device::test_support::{admin, case_a, case_b, options};
use crate::{
    Database,
    clock::{Clock, SystemClock},
};
use rss_mdm_audit_integration::{AuditStore, RequestAudit};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_certificate::{
    HandshakePeer,
    agent::{AgentTrust, PROFILE, VerifiedAgentCsr},
};
use rss_mdm_inventory::ReportSource;
use rss_mdm_registration_service::{
    agent_pki::{AgentIssuer, IssuanceError},
    enrollment::Password,
};
use sqlx::Connection;
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
fn configured_issuer(
    value: serde_json::Value,
    audit: Arc<AuditStore>,
) -> anyhow::Result<Arc<AgentIssuer>> {
    let config: crate::agent_pki::Config = serde_json::from_value(value)?;
    Ok(config
        .load(audit, Arc::new(SystemClock))?
        .unwrap()
        .issuer
        .clone())
}
fn audit(proof: &AuthorizedPrincipal, device: &str) -> RequestAudit {
    crate::enrollment::test_support::audit(proof, Uuid::new_v4(), device, "agent_certificate_issue")
}
async fn create(
    store: &AuditStore,
    proof: &AuthorizedPrincipal,
    device: &str,
    password: &Password,
    source: ReportSource,
) -> anyhow::Result<Uuid> {
    let a = audit(proof, device);
    let key = Uuid::new_v4();
    a.operation(key, "enrollment_create");
    let receipt = rss_mdm_registration_service::enrollment::store::create_enrollment(
        store,
        proof.enrollment(device)?,
        password,
        source,
        (source == ReportSource::MdmWindows)
            .then_some(rss_mdm_registration_service::enrollment::WindowsProfile::Device),
        Uuid::new_v4(),
        key,
        &a,
    )
    .await?;
    a.finalize(None);
    Ok(receipt.enrollment_id)
}
async fn peer(trust: &AgentTrust, chain: &[Vec<u8>], root: &Path) -> anyhow::Result<HandshakePeer> {
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
    let db = Database::connect(options("mdm_access")?).await?;
    let store = db.audit_store(&crate::config::AuditConfig::Plain).await?;
    let proof = admin(case_a(), "admin-a").await?;
    let foreign = admin(case_b(), "admin-b").await?;
    let issuer = configured_issuer(deployment(), store.clone())?;
    let password = Password::new(crate::enrollment::random())?;
    let device = format!("agent-pki-{}", Uuid::new_v4());
    let id = create(
        &store,
        &proof,
        &device,
        &password,
        ReportSource::AgentBuiltin,
    )
    .await?;
    let csr = std::fs::read(root().join("agent.der"))?;
    for name in ["weak", "sha1", "ec", "subject", "san", "ca", "server"] {
        assert!(
            VerifiedAgentCsr::verify(&std::fs::read(root().join(format!("{name}.der")))?).is_err(),
            "{name}"
        );
    }
    let mut tampered = csr.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(VerifiedAgentCsr::verify(&tampered).is_err());
    let wrong = Password::new(crate::enrollment::random())?;
    assert!(matches!(
        issuer
            .authorize(&proof, id, &wrong, &csr, &audit(&proof, &device))
            .await,
        Err(IssuanceError::Authorization(_))
    ));
    assert!(
        issuer
            .authorize(&foreign, id, &password, &csr, &audit(&foreign, &device))
            .await
            .is_err()
    );
    let native_id = create(
        &store,
        &proof,
        &format!("windows-{}", Uuid::new_v4()),
        &password,
        ReportSource::MdmWindows,
    )
    .await?;
    assert!(
        issuer
            .authorize(&proof, native_id, &password, &csr, &audit(&proof, &device))
            .await
            .is_err()
    );
    let a = audit(&proof, &device);
    let intent = issuer.authorize(&proof, id, &password, &csr, &a).await?;
    let attempt = intent.attempt();
    let signed = issuer.issue(intent, &a).await?;
    assert_eq!(signed.attempt, attempt);
    assert_eq!(signed.request, id);
    let c = &signed.certificate;
    let m = &c.metadata;
    assert_eq!(m.profile, PROFILE);
    assert_eq!(m.provisioner, "rss-agent");
    assert_eq!(
        m.identity,
        rss_mdm_certificate::agent::identity(Uuid::parse_str(case_a())?, &device)?
    );
    assert_eq!(m.not_after - m.not_before, 365 * 86400);
    assert_eq!(c.csr_digest, VerifiedAgentCsr::verify(&csr)?.digest());
    let evidence = peer(issuer.trust(), &c.chain, &root()).await?;
    assert_eq!(
        issuer
            .trust()
            .verify_peer(&evidence, now())?
            .metadata()
            .fingerprint,
        m.fingerprint
    );
    assert!(
        issuer
            .trust()
            .verify_peer(&evidence, m.not_before - 1)
            .is_err()
    );
    assert!(issuer.trust().verify_peer(&evidence, m.not_after).is_err());
    assert!(
        issuer
            .trust()
            .verify_peer(&evidence, issuer.trust().expires())
            .is_err()
    );
    // Copy the legitimate profile/marker but sign with a same-DN subordinate.
    // WebPKI's CA path remains valid; Agent's direct signer policy must reject.
    let mut delegated = x509_cert::Certificate::from_der(&c.chain[0])?;
    let algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
        oid: x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
        parameters: Some(x509_cert::der::asn1::Any::null()),
    };
    delegated.tbs_certificate.signature = algorithm.clone();
    delegated.signature_algorithm = algorithm;
    let subordinate = ring::signature::RsaKeyPair::from_pkcs8(&std::fs::read(
        root().join("agent-subordinate.pk8"),
    )?)
    .unwrap();
    let mut signature = vec![0; subordinate.public().modulus_len()];
    subordinate
        .sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &ring::rand::SystemRandom::new(),
            &delegated.tbs_certificate.to_der()?,
            &mut signature,
        )
        .unwrap();
    delegated.signature = x509_cert::der::asn1::BitString::from_bytes(&signature)?;
    let delegated_chain = vec![
        delegated.to_der()?,
        x509_cert::Certificate::from_pem(&std::fs::read(root().join("agent-subordinate.crt"))?)?
            .to_der()?,
    ];
    let delegated_peer = peer(issuer.trust(), &delegated_chain, &root()).await?;
    assert!(issuer.trust().verify_peer(&delegated_peer, now()).is_err());
    let apple = rss_mdm_certificate::apple::AppleDeviceTrust::from_bytes(
        &std::fs::read(root().join("step/certs/intermediate_ca.crt"))?,
        now(),
    )?;
    let chain = c
        .chain
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    assert!(apple.verify(&chain, now()).is_err());
    let mut wrong_deployment = deployment();
    wrong_deployment["kid"] = "different-provisioner".into();
    let other = configured_issuer(wrong_deployment, store.clone())?;
    assert!(other.trust().verify_peer(&evidence, now()).is_err());
    // Signing is not enrollment binding or a device credential.
    let mut conn = sqlx::PgConnection::connect_with(&options("postgres")?).await?;
    let state: String = sqlx::query_scalar("SELECT state FROM mdm_access.requests WHERE id=$1")
        .bind(id)
        .fetch_one(&mut conn)
        .await?;
    assert_eq!(state, "pending");
    let rows = crate::audit_test_support::read(&mut conn).await?;
    let authorized = rows
        .iter()
        .position(|r| {
            r.result() == "success"
                && r.payload["details"]["phase"] == "authorized"
                && r.payload["details"]["attempt"] == attempt.to_string()
        })
        .expect("authorization fact");
    let result = rows
        .iter()
        .position(|r| {
            r.result() == "success"
                && r.payload["details"]["phase"] == "signed"
                && r.payload["details"]["certificate"]["identity"] == m.identity
        })
        .expect("signed fact");
    assert!(authorized < result);
    assert!(!format!("{:?}", rows[result].payload).contains("ott"));
    a.finalize(None);
    db.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki"]
async fn explicit_development_limit_and_unknown_result_remain_auditable() -> anyhow::Result<()> {
    let db = Database::connect(options("mdm_access")?).await?;
    let store = db.audit_store(&crate::config::AuditConfig::Plain).await?;
    let proof = admin(case_a(), "admin-a").await?;
    let password = Password::new(crate::enrollment::random())?;
    let csr = std::fs::read(root().join("agent.der"))?;
    let mut value = deployment();
    value["lifetime"] = serde_json::json!({"mode":"development","days":3650});
    let dev = configured_issuer(value.clone(), store.clone())?;
    let device = format!("dev-pki-{}", Uuid::new_v4());
    let id = create(
        &store,
        &proof,
        &device,
        &password,
        ReportSource::AgentBuiltin,
    )
    .await?;
    let a = audit(&proof, &device);
    let intent = dev.authorize(&proof, id, &password, &csr, &a).await?;
    let c = dev.issue(intent, &a).await?.certificate;
    assert_eq!(c.metadata.not_after - c.metadata.not_before, 3650 * 86400);
    let evidence = peer(dev.trust(), &c.chain, &root()).await?;
    assert!(dev.trust().verify_peer(&evidence, now()).is_ok());
    let standard = configured_issuer(deployment(), store.clone())?;
    assert!(standard.trust().verify_peer(&evidence, now()).is_err());
    assert!(
        !dev.trust()
            .permits_window(dev.trust().expires() - 86400, dev.trust().expires() + 86400)
    );
    value["lifetime"]["days"] = 3651.into();
    assert!(configured_issuer(value, store.clone()).is_err());
    // A valid local configuration whose key ID is absent remotely cannot return
    // a candidate or trigger an automatic second request.
    let mut value = deployment();
    value["kid"] = "absent-agent-key".into();
    let unknown = configured_issuer(value, store.clone())?;
    let device = format!("unknown-pki-{}", Uuid::new_v4());
    let id = create(
        &store,
        &proof,
        &device,
        &password,
        ReportSource::AgentBuiltin,
    )
    .await?;
    let a = audit(&proof, &device);
    let intent = unknown.authorize(&proof, id, &password, &csr, &a).await?;
    let attempt = intent.attempt();
    assert!(
        matches!(unknown.issue(intent,&a).await,Err(IssuanceError::Unknown {attempt: id}) if id==attempt)
    );
    let mut conn = sqlx::PgConnection::connect_with(&options("postgres")?).await?;
    let rows = crate::audit_test_support::read(&mut conn).await?;
    assert!(rows.iter().any(|r| r.result() == "unknown"
        && r.payload["details"]["phase"] == "issuance_unknown"
        && r.payload["details"]["attempt"] == attempt.to_string()));
    // The same protected loader used in assembly rejects public key-file access.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key = root().join("agent-provisioner.pk8");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644))?;
        assert!(configured_issuer(deployment(), store.clone()).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    }
    a.finalize(None);
    db.close().await;
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
