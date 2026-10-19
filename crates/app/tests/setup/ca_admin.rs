use super::*;
use anyhow::{Result, ensure};
use serde_json::Value;
use std::sync::{Arc, Mutex};

#[tokio::test]
#[ignore = "MODULE=installation.ca_admin: pinned TLS admin JWT and lost create acknowledgement"]
async fn authenticated_readback_recovers_original_provider() -> Result<()> {
    use base64::Engine;
    let root = crate::windows::test_support::root()?;
    let config: crate::windows::WindowsConfig =
        serde_json::from_slice(&std::fs::read(root.join("windows.json"))?)?;
    let certificate =
        openssl::x509::X509::stack_from_pem(&std::fs::read(&config.management.certificate_file)?)?
            .remove(0);
    let subject = certificate
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .unwrap()
        .data()
        .to_string()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let origin = format!("https://localhost:{}", address.port());
    let mut tls = (*crate::native::tls::configuration(&config.management, None)?).clone();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let stored = Arc::new(Mutex::new(None::<serde_json::Value>));
    let observed = stored.clone();
    let stopped = tokio_util::sync::CancellationToken::new();
    let stop = stopped.clone();
    let server_origin = origin.clone();
    let server = tokio::spawn(async move {
        loop {
            let (tcp, _) =
                tokio::select! {()=stop.cancelled()=>break,accept=listener.accept()=>accept?};
            let tls = acceptor.accept(tcp).await?;
            let mut connection = h2::server::handshake(tls).await?;
            loop {
                let request = tokio::select! {()=stop.cancelled()=>return anyhow::Ok(()),request=connection.accept()=>request};
                let Some(request) = request else {
                    break;
                };
                let (request, mut response) = request?;
                let handle = async {
                    let token = request.headers().get("authorization").unwrap().to_str()?;
                    ensure!(!token.starts_with("Bearer "));
                    let parts = token.split('.').collect::<Vec<_>>();
                    ensure!(parts.len() == 3);
                    let header: serde_json::Value =
                        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
                    let claims: serde_json::Value =
                        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
                    let cert = openssl::x509::X509::from_der(
                        &STANDARD.decode(header["x5c"][0].as_str().unwrap())?,
                    )?;
                    let public = cert.public_key()?;
                    let mut verifier = openssl::sign::Verifier::new(
                        openssl::hash::MessageDigest::sha256(),
                        &public,
                    )?;
                    verifier.update(format!("{}.{}", parts[0], parts[1]).as_bytes())?;
                    let signature = URL_SAFE_NO_PAD.decode(parts[2])?;
                    let signature = if header["alg"] == "ES256" {
                        ensure!(signature.len() == 64);
                        openssl::ecdsa::EcdsaSig::from_private_components(
                            openssl::bn::BigNum::from_slice(&signature[..32])?,
                            openssl::bn::BigNum::from_slice(&signature[32..])?,
                        )?
                        .to_der()?
                    } else {
                        signature
                    };
                    ensure!(verifier.verify(&signature)?);
                    ensure!(
                        claims["iss"] == "step-admin-client/1.0"
                            && claims["aud"] == format!("{server_origin}{}", request.uri().path())
                    );
                    ensure!(
                        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap() == 60
                    );
                    let method = request.method().clone();
                    let path = request.uri().path().to_owned();
                    let mut stream = request.into_body();
                    let mut bytes = Vec::new();
                    while let Some(chunk) = stream.data().await {
                        let chunk = chunk?;
                        stream.flow_control().release_capacity(chunk.len())?;
                        bytes.extend_from_slice(&chunk);
                    }
                    if method == reqwest::Method::POST {
                        ensure!(
                            path == "/admin/provisioners" && observed.lock().unwrap().is_none()
                        );
                        *observed.lock().unwrap() = Some(serde_json::from_slice(&bytes)?);
                        // CA committed, but its response was lost. Do not synthesize success.
                        return anyhow::Ok(true);
                    }
                    ensure!(path == "/admin/provisioners/rss-agent");
                    let value = observed.lock().unwrap().clone();
                    let status = if value.is_some() { 200 } else { 404 };
                    let body =
                        serde_json::to_vec(&value.unwrap_or_else(|| json!({"type":"notFound"})))?;
                    let mut send = response.send_response(
                        axum::http::Response::builder().status(status).body(())?,
                        false,
                    )?;
                    send.send_data(axum::body::Bytes::from(body), true)?;
                    anyhow::Ok(false)
                };
                tokio::pin!(handle);
                tokio::select! {
                    () = stop.cancelled() => return anyhow::Ok(()),
                    result = &mut handle => if result? { break; },
                    _ = connection.accept() => anyhow::bail!("CA connection closed before request completed"),
                }
            }
        }
        anyhow::Ok(())
    });
    let profile = Profile {
        origin,
        address,
        tls_root_file: root.join("ca.crt"),
        administrator_subject: subject,
        administrator_certificate_file: config.management.certificate_file,
        administrator_key_file: config.management.private_key_file,
    };
    let client = client::Client::new(&profile, clock()?)?;
    let public = json!({"kty":"RSA","kid":"test","n":"AQ","e":"AQAB"});
    let expected = jwk_provisioner(Purpose::Agent, public)?;
    ensure!(
        ensure_provider(&client, &expected, Preparation::Create)
            .await
            .is_err()
    );
    let recovered = ensure_provider(&client, &expected, Preparation::Create).await?;
    recovered.matches(&expected)?;
    let different = jwk_provisioner(
        Purpose::Agent,
        json!({"kty":"RSA","kid":"different","n":"Ag","e":"AQAB"}),
    )?;
    ensure!(
        ensure_provider(&client, &different, Preparation::Create)
            .await
            .is_err()
    );
    stopped.cancel();
    server.await??;
    Ok(())
}

#[test]
fn imported_provider_compares_semantics_and_rejects_privilege_expansion() {
    let public = json!({"kty":"RSA","kid":"original","n":"AQ","e":"AQAB"});
    let expected = jwk_provisioner(Purpose::Agent, public.clone()).unwrap();
    let mut actual = jwk_provisioner(Purpose::Agent, public.clone()).unwrap();
    actual.id = "server-assigned".into();
    actual.details.jwk.as_mut().unwrap().public_key =
        STANDARD.encode(serde_json::to_string_pretty(&public).unwrap());
    assert!(actual.matches(&expected).is_ok());
    actual.deleted_at = Some("0001-01-01T00:00:00Z".into());
    assert!(actual.matches(&expected).is_ok());
    for deleted_at in ["2026-10-19T00:00:00Z", "invalid", ""] {
        actual.deleted_at = Some(deleted_at.into());
        assert!(actual.matches(&expected).is_err());
    }
    actual.deleted_at = None;
    actual.claims.ssh.enabled = true;
    assert!(actual.matches(&expected).is_err());
    actual.claims.ssh.enabled = false;
    actual.details.jwk.as_mut().unwrap().encrypted_private_key =
        Some("unexpected-online-private-key".to_owned().into());
    assert!(actual.matches(&expected).is_err());
}

#[tokio::test]
#[ignore = "MODULE=installation.ca: actual fixed step-ca JWK/SCEP creation, authenticated import and webhook readback"]
async fn actual_ca_creates_and_imports_exact_purpose_resources() -> Result<()> {
    use anyhow::Context as _;
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{
            X509, X509NameBuilder,
            extension::{BasicConstraints, KeyUsage},
        },
    };
    use std::os::unix::fs::PermissionsExt;
    let fixture = PathBuf::from(std::env::var("MDM_AGENT_PKI_FIXTURES")?);
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().canonicalize()?;
    let admin_certificate = directory.join("admin.pem");
    let admin_key = directory.join("admin.key");
    let origin = std::env::var("MDM_STEP_CA_URL")?;
    let root = PathBuf::from(std::env::var("MDM_STEP_CA_ROOT")?);
    let result = tokio::process::Command::new(std::env::var("MDM_STEP_CLI")?)
        .args(["ca", "certificate", "rss-admin"])
        .arg(&admin_certificate)
        .arg(&admin_key)
        .args(["--ca-url", &origin, "--root"])
        .arg(&root)
        .args(["--provisioner", "rss-admin", "--provisioner-password-file"])
        .arg(fixture.join("step-password"))
        .env("STEPPATH", fixture.join("step"))
        .kill_on_drop(true)
        .output()
        .await?;
    ensure!(
        result.status.success(),
        "fixed fixture administrator certificate issuance failed"
    );
    std::fs::set_permissions(&admin_key, std::fs::Permissions::from_mode(0o600))?;
    let url = url::Url::parse(&origin)?;
    let address =
        std::net::SocketAddr::from(([127, 0, 0, 1], url.port_or_known_default().unwrap()));
    let profile = Profile {
        origin: origin.clone(),
        address,
        tls_root_file: root.clone(),
        administrator_subject: "rss-admin".into(),
        administrator_certificate_file: admin_certificate,
        administrator_key_file: admin_key,
    };
    let client = client::Client::new(&profile, clock()?)?;
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let private = zeroize::Zeroizing::new(key.private_key_to_pkcs8()?);
    let (kid, public) = jwk(&private, None)?;
    let expected = jwk_provisioner(Purpose::Windows, public)?;
    ensure_provider(&client, &expected, Preparation::Create)
        .await
        .context("create/read back exact Windows JWK provisioner")?;
    ensure_provider(&client, &expected, Preparation::Import)
        .await
        .context("import exact Windows JWK provisioner")?;
    let provider = rss_mdm_pki_service::StepCa::at_address(
        rss_mdm_pki_service::Configuration {
            origin,
            provisioner: "rss-windows".into(),
            kid,
        },
        &std::fs::read(&root)?,
        &private,
        address,
    )?;
    provider
        .verify_provisioner()
        .await
        .context("public purpose JWK verification")?;
    let changed = jwk_provisioner(
        Purpose::Windows,
        json!({"kty":"RSA","kid":"changed","n":"AQ","e":"AQAB"}),
    )?;
    ensure!(
        ensure_provider(&client, &changed, Preparation::Create)
            .await
            .is_err()
    );

    let issuer_config: Value =
        serde_json::from_slice(&std::fs::read(fixture.join("leaf-issuer.json"))?)?;
    let issuer = X509::from_pem(&std::fs::read(
        issuer_config["certificate"].as_str().unwrap(),
    )?)?;
    let password = std::fs::read(issuer_config["password"].as_str().unwrap())?;
    let issuer_key = PKey::private_key_from_pem_passphrase(
        &std::fs::read(issuer_config["key"].as_str().unwrap())?,
        &password,
    )?;
    let decrypter = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "dedicated-scep-decrypter")?;
    let name = name.build();
    let mut certificate = X509::builder()?;
    certificate.set_version(2)?;
    let serial = openssl::bn::BigNum::from_u32(72823)?.to_asn1_integer()?;
    certificate.set_serial_number(&serial)?;
    certificate.set_subject_name(&name)?;
    certificate.set_issuer_name(issuer.subject_name())?;
    certificate.set_pubkey(&decrypter)?;
    let start = Asn1Time::days_from_now(0)?;
    let end = Asn1Time::days_from_now(1)?;
    certificate.set_not_before(&start)?;
    certificate.set_not_after(&end)?;
    certificate.append_extension(BasicConstraints::new().critical().build()?)?;
    certificate.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;
    certificate.sign(&issuer_key, MessageDigest::sha256())?;
    let certificate_file = directory.join("decrypter.pem");
    let private_key_file = directory.join("decrypter.key");
    std::fs::write(&certificate_file, certificate.build().to_pem()?)?;
    std::fs::write(&private_key_file, decrypter.private_key_to_pem_pkcs8()?)?;
    std::fs::set_permissions(&private_key_file, std::fs::Permissions::from_mode(0o600))?;
    let journal = Journal::open(&directory.join("operation"))?;
    let source = ScepInput {
        certificate_file,
        private_key_file,
    };
    let crl = provider
        .published_crl()
        .await
        .context("read fixture issuer CRL")?;
    let expected = scep_provisioner(
        Purpose::Apple,
        &source,
        &journal,
        "rss",
        &issuer.to_der()?,
        &crl,
    )?;
    prepare_scep(
        Purpose::Apple,
        "https://mdm.example.test:1",
        Preparation::Create,
        &journal,
        &client,
        &expected,
    )
    .await?;
    let original: Value = journal.load("challenge-runtime.json")?.unwrap();
    prepare_scep(
        Purpose::Apple,
        "https://mdm.example.test:1",
        Preparation::Import,
        &journal,
        &client,
        &expected,
    )
    .await?;
    ensure!(journal.load::<Value>("challenge-runtime.json")?.unwrap() == original);
    ensure!(
        prepare_scep(
            Purpose::Apple,
            "https://other.example.test:1",
            Preparation::Import,
            &journal,
            &client,
            &expected
        )
        .await
        .is_err()
    );
    Ok(())
}
