use super::*;
use anyhow::{Context, Result, ensure};
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
    let mut tls = crate::native::tls::configuration(&config.management, None)?.fixture_server();
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
    // Fresh deployment generates its SCEP encryption identity through the real CA, without its issuer key.
    let shared = Journal::open(&directory.join("shared-ca"))?;
    let encryption = initialize::encryption_identity(&shared, &client, &profile).await?;
    let replay = initialize::encryption_identity(&shared, &client, &profile).await?;
    ensure!(encryption.0 == replay.0 && encryption.1.as_slice() == replay.1.as_slice());
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
        public_url: "https://mdm.example.test/scep/rss".into(),
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
        None,
    )
    .await?;
    let original: Value = journal.load("challenge-runtime.json")?.unwrap();
    // Renew only the encryption identity; the authenticated CA must retain the original webhook identity.
    let replacement = ScepInput {
        public_url: source.public_url.clone(),
        certificate_file: journal.secret("replacement.pem", &encryption.0)?,
        private_key_file: journal.secret("replacement.key", &encryption.1)?,
    };
    let updated = scep_provisioner(
        Purpose::Apple,
        &replacement,
        &Journal::open(&directory.join("renewal"))?,
        "rss",
        &issuer.to_der()?,
        &crl,
    )?;
    let remote: wire::Provisioner = client.get("rss", clock()?).await?.unwrap();
    let mut replacement = remote;
    replacement.details.scep = updated.details.scep.clone();
    client.update("rss", &replacement, clock()?).await?;
    let expected = updated;
    prepare_scep(
        Purpose::Apple,
        "https://mdm.example.test:1",
        Preparation::Import,
        &journal,
        &client,
        &expected,
        None,
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
            &expected,
            None,
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=installation.ca: shared CA setup, stable replay and independent tenant resources"]
async fn unified_ca_initialization_replays_and_isolates_tenants() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use x509_cert::der::{Decode, Encode};
    let fixture = PathBuf::from(std::env::var("MDM_WINDOWS_PKI_FIXTURES")?);
    let temp = tempfile::tempdir()?;
    let directory = temp.path().canonicalize()?;
    let admin = directory.join("admin.pem");
    let key = directory.join("admin.key");
    let origin = std::env::var("MDM_STEP_CA_URL")?;
    let root_cert = PathBuf::from(std::env::var("MDM_STEP_CA_ROOT")?);
    let issued = tokio::process::Command::new(std::env::var("MDM_STEP_CLI")?)
        .args(["ca", "certificate", "rss-admin"])
        .arg(&admin)
        .arg(&key)
        .args(["--ca-url", &origin, "--root"])
        .arg(&root_cert)
        .args(["--provisioner", "rss-admin", "--provisioner-password-file"])
        .arg(fixture.join("step-password"))
        .env("STEPPATH", fixture.join("step"))
        .kill_on_drop(true)
        .output()
        .await?;
    ensure!(issued.status.success());
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    let settings = initialize::Settings {
        origin,
        root_certificate_file: root_cert,
        root_crl_file: fixture.join("root.crl.der"),
        administrator_certificate_file: admin,
        administrator_key_file: key,
        public_scep_origin: None,
    };
    let url = url::Url::parse(&settings.origin)?;
    let profile = Profile {
        origin: settings.origin.clone(),
        address: ([127, 0, 0, 1], url.port_or_known_default().unwrap()).into(),
        tls_root_file: settings.root_certificate_file.clone(),
        administrator_subject: "rss-admin".into(),
        administrator_certificate_file: settings.administrator_certificate_file.clone(),
        administrator_key_file: settings.administrator_key_file.clone(),
    };
    let ca = client::Client::new(&profile, clock()?)?;
    let options = std::env::var("MDM_OWNER_URL")?
        .parse::<sqlx::postgres::PgConnectOptions>()?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut connection = PgConnection::connect_with(&options).await?;
    let root = Journal::open(&directory.join("installation"))?;
    root.save(
        "installation.json",
        &json!({"receipt":{"tenantId":Uuid::new_v4()}}),
    )?;
    let mut first_names = Vec::new();
    for index in 0..2 {
        let tenant = Uuid::new_v4();
        let journal = Journal::open(&directory.join(format!("operation-{index}")))?;
        let agent_origin = format!("https://agent-{index}.example.test");
        let windows_origin = format!("https://windows-{index}.example.test");
        let agent: crate::agent_pki::Config = serde_json::from_value(json!({"mode":"step_ca",
            "endpoint":{"origin":agent_origin,"listen":"127.0.0.1:9445","certificate_file":"/unused.crt","private_key_file":"/unused.pk8"},
            "bootstrap":{}}))?;
        let mut runtime = json!({"product_origin":format!("https://tenant-{index}.example.test"),
            "identity":{"tenant_id":tenant},"runtime_binding":{"host_id":Uuid::new_v4()},
            "device_pki":[],"native_protocols":{
                "windows":{"trust_file":"","management":{"origin":windows_origin}},
                "apple":{"trust_file":"","webhooks":[],"management":{"origin":format!("https://apple-{index}.example.test")}}
            },"agent_pki":agent});
        initialize::prepare(&root, &journal, &mut connection, &mut runtime, &settings)
            .await
            .context("initial CA preparation")?;
        let scep_name = format!("rss-{}", tenant.simple());
        let renewal = if index == 0 {
            Some(
                near_expiry_scep(&ca, &profile, &journal, &scep_name)
                    .await
                    .context("short-lived seed")?,
            )
        } else {
            None
        };
        // Reapplying the same explicit intent renews only eligible materials.
        let late = Journal::open(&directory.join(format!("late-{index}")))?;
        initialize::attach(&root, &late, &mut connection, &mut runtime)
            .await
            .context("late Agent attachment")?;
        if let Some((old, digest)) = renewal {
            let remote: wire::Provisioner = ca.get(&scep_name, clock()?).await?.unwrap();
            let cert = openssl::x509::X509::from_pem(
                &STANDARD.decode(&remote.details.scep.as_ref().unwrap().decrypter.certificate)?,
            )?;
            ensure!(rss_mdm_device_trust::digest(&cert.to_der()?) != old);
            ensure!(
                cert.not_after()
                    > openssl::asn1::Asn1Time::from_unix(clock()? + 30 * 86400)?.as_ref()
            );
            ensure!(webhook_digest(&remote) == digest);
        }
        let remote: wire::Provisioner = ca
            .get(
                &format!("rss-agent-bootstrap-{}", tenant.simple()),
                clock()?,
            )
            .await?
            .unwrap();
        ensure!(
            remote
                .webhooks
                .iter()
                .all(|h| h.url.starts_with(&format!("{agent_origin}/")))
        );
        let original = runtime.clone();
        if index == 0 {
            // Persisted trust retains signed history while current CRLs are published separately.
            let mut previous: Trust = serde_json::from_slice(&std::fs::read(
                runtime["agent_pki"]["trust_file"].as_str().unwrap(),
            )?)?;
            let mut stale = x509_cert::crl::CertificateList::from_der(
                &STANDARD.decode(&previous.issuers[0].crl)?,
            )?;
            let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(clock()? as u64);
            stale.tbs_cert_list.this_update =
                (now - std::time::Duration::from_secs(120)).try_into()?;
            stale.tbs_cert_list.next_update =
                Some((now - std::time::Duration::from_secs(60)).try_into()?);
            let source: Value =
                serde_json::from_slice(&std::fs::read(fixture.join("leaf-issuer.json"))?)?;
            let key = openssl::pkey::PKey::private_key_from_pem_passphrase(
                &std::fs::read(source["key"].as_str().unwrap())?,
                &std::fs::read(source["password"].as_str().unwrap())?,
            )?;
            let mut signer =
                openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key)?;
            signer.update(&stale.tbs_cert_list.to_der()?)?;
            stale.signature = x509_cert::der::asn1::BitString::from_bytes(&signer.sign_to_vec()?)?;
            previous.issuers[0].crl = STANDARD.encode(stale.to_der()?);
            let mut tx = connection.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(tenant.to_string())
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO mdm_pki.trust(tenant_id,purpose,revision,body) VALUES($1,'agent',$2,$3)").bind(tenant).bind(previous.revision as i64).bind(serde_json::to_vec(&previous)?).execute(&mut *tx).await?;
            tx.commit().await?;
        }
        initialize::attach(&root, &late, &mut connection, &mut runtime)
            .await
            .context("late Agent attachment")?;
        ensure!(runtime == original);
        let bootstrap = &runtime["agent_pki"]["bootstrap"];
        ensure!(bootstrap["webhooks"].as_array().unwrap().len() == 1);
        let trust: Trust =
            serde_json::from_slice(&std::fs::read(bootstrap["trust_file"].as_str().unwrap())?)?;
        ensure!(trust.origin == agent_origin);

        ensure!(runtime["device_pki"].as_array().unwrap().len() == 4);
        let names = runtime["device_pki"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["provisioner"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        if index == 0 {
            first_names = names;
        } else {
            ensure!(
                names
                    .iter()
                    .filter(|n| first_names.contains(n))
                    .collect::<Vec<_>>()
                    == vec![&"rss-agent".to_owned()]
            );
        }
        // Windows retains its explicit management hostname across material preparation.
        let windows = Journal::open(&directory.join(format!("windows-{index}")))?;
        initialize::attach(&root, &windows, &mut connection, &mut runtime)
            .await
            .context("late Windows attachment")?;
        let trust: Trust = serde_json::from_slice(&std::fs::read(
            runtime["native_protocols"]["windows"]["trust_file"]
                .as_str()
                .unwrap(),
        )?)?;
        ensure!(trust.origin == windows_origin);
    }
    connection.close().await?;
    Ok(())
}

fn webhook_digest(provider: &wire::Provisioner) -> Vec<u8> {
    use sha2::Digest;
    let mut hooks = provider.webhooks.clone();
    hooks.sort_by(|a, b| a.name.cmp(&b.name));
    sha2::Sha256::digest(serde_json::to_vec(&hooks).unwrap()).to_vec()
}
/// Seed one short-lived identity through the real CA; only production initialization may renew it.
async fn near_expiry_scep(
    client: &client::Client,
    profile: &Profile,
    journal: &Journal,
    name: &str,
) -> Result<(String, Vec<u8>)> {
    use openssl::{
        hash::MessageDigest,
        pkey::PKey,
        x509::{X509NameBuilder, X509Req},
    };
    use sha2::Digest;
    let mut remote: wire::Provisioner = client.get(name, clock()?).await?.unwrap();
    let digest = webhook_digest(&remote);
    let private = STANDARD.decode(
        remote
            .details
            .scep
            .as_ref()
            .unwrap()
            .decrypter
            .key
            .as_bytes(),
    )?;
    let key = PKey::private_key_from_pem(&private)?;
    let mut subject = X509NameBuilder::new()?;
    subject.append_entry_by_text("CN", "rss-scep-encryption")?;
    let mut request = X509Req::builder()?;
    request.set_subject_name(&subject.build())?;
    request.set_pubkey(&key)?;
    request.sign(&key, MessageDigest::sha256())?;
    let request = request.build();
    let csr = request.to_der()?;
    let pem = String::from_utf8(request.to_pem()?)?;
    let helper = Journal::open(&journal.path("scep-encryption")?)?;
    let expected: wire::Provisioner = helper.load("expected-jwk.json")?.unwrap();
    let signing = std::fs::read(helper.path("provisioner.pk8")?)?;
    let (kid, _) = jwk(&signing, None)?;
    let provider = rss_mdm_pki_service::StepCa::at_address(
        rss_mdm_pki_service::Configuration {
            origin: profile.origin.clone(),
            provisioner: expected.name,
            kid,
        },
        &std::fs::read(&profile.tls_root_file)?,
        &signing,
        profile.address,
    )?;
    let now = clock()?;
    let chain = provider
        .sign(
            rss_mdm_pki_service::Sign {
                attempt: Uuid::new_v4(),
                csr_pem: &pem,
                csr_digest: &sha2::Sha256::digest(&csr).into(),
                subject: "rss-scep-encryption",
                sans: &[],
                start: now,
                end: now + 86400,
                deadline: now + 60,
            },
            now,
        )
        .await?;
    let cert = openssl::x509::X509::from_der(&chain[0])?;
    remote.details.scep.as_mut().unwrap().decrypter.certificate = STANDARD.encode(cert.to_pem()?);
    client.update(name, &remote, clock()?).await?;
    Ok((rss_mdm_device_trust::digest(&cert.to_der()?), digest))
}
