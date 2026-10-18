use super::*;
use anyhow::{Result, ensure};
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
                let mut verifier =
                    openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &public)?;
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
                ensure!(claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap() == 60);
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
                    ensure!(path == "/admin/provisioners" && observed.lock().unwrap().is_none());
                    *observed.lock().unwrap() = Some(serde_json::from_slice(&bytes)?);
                    // CA committed, but its response was lost. Do not synthesize success.
                    break;
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
    actual.claims.ssh.enabled = true;
    assert!(actual.matches(&expected).is_err());
    actual.claims.ssh.enabled = false;
    actual.details.jwk.as_mut().unwrap().encrypted_private_key =
        Some("unexpected-online-private-key".to_owned().into());
    assert!(actual.matches(&expected).is_err());
}
