//! Real TLS, signed CRL and JWT with a clock advanced by independent provider responses.
use super::*;
use anyhow::ensure;
use rss_mdm_agent_wire::pki::Purpose;
use rss_mdm_pki_service::{
    Configuration, StepCa,
    providers::{Provider, Providers},
    registry::Registry,
};
use sqlx::Connection;
use std::sync::atomic::{AtomicI64, Ordering};

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki: slow publication and revoke queue with controlled clock"]
async fn sweep_uses_response_and_dispatch_times_without_changing_attempts() -> anyhow::Result<()> {
    let s = service(deployment()).await?;
    let p = admin(case_a(), "admin-a").await?;
    let mut serials = Vec::new();
    for _ in 0..2 {
        let g = grant()?;
        let r = authorize_request(&s, &p, &g, &audit()).await?;
        let candidate = s.issue(&signing(&g, r.grant_id)?, &audit()).await?;
        let certificate = x509_cert::Certificate::from_der(&chain(&candidate)?[0])?;
        serials.push((
            rss_mdm_device_trust::serial(certificate.tbs_certificate.serial_number.as_bytes()),
            Uuid::new_v4(),
        ));
    }
    let binding = s.trust().trust.clone();
    let trust = binding.public()?;
    let issuer = &trust.issuers[0];
    let start = now();
    let refreshed = start + 130;
    let publication = STANDARD
        .decode(publication_fixture(&root(), &issuer.crl, false, refreshed, None).await?)?;
    let clock = Arc::new(AtomicI64::new(start));
    let observed = Arc::new(std::sync::Mutex::new(Vec::<(String, String, i64)>::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("https://localhost:{}", listener.local_addr()?.port());
    let endpoint = crate::native::TlsEndpoint {
        listen: listener.local_addr()?,
        origin: origin.clone(),
        certificate_file: root().join("server.crt"),
        private_key_file: root().join("agent-tls.pk8"),
    };
    let mut tls = (*crate::native::tls::configuration(&endpoint, None)?).clone();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let stop = tokio_util::sync::CancellationToken::new();
    let stopped = stop.clone();
    let server_clock = clock.clone();
    let server_observed = observed.clone();
    let key = ring::signature::RsaKeyPair::from_pkcs8(&std::fs::read(
        root().join("agent-provisioner.pk8"),
    )?)
    .unwrap();
    use ring::signature::KeyPair;
    let public_key = key.public_key().as_ref().to_vec();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let tls = acceptor.accept(stream).await?;
        let mut h2 = h2::server::handshake(tls).await?;
        let mut handlers = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                () = stopped.cancelled() => break,
                request = h2.accept() => {
                    let Some(request) = request else { break; };
                    let (request, mut response) = request?;
                    let clock = server_clock.clone();
                    let observed = server_observed.clone();
                    let publication = publication.clone();
                    let public_key = public_key.clone();
                    handlers.spawn(async move {
                        let path = request.uri().path().to_owned();
                        let mut stream = request.into_body();
                        let mut bytes = Vec::new();
                        while let Some(chunk) = stream.data().await {
                            let chunk = chunk?;
                            stream.flow_control().release_capacity(chunk.len())?;
                            bytes.extend_from_slice(&chunk);
                        }
                        let body = if path == "/crl" {
                            // The signed list was generated after this sweep began.
                            clock.store(refreshed, Ordering::SeqCst);
                            publication
                        } else {
                            ensure!(path == "/revoke");
                            let body: serde_json::Value = serde_json::from_slice(&bytes)?;
                            let token = body["ott"].as_str().unwrap();
                            let parts = token.split('.').collect::<Vec<_>>();
                            ensure!(parts.len() == 3);
                            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                            ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, public_key)
                                .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &URL_SAFE_NO_PAD.decode(parts[2])?)
                                .map_err(|_| anyhow::anyhow!("revoke signature rejected"))?;
                            let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
                            let dispatch = clock.load(Ordering::SeqCst);
                            ensure!(claims["iat"] == dispatch && claims["nbf"] == dispatch && claims["exp"] == dispatch + 60,
                                "revoke JWT reused sweep/previous dispatch time");
                            ensure!(claims["sub"] == body["serial"] && body["passive"] == true);
                            observed.lock().unwrap().push((body["serial"].as_str().unwrap().into(), claims["jti"].as_str().unwrap().into(), dispatch));
                            // Advance beyond the next token's entire upstream leeway, without sleeping.
                            clock.fetch_add(130, Ordering::SeqCst);
                            b"{}".to_vec()
                        };
                        let mut send = response.send_response(axum::http::Response::builder().status(200).body(())?, false)?;
                        send.send_data(axum::body::Bytes::from(body), true)?;
                        anyhow::Ok(())
                    });
                }
            }
        }
        while let Some(result) = handlers.join_next().await {
            result??;
        }
        anyhow::Ok(())
    });
    let client = StepCa::new(
        Configuration {
            origin,
            provisioner: issuer.provisioner.clone(),
            kid: issuer.kid.clone(),
        },
        &std::fs::read(root().join("ca.crt"))?,
        &std::fs::read(root().join("agent-provisioner.pk8"))?,
    )?;
    let providers = Arc::new(Providers::new(vec![Provider {
        purpose: Purpose::Agent,
        issuer: issuer.digest.clone(),
        client: Arc::new(client),
        scep_url: None,
    }])?);
    let db = Database::connect(options("mdm_access")?).await?;
    let registry = Registry::new(
        db.archive_pool(),
        db.audit_store(&crate::config::AuditConfig::Plain).await?,
        vec![binding],
        providers,
    );
    let mut pg =
        <sqlx::PgConnection as sqlx::Connection>::connect_with(&options("postgres")?).await?;
    for (serial, attempt) in &serials {
        sqlx::query("INSERT INTO mdm_pki.revocations(tenant_id,purpose,issuer,serial,attempt,state) VALUES($1::uuid,'agent',$2,$3,$4,'pending')")
            .bind(case_a()).bind(&issuer.digest).bind(serial).bind(attempt).execute(&mut pg).await?;
    }
    let result = registry.sweep(|| Ok(clock.load(Ordering::SeqCst))).await;
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    result?;
    let observations = observed.lock().unwrap().clone();
    ensure!(observations.len() == 2);
    ensure!(observations[0].2 == refreshed && observations[1].2 == refreshed + 130);
    for (serial, attempt) in serials {
        ensure!(
            observations
                .iter()
                .any(|(s, jti, _)| s == &serial && jti == &attempt.to_string())
        );
        let state: (String, i32) = sqlx::query_as("SELECT state,failures FROM mdm_pki.revocations WHERE tenant_id=$1::uuid AND attempt=$2")
            .bind(case_a()).bind(attempt).fetch_one(&mut pg).await?;
        ensure!(
            state == ("submitted".into(), 1),
            "fresh request consumed retry budget: {state:?}"
        );
    }
    pg.close().await?;
    db.close().await;
    Ok(())
}
