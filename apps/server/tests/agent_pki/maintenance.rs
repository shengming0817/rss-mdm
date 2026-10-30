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
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki: slow publication and revoke queue with controlled clock"]
async fn sweep_uses_response_and_dispatch_times_without_changing_attempts() -> anyhow::Result<()> {
    let config: crate::agent_pki::Config = serde_json::from_value(deployment())?;
    let crate::agent_pki::Config::StepCa { trust_file, .. } = config else {
        anyhow::bail!("Agent trust fixture is disabled");
    };
    let binding = crate::device_pki::load(&trust_file, Purpose::Agent, now())?;
    let trust = binding.public()?;
    let issuer = &trust.issuers[0];
    let start = now();
    let refreshed = start + 130;
    let publication = STANDARD
        .decode(publication_fixture(&root(), &issuer.crl, false, refreshed, None).await?)?;
    let expected_crl = STANDARD.encode(&publication);
    let initial_publication = STANDARD.decode(&issuer.crl)?;
    let publishing = Arc::new(AtomicBool::new(false));
    let clock = Arc::new(AtomicI64::new(start));
    let observed = Arc::new(std::sync::Mutex::new(Vec::<(String, String, i64)>::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("https://localhost:{}", listener.local_addr()?.port());
    let mut tls = crate::test_support::tls::server(&root(), "agent-tls.pk8", None)?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let stop = tokio_util::sync::CancellationToken::new();
    let stopped = stop.clone();
    let server_clock = clock.clone();
    let server_publishing = publishing.clone();
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
                    let initial_publication = initial_publication.clone();
                    let publishing = server_publishing.clone();
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
                            if publishing.load(Ordering::SeqCst) {
                                clock.store(refreshed, Ordering::SeqCst);
                                publication
                            } else {
                                initial_publication
                            }
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
    let client = Arc::new(client);
    let mut windows = trust.clone();
    windows.purpose = Purpose::Windows;
    let windows = rss_mdm_device_trust::DeviceTrust::new(windows, Purpose::Windows, start)?;
    let providers = Arc::new(Providers::new(
        [Purpose::Windows, Purpose::Agent]
            .into_iter()
            .map(|purpose| Provider {
                purpose,
                issuer: issuer.digest.clone(),
                client: client.clone(),
                scep_url: None,
            })
            .collect(),
    )?);
    let (pool, source, audit) = crate::audit_test_support::request_store().await?;
    let registry = Registry::new(pool.clone(), audit, vec![windows, binding], providers);
    registry
        .admit(rss_request_context::TenantId::parse(case_a())?, start)
        .await?;
    let mut pg =
        <sqlx::PgConnection as sqlx::Connection>::connect_with(&options("postgres")?).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_a())
        .execute(&mut pg)
        .await?;
    let mut serials = Vec::new();
    let csr = std::fs::read(root().join("agent.der"))?;
    for name in ["sweep-first", "sweep-second"] {
        let identity = rss_mdm_certificate::agent::identity(Uuid::parse_str(case_a())?, name)?;
        let chain = crate::test_support::pki::leaf(
            &root(),
            &csr,
            "rss-mdm-agent",
            &[identity],
            start,
            start + 86400,
        )?;
        rss_mdm_pki_service::certificates::record_candidate_in(
            &mut pg,
            case_a(),
            "agent",
            None,
            &issuer.digest,
            &chain[0],
        )
        .await?;
        let leaf = x509_cert::Certificate::from_der(&chain[0])?;
        serials.push((
            rss_mdm_device_trust::serial(leaf.tbs_certificate.serial_number.as_bytes()),
            Uuid::new_v4(),
        ));
    }
    for (serial, attempt) in &serials {
        sqlx::query("INSERT INTO mdm_pki.revocations(tenant_id,purpose,issuer,serial,attempt,state) VALUES($1::uuid,'agent',$2,$3,$4,'pending')")
            .bind(case_a()).bind(&issuer.digest).bind(serial).bind(attempt).execute(&mut pg).await?;
    }
    publishing.store(true, Ordering::SeqCst);
    let result = registry.sweep(|| Ok(clock.load(Ordering::SeqCst))).await;
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    result?;
    for purpose in [Purpose::Windows, Purpose::Agent] {
        let actual = registry.trust(purpose)?;
        ensure!(actual.issuers[0].crl == expected_crl);
        let stored: Vec<u8> = sqlx::query_scalar(
            "SELECT body FROM mdm_pki.trust WHERE tenant_id=$1::uuid AND purpose=$2",
        )
        .bind(case_a())
        .bind(rss_mdm_pki_service::registry::purpose(purpose))
        .fetch_one(&mut pg)
        .await?;
        let stored: rss_mdm_agent_wire::pki::Trust = serde_json::from_slice(&stored)?;
        ensure!(stored == actual);
    }
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
    source.close().await;
    pool.close().await;
    Ok(())
}
