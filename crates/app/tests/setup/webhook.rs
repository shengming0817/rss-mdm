use super::*;
use anyhow::{Result, ensure};
use std::sync::Arc;
#[tokio::test]
#[ignore = "MODULE=installation.webhook: real TLS receiver proof, failed-candidate retention and encrypted rewrap"]
async fn receiver_possession_gates_activation_and_old_ciphertexts_remain_readable() -> Result<()> {
    use materials::{Action, Prepare, Source, Transition};
    let root = crate::windows::test_support::root()?;
    let windows: crate::windows::WindowsConfig =
        serde_json::from_slice(&std::fs::read(root.join("windows.json"))?)?;
    let config = crate::test_support::identity::config(crate::test_support::case::tenant())?;
    let tenant = Uuid::parse_str(&config.identity.tenant_id)?;
    let protection = config.native_protector()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let network = crate::webhooks::Network {
        tenant,
        reference: "receiver".into(),
        hostname: "localhost".into(),
        port: address.port(),
        addresses: vec![address],
        cidrs: vec!["127.0.0.1/32".parse()?],
        ca_files: vec![root.join("ca.crt")],
    };
    let configuration = crate::webhooks::Config {
        networks: vec![network.clone()],
        recovery_database: config.webhooks.recovery_database.clone(),
    }
    .material_configuration()?;
    let options = std::env::var("MDM_OWNER_URL")?
        .parse::<sqlx::postgres::PgConnectOptions>()?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut owner = PgConnection::connect_with(&options).await?;
    let secret = zeroize::Zeroizing::new(format!("whsec_{}", STANDARD.encode([9u8; 32])));
    let mut tx = owner.begin().await?;
    scope(&mut tx, tenant).await?;
    let first = materials::prepare(
        &mut tx,
        tenant,
        Uuid::new_v4(),
        &Prepare {
            reference: "receiver".into(),
            expected_revision: 0,
            configuration_sha256: configuration.clone(),
            endpoint: format!("https://localhost:{}/events", address.port()),
            network_reference: "receiver".into(),
            source: Source::Import {
                secret: secret.clone(),
            },
        },
        &protection,
    )
    .await?;
    tx.commit().await?;
    let mut tx = owner.begin().await?;
    scope(&mut tx, tenant).await?;
    ensure!(matches!(
        materials::transition(
            &mut tx,
            tenant,
            Uuid::new_v4(),
            &Transition {
                reference: "receiver".into(),
                expected_revision: 1,
                action: Action::Activate {
                    material_revision: 1
                }
            },
            &configuration,
            &protection
        )
        .await,
        Err(rss_mdm_webhook_service::Error::Conflict)
    ));
    tx.rollback().await?;
    // Runtime SQL privileges cannot manufacture an external qualification.
    let mut runtime = PgConnection::connect_with(&config.execution.database.options()?).await?;
    let mut tx = runtime.begin().await?;
    scope(&mut tx, tenant).await?;
    let forged =
        sqlx::query("UPDATE mdm_webhook.key_materials SET confirmed=true WHERE tenant_id=$1")
            .bind(tenant)
            .execute(&mut *tx)
            .await;
    ensure!(
        forged
            .unwrap_err()
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref()
            == Some("42501")
    );
    tx.rollback().await?;
    runtime.close().await?;
    let mut tls = (*crate::native::tls::configuration(&windows.management, None)?).clone();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let expected = first.clone();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let server = tokio::spawn(async move {
        for correct in [false, true] {
            let (tcp, _) = listener.accept().await?;
            let tls = acceptor.accept(tcp).await?;
            let mut h2 = h2::server::handshake(tls).await?;
            let (request, mut response) = h2.accept().await.unwrap()?;
            ensure!(request.method() == reqwest::Method::POST && request.uri().path() == "/events");
            let timestamp = request.headers()["webhook-timestamp"].to_str()?.to_owned();
            ensure!(request.headers()["webhook-id"].to_str()? == expected.operation_id.to_string());
            let signature = request.headers()["webhook-signature"]
                .to_str()?
                .strip_prefix("v1,")
                .unwrap()
                .to_owned();
            let mut body = request.into_body();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk?;
                body.flow_control().release_capacity(chunk.len())?;
                bytes.extend_from_slice(&chunk);
            }
            let message: materials::ConfirmationRequest = serde_json::from_slice(&bytes)?;
            ensure!(
                message.challenge == expected.challenge
                    && message.configuration_sha256 == expected.configuration_sha256
            );
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[9u8; 32]);
            let mut signed = format!("{}.{timestamp}.", expected.operation_id).into_bytes();
            signed.extend_from_slice(&bytes);
            ring::hmac::verify(&key, &signed, &STANDARD.decode(signature)?)
                .map_err(|_| anyhow::anyhow!("qualification request signature rejected"))?;
            let proof = if correct {
                STANDARD.encode(
                    ring::hmac::sign(&key, &materials::confirmation_message(tenant, &expected))
                        .as_ref(),
                )
            } else {
                STANDARD.encode([0u8; 32])
            };
            let response_body = serde_json::to_vec(&materials::ConfirmationResponse {
                confirmation_proof: proof,
            })?;
            let mut send = response
                .send_response(axum::http::Response::builder().status(200).body(())?, false)?;
            send.send_data(axum::body::Bytes::from(response_body), true)?;
            while h2.accept().await.is_some() {}
        }
        anyhow::Ok(())
    });
    ensure!(probe(&network, &first, tenant, &secret).await.is_err());
    let proof = probe(&network, &first, tenant, &secret).await?;
    server.await??;
    let mut tx = owner.begin().await?;
    scope(&mut tx, tenant).await?;
    materials::confirm(&mut tx, tenant, "receiver", 1, &proof, &protection).await?;
    let activated = materials::transition(
        &mut tx,
        tenant,
        Uuid::new_v4(),
        &Transition {
            reference: "receiver".into(),
            expected_revision: 1,
            action: Action::Activate {
                material_revision: 1,
            },
        },
        &configuration,
        &protection,
    )
    .await?;
    let second = materials::prepare(
        &mut tx,
        tenant,
        Uuid::new_v4(),
        &Prepare {
            reference: "receiver".into(),
            expected_revision: activated.revision,
            configuration_sha256: configuration.clone(),
            endpoint: first.endpoint.clone().unwrap(),
            network_reference: "receiver".into(),
            source: Source::Generate,
        },
        &protection,
    )
    .await?;
    ensure!(second.revision == 3);
    ensure!(
        materials::load(&mut tx, tenant, "receiver", &configuration, &protection)
            .await?
            .current
            .as_str()
            == secret.as_str()
    );
    let old = crate::config::read(&config.native_protection.active_file, 32, true)?;
    let fingerprint = crate::config::read(&config.native_protection.fingerprint_file, 32, true)?;
    let next = rss_mdm_native_protection::Protector::with_fingerprint(
        &[43u8; 32],
        &[old.as_slice()],
        &fingerprint,
    )?;
    ensure!(materials::rewrap(&mut tx, tenant, &next).await? == 2);
    ensure!(
        materials::load(&mut tx, tenant, "receiver", &configuration, &next)
            .await?
            .current
            .as_str()
            == secret.as_str()
    );
    ensure!(
        materials::load(&mut tx, tenant, "receiver", &configuration, &protection)
            .await
            .is_err()
    );
    materials::transition(
        &mut tx,
        tenant,
        Uuid::new_v4(),
        &Transition {
            reference: "receiver".into(),
            expected_revision: 3,
            action: Action::Revoke {
                material_revision: 1,
            },
        },
        &configuration,
        &next,
    )
    .await?;
    ensure!(
        materials::load(&mut tx, tenant, "receiver", &configuration, &next)
            .await
            .is_err()
    );
    let public = serde_json::to_string(&materials::directory(&mut tx, tenant).await?)?;
    ensure!(!public.contains(secret.as_str()));
    tx.commit().await?;
    owner.close().await?;
    Ok(())
}
