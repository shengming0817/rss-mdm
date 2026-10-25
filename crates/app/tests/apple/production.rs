//! The production serve path owns listeners, automatic APNs work, health and shutdown.
use super::*;
use crate::apple::push;
use sqlx::{Connection, Row};
impl Fixture {
    pub async fn production() -> Result<()> {
        use crate::test_support::{authority::Authority, identity};
        let root = PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
        let manage = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("https://localhost:{}", manage.local_addr()?.port());
        let participant = push::test_support::Participant::start(vec![200], vec![42; 32]).await?;
        let mut config = identity::config(case_tenant())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        config.listen = listener.local_addr()?;
        drop(listener);
        let address = config.listen;
        let native_address = address;
        config.trusted_gateway = "127.0.0.1".parse()?;
        config.native_protocols.windows = None;
        let mut apple_config: config::Config =
            serde_json::from_slice(&std::fs::read(root.join("apple.json"))?)?;
        apple_config.management.origin = origin.clone();
        let mut trust: rss_mdm_agent_wire::pki::Trust =
            serde_json::from_slice(&std::fs::read(&apple_config.trust_file)?)?;
        trust.origin = origin.clone();
        let trust_file = root.join(format!("production-trust-{}.json", Uuid::new_v4()));
        std::fs::write(&trust_file, serde_json::to_vec(&trust)?)?;
        apple_config.trust_file = trust_file;
        apple_config.test_push_transport = Some((participant.origin(), root.join("ca.crt")));
        config.native_protocols.apple = Some(serde_json::from_value(serde_json::to_value(
            &apple_config,
        )?)?);
        config
            .native_protocols
            .apple
            .as_mut()
            .unwrap()
            .test_push_transport = Some((participant.origin(), root.join("ca.crt")));
        config.apple_material_roots = vec![root.join("apple-root.pem")];
        let protection = config.native_protector()?;
        seed_fixture_materials(&root, &protection).await?;
        let mut authority = Authority::open().await?;
        let resources = std::mem::take(&mut authority.resources);
        let peer = resources.finish(async {
            identity::seed_grants(case_tenant(), crate::test_support::case::admin(), Fixture::native_grants(&["device_control"])?).await?;
            let apple = Apple::load(protection, apple_config, fixture_materials(&root)?, crate::clock::SystemClock.unix_seconds()?,
                (&config.product_origin, authority.identity.tenant), crate::device_pki::providers(&config.device_pki)?)?;
            crate::test_support::pki::seed_trust(&authority.pool, &[apple.channel.device_trust().clone()]).await?;
            let device = scep_client::Device::new(Uuid::new_v4(), Uuid::new_v4(), &crate::enrollment::random())?;
            let der = device.local_leaf(&PathBuf::from(std::env::var("MDM_APPLE_PKI_FIXTURES")?))?;
            let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
            let mut tx = authority.pool.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
            rss_mdm_apple_channel::enrollment::seed_current_peer_in(&mut tx, &apple.channel, &proof,
                rss_mdm_apple_channel::enrollment::CurrentPeer { device: case_device(), udid: crate::test_support::case::name("rss-t2-apple"), csr: &device.csr, certificate: &der, now: crate::clock::SystemClock.unix_seconds()? }).await?;
            let (registration, generation): (Uuid, i64) = sqlx::query_as("SELECT id,generation FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm' AND state='active' AND purpose='primary'")
                .bind(case_tenant()).bind(case_device()).fetch_one(&mut *tx).await?;
            tx.commit().await?;
            let sessions = Arc::new(rss_mdm_authorization_service::session::SessionAuthority::new(authority.identity.authority.clone(), authority.identity.tenant));
            let (commands, _, runtime) = crate::test_support::command::command_service(authority.audit.clone(), sessions, rss_device_command_postgres::CommandClock::Postgres).await?;
            let operation = Uuid::new_v4();
            let prepared = runtime.local_tx_with_context(authority.identity.tenant, crate::identity::deadline(), (&commands, &proof), |(service, proof), tx| Box::pin(async move {
                service.seed_cancelled_apple_restart_in(tx, proof, case_device(), operation).await.map_err(|e| rss_transactional_messaging_postgres::PgError::from(sqlx::Error::Protocol(e.to_string())))
            })).await.fold(Ok, Err, Err, Err, Err, Err);
            rss_runtime::ManagedResource::shutdown(&rss_mdm_execution_service::Resource(commands)).await?;
            prepared?;
            let mut tx = authority.pool.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
            apple.channel.prepare_context_fixture(&mut tx, case_tenant(), registration, generation, operation).await?;
            tx.commit().await?;
            Ok(lifecycle::Peer {
                client: reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(15)).identity(device.identity(&der)?)
                    .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(root.join("ca.crt"))?)?).build()?,
                origin: origin.clone(), topic: apple.channel.apns_topic().into(), pending_replies: Default::default(), installed_trust: Default::default(), oracle: oracle::Oracle::new(&der)?,
            })
        }).await?;
        let mut browser = Authority::prepared_browser("admin")?;
        let mut ingress = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(5))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        ingress
            .startup()?
            .stage_task_with_token(crate::test_support::gateway::proxy(
                manage,
                native_address,
                root.clone(),
                peer.origin.clone(),
                "apple-tls.pk8",
            )?);
        let stop = tokio_util::sync::CancellationToken::new();
        let stopped = stop.clone();
        let server = tokio::spawn(crate::lifecycle::serve(
            config,
            async move {
                stopped.cancelled().await;
                Ok(())
            },
            fixture_clock(),
        ));
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()?;
        let ready = |client: reqwest::Client| async move {
            client
                .get(format!("http://{address}/readyz"))
                .header("host", "mdm.example.test")
                .header("x-rss-public-origin", "https://mdm.example.test")
                .header("x-forwarded-for", "127.0.0.1")
                .send()
                .await
                .map(|r| r.status())
        };
        let mut online = false;
        for _ in 0..100 {
            if ready(client.clone()).await.ok() == Some(StatusCode::OK) {
                online = true;
                break;
            }
            if server.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !online {
            stop.cancel();
            anyhow::bail!(
                "production Apple startup did not become ready: {:?}",
                server.await?
            );
        }
        // Hits the listener bound by serve, without resetting an already accepted push.
        let reply = peer
            .send(
                "/checkin",
                protocol::dictionary([
                    ("MessageType", "Authenticate".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                    ("Topic", peer.topic.clone().into()),
                ]),
            )
            .await?;
        ensure!(reply.0 == StatusCode::OK);
        peer.token().await?;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-rss-public-origin", "https://mdm.example.test".parse()?);
        headers.insert("x-forwarded-for", "127.0.0.1".parse()?);
        browser.network = Some((
            reqwest::Client::builder()
                .no_proxy()
                .default_headers(headers)
                .timeout(Duration::from_secs(15))
                .build()?,
            format!("http://{address}"),
        ));
        let operation = Uuid::new_v4();
        let (status, value) = browser.call(&Router::new(), Method::POST, &format!("/api/v1/devices/{}/operations", case_device()),
            Some(json!({"operationId":operation,"action":{"kind":"restart"},"deadline":crate::clock::SystemClock.unix_seconds()?+300}))).await?;
        ensure!(
            status == StatusCode::ACCEPTED,
            "production restart: {status} {value}"
        );
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let mut accepted = false;
        for _ in 0..100 {
            let row = sqlx::query(
                "SELECT push_status,push_outcome FROM mdm_apple.channels WHERE state='active'",
            )
            .fetch_one(&mut pg)
            .await?;
            let published: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2 AND status='published')").bind(case_tenant()).bind(operation.to_string()).fetch_one(&mut pg).await?;
            if published
                && row.try_get::<Option<i32>, _>("push_status")? == Some(200)
                && row.try_get::<Option<String>, _>("push_outcome")?.as_deref() == Some("accepted")
            {
                accepted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        ensure!(
            accepted,
            "production APNs worker never delivered pending work"
        );
        let (status, value) = browser
            .call(
                &Router::new(),
                Method::GET,
                &format!("/api/v1/devices/{}/operations/{operation}", case_device()),
                None,
            )
            .await?;
        ensure!(status == StatusCode::OK && value["commandStatus"] == "published");
        crate::test_support::http::seed_management_grants(
            crate::test_support::case::admin(),
            json!(["runtime_diagnostics_read"]),
        )
        .await?;
        // APNs failure degrades only the channel; core readiness stays available.
        sqlx::query("REVOKE SELECT ON mdm_apple.channels FROM mdm_command_runtime")
            .execute(&mut pg)
            .await?;
        let mut unhealthy = false;
        for _ in 0..120 {
            let response = client
                .get(format!("http://{address}/api/v1/runtime/diagnostics"))
                .header("host", "mdm.example.test")
                .header("x-rss-public-origin", "https://mdm.example.test")
                .header("x-forwarded-for", "127.0.0.1")
                .header(
                    "cookie",
                    browser
                        .cookies
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join("; "),
                )
                .send()
                .await?;
            let snapshot: serde_json::Value = response.json().await?;
            if snapshot["channels"].as_array().is_some_and(|channels| {
                channels
                    .iter()
                    .any(|c| c["name"] == "apple" && c["state"] == "degraded")
            }) {
                ensure!(ready(client.clone()).await.ok() == Some(StatusCode::OK));
                unhealthy = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        sqlx::query("GRANT SELECT ON mdm_apple.channels TO mdm_command_runtime")
            .execute(&mut pg)
            .await?;
        ensure!(
            unhealthy,
            "persistent APNs storage failure was not reported by channel diagnostics"
        );
        let mut recovered = false;
        for _ in 0..180 {
            let snapshot: serde_json::Value = client
                .get(format!("http://{address}/api/v1/runtime/diagnostics"))
                .header("host", "mdm.example.test")
                .header("x-rss-public-origin", "https://mdm.example.test")
                .header("x-forwarded-for", "127.0.0.1")
                .header(
                    "cookie",
                    browser
                        .cookies
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join("; "),
                )
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if snapshot["channels"].as_array().is_some_and(|channels| {
                channels
                    .iter()
                    .any(|c| c["name"] == "apple" && c["state"] == "ready")
            }) {
                recovered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        ensure!(
            recovered,
            "APNs worker did not restore readiness after storage recovery"
        );
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(45), server).await???;
        ensure!(ingress.shutdown().join().await?.is_clean());
        participant.close().await?;
        ensure!(
            tokio::net::TcpStream::connect(address).await.is_err(),
            "browser listener survived shutdown"
        );
        ensure!(
            tokio::net::TcpStream::connect((
                "127.0.0.1",
                url::Url::parse(&peer.origin)?
                    .port_or_known_default()
                    .unwrap()
            ))
            .await
            .is_err(),
            "native listener survived shutdown"
        );
        pg.close().await?;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "MODULE=apple.host: production assembly, health and bounded shutdown"]
async fn production_listeners_push_and_shutdown() -> Result<()> {
    Fixture::production().await
}

#[test]
#[ignore = "MODULE=apple.host: material loading without production listeners or application assembly"]
fn startup_material_diagnostics() -> Result<()> {
    startup_diagnostics(&PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?))
}

#[tokio::test]
#[ignore = "MODULE=apple.host: durable material selection, failed-candidate rollback, isolation and revocation"]
async fn durable_material_authority_controls_host_use() -> Result<()> {
    use rss_mdm_apple_channel::runtime_materials::runtime;
    use sqlx::Connection;
    let root = std::path::PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
    let config = crate::test_support::identity::config(case_tenant())?;
    let protection = config.native_protector()?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(config.access_options()?)
        .await?;
    let mut resources = crate::test_support::runtime::Resources::default();
    resources.resource(crate::test_support::runtime::PoolResource(pool.clone()));
    let store = rss_mdm_apple_channel::Store::from_pool(
        pool.clone(),
        Arc::new(rss_mdm_registration_service::Store::from_pool(
            pool.clone(),
            Arc::new(crate::registration_lifecycle::Bridge),
        )),
        Arc::new(rss_mdm_authorization_service::Store::from_pool(
            pool,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )),
    );
    resources.finish(async {
    seed_fixture_materials(&root, &protection).await?;
    let roots = vec![std::fs::read(root.join("apple-root.pem"))?];
    let selection = runtime::Selection {
        apns: Some(1),
        profile: Some(1),
        accounts: std::collections::BTreeMap::from([("organization".into(), 1)]),
    };
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let loaded = runtime::load(&store, tenant, &protection, &roots, &selection, now).await?;
    loaded.binding.check(&store, case_tenant(), now).await?;
    let wrong = rss_mdm_native_protection::Protector::new(&[19; 32])?;
    ensure!(
        runtime::load(&store, tenant, &wrong, &roots, &selection, now)
            .await
            .is_err()
    );
    ensure!(
        runtime::load(
            &store,
            rss_request_context::TenantId::parse("33333333-3333-4333-8333-333333333333")?,
            &protection,
            &roots,
            &selection,
            now
        )
        .await
        .is_err()
    );
    let mut c =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("mdm_access")?)
            .await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE mdm_apple_runtime.heads SET revision=9,desired_revision=9 WHERE tenant_id=$1::uuid",
    )
    .bind(case_tenant())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    // A rejected newer candidate cannot prevent restoring the previously selected valid version.
    runtime::load(&store, tenant, &protection, &roots, &selection, now).await?;
    let mut tx = c.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE mdm_apple_runtime.versions SET revoked=true WHERE tenant_id=$1::uuid AND purpose='apns'").bind(case_tenant()).execute(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        loaded
            .binding
            .check(&store, case_tenant(), now)
            .await
            .is_err()
    );
    ensure!(
        runtime::load(&store, tenant, &protection, &roots, &selection, now)
            .await
            .is_err()
    );
    c.close().await?;
    Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=apple.host: real host starts with Apple intent but no selected organizational materials"]
async fn missing_apple_materials_keep_management_ready_and_listener_closed() -> Result<()> {
    blocked_apple_host(StartupFault::MissingSelection).await
}

#[tokio::test]
#[ignore = "MODULE=apple.host: unavailable optional CA leaves management alive and closes Apple transport"]
async fn unavailable_apple_provider_keeps_management_ready_and_listener_closed() -> Result<()> {
    blocked_apple_host(StartupFault::ProviderUnavailable).await
}

#[tokio::test]
#[ignore = "MODULE=apple.host: conflicting origin closes only the channel and preserves persistent trust"]
async fn conflicting_apple_trust_preserves_history_and_keeps_management_ready() -> Result<()> {
    blocked_apple_host(StartupFault::TrustConflict).await
}
#[derive(Clone, Copy)]
enum StartupFault {
    MissingSelection,
    ProviderUnavailable,
    TrustConflict,
}

async fn blocked_apple_host(fault: StartupFault) -> Result<()> {
    let root = PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
    let mut authority = crate::test_support::authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources
        .finish(async {
            let (expected_state, expected_reason) = match fault {
                StartupFault::MissingSelection => ("waiting", "material_not_selected"),
                StartupFault::ProviderUnavailable => ("degraded", "dependency_unavailable"),
                StartupFault::TrustConflict => ("degraded", "trust_conflict"),
            };
            let mut config = crate::test_support::identity::config(case_tenant())?;
            let browser = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = browser.local_addr()?;
            drop(browser);
            config.listen = address;
            config.native_protocols.windows = None;
            config.agent_pki = crate::agent_pki::Config::Disabled {};
            let mut apple: config::Config =
                serde_json::from_slice(&std::fs::read(root.join("apple.json"))?)?;
            config.trusted_gateway = "127.0.0.1".parse()?;
            let protection = config.native_protector()?;
            let expected_trust: rss_mdm_agent_wire::pki::Trust =
                serde_json::from_slice(&std::fs::read(&apple.trust_file)?)?;
            let original_origin = expected_trust.origin.clone();
            let loaded = Apple::load(
                protection.clone(),
                serde_json::from_value(serde_json::to_value(&apple)?)?,
                fixture_materials(&root)?,
                crate::clock::SystemClock.unix_seconds()?,
                (&config.product_origin, authority.identity.tenant),
                crate::device_pki::providers(&config.device_pki)?,
            )?;
            crate::test_support::pki::seed_trust(
                &authority.pool,
                &[loaded.channel.device_trust().clone()],
            )
            .await?;
            if matches!(fault, StartupFault::TrustConflict) {
                let mut changed = expected_trust;
                changed.origin = "https://conflicting-apple.example.test".into();
                apple.management.origin = changed.origin.clone();
                apple.trust_file = root.join(format!("conflicting-trust-{}.json", Uuid::new_v4()));
                std::fs::write(&apple.trust_file, serde_json::to_vec(&changed)?)?;
            }
            if !matches!(fault, StartupFault::MissingSelection) {
                seed_fixture_materials(&root, &protection).await?;
                for provider in &mut config.device_pki {
                    if matches!(fault, StartupFault::ProviderUnavailable)
                        && provider.purpose == rss_mdm_agent_wire::pki::Purpose::Apple
                    {
                        provider.origin = "https://localhost:1".into();
                    }
                }
            } else {
                apple.materials = Default::default();
            }
            crate::test_support::http::seed_management_grants(
                crate::test_support::case::admin(),
                json!(["runtime_diagnostics_read"]),
            )
            .await?;
            config.native_protocols.apple = Some(apple);
            config.apple_material_roots = vec![root.join("apple-root.pem")];
            let stop = tokio_util::sync::CancellationToken::new();
            let stopped = stop.clone();
            let server = tokio::spawn(crate::lifecycle::serve(
                config,
                async move {
                    stopped.cancelled().await;
                    Ok(())
                },
                fixture_clock(),
            ));
            let result: Result<()> = async {
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .timeout(Duration::from_secs(2))
                    .build()?;
                tokio::time::timeout(Duration::from_secs(20), async {
                    loop {
                        if let Ok(response) = client
                            .get(format!("http://{address}/readyz"))
                            .header("host", "mdm.example.test")
                            .header("x-rss-public-origin", "https://mdm.example.test")
                            .header("x-forwarded-for", "127.0.0.1")
                            .send()
                            .await
                            && response.status() == StatusCode::OK
                        {
                            break;
                        }
                        ensure!(
                            !server.is_finished(),
                            "missing optional materials terminated the host"
                        );
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Ok::<_, anyhow::Error>(())
                })
                .await??;
                let response = client
                    .get(format!("http://{address}/api/v1/runtime/diagnostics"))
                    .header("host", "mdm.example.test")
                    .header("x-rss-public-origin", "https://mdm.example.test")
                    .header("x-forwarded-for", "127.0.0.1")
                    .header(
                        "cookie",
                        crate::test_support::authority::Authority::prepared_browser("admin")?
                            .cookies
                            .iter()
                            .map(|(k, v)| format!("{k}={v}"))
                            .collect::<Vec<_>>()
                            .join("; "),
                    )
                    .send()
                    .await?;
                ensure!(
                    response.status() == StatusCode::OK,
                    "authorized diagnostics unavailable"
                );
                let snapshot: serde_json::Value = response.json().await?;
                let apple = snapshot["channels"]
                    .as_array()
                    .and_then(|rows| rows.iter().find(|row| row["name"] == "apple"))
                    .ok_or_else(|| anyhow::anyhow!("missing Apple state"))?;
                ensure!(
                    apple["state"] == expected_state && apple["mounted"] == false,
                    "{apple}"
                );
                ensure!(apple["reasons"] == json!([expected_reason]), "{apple}");
                let mut tx = authority.pool.begin().await?;
                sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                    .bind(case_tenant())
                    .execute(&mut *tx)
                    .await?;
                let body: Vec<u8> = sqlx::query_scalar(
                    "SELECT body FROM mdm_pki.trust WHERE tenant_id=$1::uuid AND purpose='apple'",
                )
                .bind(case_tenant())
                .fetch_one(&mut *tx)
                .await?;
                tx.rollback().await?;
                let retained: rss_mdm_agent_wire::pki::Trust = serde_json::from_slice(&body)?;
                ensure!(retained.origin == original_origin);
                Ok(())
            }
            .await;
            stop.cancel();
            let closed = tokio::time::timeout(Duration::from_secs(45), server).await;
            result?;
            closed???;
            Ok(())
        })
        .await
}

#[tokio::test]
#[ignore = "MODULE=apple.host: persisted Apple corruption must remain a fatal material error"]
async fn corrupt_persisted_apple_certificate_is_not_optional_unavailability() -> Result<()> {
    let root = std::path::PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
    let config = crate::test_support::identity::config(case_tenant())?;
    let protection = config.native_protector()?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(config.access_options()?)
        .await?;
    let mut resources = crate::test_support::runtime::Resources::default();
    resources.resource(crate::test_support::runtime::PoolResource(pool.clone()));
    let store = rss_mdm_apple_channel::Store::from_pool(
        pool.clone(),
        Arc::new(rss_mdm_registration_service::Store::from_pool(
            pool.clone(),
            Arc::new(crate::registration_lifecycle::Bridge),
        )),
        Arc::new(rss_mdm_authorization_service::Store::from_pool(
            pool,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )),
    );
    resources.finish(async {
        seed_fixture_materials(&root, &protection).await?;
        let mut c = sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        sqlx::query("UPDATE mdm_apple_runtime.versions SET certificate='corrupt persisted PEM' WHERE tenant_id=$1::uuid AND purpose='apns' AND revision=1")
            .bind(case_tenant()).execute(&mut c).await?;
        let selection = rss_mdm_apple_channel::runtime_materials::runtime::Selection {
            apns: Some(1), profile: Some(1), accounts: Default::default(),
        };
        let result = rss_mdm_apple_channel::runtime_materials::runtime::load(
            &store, rss_request_context::TenantId::parse(case_tenant())?,
            &protection, &[std::fs::read(root.join("apple-root.pem"))?],
            &selection, time::OffsetDateTime::now_utc().unix_timestamp(),
        ).await;
        ensure!(matches!(result, Err(rss_mdm_apple_channel::runtime_materials::runtime::LoadError::Fatal(_))));
        c.close().await?;
        Ok(())
    }).await
}
