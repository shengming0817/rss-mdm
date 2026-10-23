//! The production serve path owns listeners, automatic APNs work, health and shutdown.
use super::*;
use crate::apple::push;
use sqlx::{Connection, Row};
impl Fixture {
    pub async fn production(mut self) -> Result<()> {
        let (device, der) = self.scep_leaf().await?;
        let peer = lifecycle::Peer {
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(15))
                .identity(device.identity(&der)?)
                .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                    self.root.join("ca.crt"),
                )?)?)
                .build()?,
            origin: self.app.apple()?.config.management.origin.clone(),
            topic: self.app.apple()?.channel.apns_topic().to_owned(),
            pending_replies: Default::default(),
            installed_trust: Default::default(),
            oracle: oracle::Oracle::new(&der)?,
        };
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
        self.native_context().await?;
        self.grant_native_actions(&["device_control"]).await?;
        let operation = self.create_restart().await?;
        let participant = push::test_support::Participant::start(vec![200], vec![42; 32]).await?;
        let mut config = crate::test_support::identity::config(case_tenant())?;
        let port = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        config.listen = port.local_addr()?;
        drop(port);
        config.native_protocols.windows = None;
        let mut apple: config::Config =
            serde_json::from_slice(&std::fs::read(self.root.join("apple.json"))?)?;
        let native_address = config.listen;
        config.trusted_gateway = "127.0.0.1".parse()?;
        apple.management.origin = peer.origin.clone();
        apple.trust_file = self.app.apple()?.config.trust_file.clone();
        apple.test_push_transport = Some((participant.origin(), self.root.join("ca.crt")));
        config.native_protocols.apple = Some(apple);
        config.apple_material_roots = vec![self.root.join("apple-root.pem")];
        seed_fixture_materials(&self.root, &self.app.protection).await?;
        let address = config.listen;
        let empty = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        self.stop_execution_worker().await?;
        let manual = std::mem::replace(&mut self.owner, empty);
        ensure!(manual.shutdown().join().await?.is_clean());
        let mut ingress = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(5))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        ingress
            .startup()?
            .stage_task_with_token(crate::test_support::gateway::proxy(
                tokio::net::TcpListener::bind((
                    "127.0.0.1",
                    url::Url::parse(&peer.origin)?
                        .port_or_known_default()
                        .unwrap(),
                ))
                .await?,
                native_address,
                self.root.clone(),
                peer.origin.clone(),
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
            if row.try_get::<Option<i32>, _>("push_status")? == Some(200)
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
        ensure!(self.operation(operation).await?["commandStatus"] == "published");
        crate::test_support::http::set_management_grants(
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
                    self.browser
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
                    self.browser
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
        self.close().await
    }
}

#[tokio::test]
#[ignore = "MODULE=apple.host: production assembly, health and bounded shutdown"]
async fn production_listeners_push_and_shutdown() -> Result<()> {
    let f = Fixture::start().await?;
    f.production().await
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
    let f = Fixture::start().await?;
    seed_fixture_materials(&f.root, &f.app.protection).await?;
    let roots = vec![std::fs::read(f.root.join("apple-root.pem"))?];
    let selection = runtime::Selection {
        apns: Some(1),
        profile: Some(1),
        accounts: std::collections::BTreeMap::from([("organization".into(), 1)]),
    };
    let store = f.app.access.apple_store();
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let now = f.app.clock.unix_seconds()?;
    let loaded = runtime::load(&store, tenant, &f.app.protection, &roots, &selection, now).await?;
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
            &f.app.protection,
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
    runtime::load(&store, tenant, &f.app.protection, &roots, &selection, now).await?;
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
        runtime::load(&store, tenant, &f.app.protection, &roots, &selection, now)
            .await
            .is_err()
    );
    f.close().await
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
    let fixture = Fixture::start().await?;
    let (expected_state, expected_reason) = match fault {
        StartupFault::MissingSelection => ("waiting", "material_not_selected"),
        StartupFault::ProviderUnavailable => ("degraded", "dependency_unavailable"),
        StartupFault::TrustConflict => ("degraded", "trust_conflict"),
    };
    let mut config = crate::test_support::identity::config(case_tenant())?;
    let browser = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = browser.local_addr()?;
    drop(browser);
    let native = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let native_address = native.local_addr()?;
    drop(native);
    config.listen = address;
    config.native_protocols.windows = None;
    config.agent_pki = crate::agent_pki::Config::Disabled {};
    let mut apple: config::Config =
        serde_json::from_slice(&std::fs::read(fixture.root.join("apple.json"))?)?;
    let _ = native_address;
    config.trusted_gateway = "127.0.0.1".parse()?;
    if !matches!(fault, StartupFault::TrustConflict) {
        apple.management.origin = fixture.app.apple()?.config.management.origin.clone();
        apple.trust_file = fixture.app.apple()?.config.trust_file.clone();
    }
    if !matches!(fault, StartupFault::MissingSelection) {
        seed_fixture_materials(&fixture.root, &fixture.app.protection).await?;
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
    crate::test_support::http::set_management_grants(
        crate::test_support::case::admin(),
        json!(["runtime_diagnostics_read"]),
    )
    .await?;
    config.native_protocols.apple = Some(apple);
    config.apple_material_roots = vec![fixture.root.join("apple-root.pem")];
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
                fixture
                    .browser
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
        let mut tx = fixture.app.access.archive_pool().begin().await?;
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
        ensure!(retained.origin == fixture.app.apple()?.config.management.origin);
        ensure!(
            tokio::net::TcpStream::connect(native_address)
                .await
                .is_err(),
            "unprepared Apple listener was published"
        );
        Ok(())
    }
    .await;
    stop.cancel();
    let closed = tokio::time::timeout(Duration::from_secs(45), server).await;
    let fixture_closed = fixture.close().await;
    result?;
    closed???;
    fixture_closed
}

#[tokio::test]
#[ignore = "MODULE=apple.host: persisted Apple corruption must remain a fatal material error"]
async fn corrupt_persisted_apple_certificate_is_not_optional_unavailability() -> Result<()> {
    let fixture = Fixture::start().await?;
    let result: Result<()> = async {
        seed_fixture_materials(&fixture.root, &fixture.app.protection).await?;
        let mut c = sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        sqlx::query("UPDATE mdm_apple_runtime.versions SET certificate='corrupt persisted PEM' WHERE tenant_id=$1::uuid AND purpose='apns' AND revision=1")
            .bind(case_tenant()).execute(&mut c).await?;
        let selection = rss_mdm_apple_channel::runtime_materials::runtime::Selection {
            apns: Some(1), profile: Some(1), accounts: Default::default(),
        };
        let result = rss_mdm_apple_channel::runtime_materials::runtime::load(
            &fixture.app.access.apple_store(), rss_request_context::TenantId::parse(case_tenant())?,
            &fixture.app.protection, &[std::fs::read(fixture.root.join("apple-root.pem"))?],
            &selection, time::OffsetDateTime::now_utc().unix_timestamp(),
        ).await;
        ensure!(matches!(result, Err(rss_mdm_apple_channel::runtime_materials::runtime::LoadError::Fatal(_))));
        Ok(())
    }.await;
    let closed = fixture.close().await;
    result?;
    closed
}
