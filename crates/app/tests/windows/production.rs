//! Production lifecycle and origin dispatch; Nginx TLS policy is proved by gateway.tls.
use crate::test_support::{gateway, identity};
use crate::windows::test_support::{Host, case_tenant, monotonic, root};
use anyhow::{Context, Result, ensure};
use futures::FutureExt;
use rss_mdm_windows_mdm::{
    CodecLimits,
    soap::{self, Body, Operation},
};
use std::{sync::Arc, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=windows.production"]
async fn production_origins_keep_bootstrap_and_certificate_discovery_separate() -> Result<()> {
    let host = Host::open().await?;
    let peer = host.peer().await?;
    let mut config = identity::config(case_tenant())?;
    config.agent_pki = crate::agent_pki::Config::Disabled {};
    config.native_protocols.apple = None;
    let mut windows: crate::windows::WindowsConfig =
        serde_json::from_value(serde_json::to_value(&host.windows.config)?)?;
    // Keep the baseline's configured origins and selected PKI trust together.
    // The shared-443 hostname topology is exercised by the actual Nginx fixture.
    windows.additional_management = vec![crate::native::PublicEndpoint {
        origin: "https://devices-second.example.test".into(),
    }];
    let origins = vec![
        windows.enrollment.origin.clone(),
        windows.management.origin.clone(),
        windows.additional_management[0].origin.clone(),
    ];
    config.native_protocols.windows = Some(windows);
    config.trusted_gateway = "127.0.0.1".parse()?;
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    config.listen = reservation.local_addr()?;
    drop(reservation);
    let address = config.listen;
    let mut proxies = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(5))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut addresses = Vec::new();
    let mut launch = proxies.startup()?.commit();
    for origin in &origins {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        addresses.push(listener.local_addr()?);
        launch.stage_task_with_token(gateway::proxy(
            listener,
            address,
            root()?,
            origin.clone(),
            "windows-tls.pk8",
        )?);
    }
    launch.finish();
    let certificate = openssl::x509::X509::from_der(&peer.certificate)?.to_pem()?;
    let identity = reqwest::Identity::from_pem(
        &[certificate, std::fs::read(root()?.join("device.key"))?].concat(),
    )?;
    let anonymous = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(host.root_cert.clone())
        .timeout(Duration::from_secs(10))
        .build()?;
    let authenticated = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(host.root_cert.clone())
        .identity(identity)
        .timeout(Duration::from_secs(10))
        .build()?;
    let stop = tokio_util::sync::CancellationToken::new();
    let stopping = stop.clone();
    let mut server = tokio::spawn(crate::lifecycle::serve(
        config,
        async move {
            stopping.cancelled().await;
            Ok(())
        },
        monotonic(),
    ));
    let result = std::panic::AssertUnwindSafe(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                ensure!(
                    !server.is_finished(),
                    "production Windows host exited before readiness"
                );
                let response = anonymous
                    .get(format!("http://{address}/readyz"))
                    .header("host", "mdm.example.test")
                    .header("x-rss-public-origin", "https://mdm.example.test")
                    .header("x-forwarded-for", "127.0.0.1")
                    .send()
                    .await;
                if response.is_ok_and(|r| r.status() == 200) {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .context("production Windows readiness deadline")??;
        for (index, origin) in origins.iter().enumerate() {
            let mut request = soap::decode(
                include_bytes!(
                    "../../../windows-mdm/tests/fixtures/discovery-native-windows11.xml"
                ),
                Operation::Discover,
                &CodecLimits::default(),
            )?;
            request.header.to = Some(format!("{origin}/EnrollmentServer/Discovery.svc"));
            let body = soap::encode(&request, &CodecLimits::default())?;
            let url = format!(
                "https://localhost:{}/EnrollmentServer/Discovery.svc",
                addresses[index].port()
            );
            let client = if index == 0 {
                &anonymous
            } else {
                &authenticated
            };
            let response = client
                .post(&url)
                .header("content-type", "application/soap+xml")
                .body(body.clone())
                .send()
                .await?;
            ensure!(
                response.status() == 200,
                "production discovery on {origin}: {}",
                response.status()
            );
            let response =
                soap::decode_response(&request, &response.bytes().await?, &CodecLimits::default())?;
            let Body::DiscoverResponse(found) = response.body else {
                anyhow::bail!("missing discovery body")
            };
            ensure!(
                found.policy_url == format!("{origin}/EnrollmentServer/Policy.svc")
                    && found.enrollment_url == format!("{origin}/EnrollmentServer/Enrollment.svc"),
                "public origin changed during production dispatch"
            );
            if index > 0 {
                let denied = anonymous
                    .post(&url)
                    .header("content-type", "application/soap+xml")
                    .body(body)
                    .send()
                    .await?;
                ensure!(
                    !denied.status().is_success(),
                    "certificate discovery accepted anonymous bootstrap"
                );
                let management = anonymous
                    .post(format!(
                        "https://localhost:{}/ManagementServer/MDM.svc",
                        addresses[index].port()
                    ))
                    .body("no certificate")
                    .send()
                    .await?;
                ensure!(
                    management.status() == 401,
                    "management must reject missing certificate before protocol decoding"
                );
            }
        }
        let wrong = authenticated
            .post(format!(
                "https://localhost:{}/ManagementServer/MDM.svc",
                addresses[0].port()
            ))
            .send()
            .await?;
        ensure!(
            wrong.status() == 404,
            "management route entered bootstrap origin"
        );
        Ok::<_, anyhow::Error>(())
    })
    .catch_unwind()
    .await;
    stop.cancel();
    let stopped = tokio::time::timeout(Duration::from_secs(65), &mut server).await;
    if stopped.is_err() {
        server.abort();
        let _ = server.await;
    }
    ensure!(
        proxies.shutdown().join().await?.is_clean(),
        "Windows proxy shutdown incomplete"
    );
    host.close().await?;
    stopped
        .context("production Windows shutdown deadline")??
        .map_err(|e| anyhow::anyhow!("production Windows host failed: {e:?}"))?;
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
