//! Complete production Agent assembly, readiness and authenticated event/task routes.
//! ref: axum axum/src/serve/mod.rs@axum-v0.8.9 (served requests and graceful shutdown).
use crate::clock::{Clock, SystemClock};
use crate::test_support::{agent_http::*, authority::Authority, runtime::*, *};
use anyhow::Context;
use futures::FutureExt;
use std::{net::SocketAddr, path::PathBuf};

async fn prepare_peer() -> Result<(String, Vec<Vec<u8>>)> {
    let mut authority = Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources
        .finish(async {
            let service = agent::service(&authority).await?;
            let root = PathBuf::from(std::env::var("MDM_AGENT_PKI_FIXTURES")?);
            let device = case::name("listener-agent").to_owned();
            let csr = std::fs::read(root.join("agent.der"))?;
            let identity = rss_mdm_certificate::agent::identity(
                Uuid::parse_str(case_tenant())?,
                &device,
            )?;
            let now = SystemClock.unix_seconds()?;
            let chain = pki::leaf(&root, &csr, "rss-mdm-agent", &[identity], now, now + 86400)?;
            let validity = pki::validity(&chain[0])?;
            let (issued, _) = service
                .seed_peer(
                    &device,
                    serde_json::from_value(json!({
                        "capabilities":["inventory.collect.v1", "task.execute.v1"],
                        "platform":"macos", "architecture":"aarch64",
                        "executionContext":software_execution::context(software_execution::Platform::MacOs)
                    }))?,
                    csr,
                    chain,
                    validity,
                )
                .await?;
            let peer = agent_tls::peer(service.trust(), &issued.chain, &root).await?;
            task_signing::acknowledge(&service, &peer).await?;
            Ok((device, issued.chain))
        })
        .await
}

async fn exercise(
    address: SocketAddr,
    agent_address: SocketAddr,
    device: &str,
    chain: &[Vec<u8>],
) -> Result<()> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("x-rss-public-origin", "https://mdm.example.test".parse()?);
    headers.insert("x-forwarded-for", "127.0.0.1".parse()?);
    let client = Client::builder()
        .no_proxy()
        .default_headers(headers)
        .timeout(Duration::from_secs(2))
        .build()?;
    let mut browser = Authority::prepared_browser("admin")?;
    browser.network = Some((client, format!("http://{address}")));
    use crate::authorization::{Grant, Permission, Scope};
    let mut grants = [
        Permission::ScopeWrite,
        Permission::ScopeRead,
        Permission::PolicyWrite,
        Permission::PolicyRead,
    ]
    .into_iter()
    .map(|operation| Grant {
        operation,
        scope: Scope::Tenant,
    })
    .collect::<Vec<_>>();
    grants.extend(identity::device_grants(
        None,
        &["inventory_read", "account_write"],
    )?);
    identity::seed_grants(case_tenant(), case_admin(), grants).await?;
    let scope = Uuid::new_v4();
    http::ok(
        &mut browser,
        &Router::new(),
        Method::POST,
        &format!("/api/v1/scopes/{scope}"),
        Some(http::request(
            0,
            json!({"action":"put","definition":{
                "targets":[{"kind":"device","id":device}],"limitations":null,"exclusions":[]
            }}),
        )),
    )
    .await?;
    loop {
        let ready = http::ok(
            &mut browser,
            &Router::new(),
            Method::GET,
            &format!("/api/v1/scopes?filter=id=={scope};ready==true"),
            None,
        )
        .await?;
        if ready["items"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let policy = Uuid::new_v4();
    // This policy has no macOS access change; only its real event membership is needed.
    http::ok(
        &mut browser,
        &Router::new(),
        Method::POST,
        &format!("/api/v1/policies/{policy}"),
        Some(http::request(
            0,
            json!({"action":"put","enabled":true,"definition":{
                "customEvent":"listener-ready","scope":scope,"action":{"kind":"device_access",
                "mac":null,"windows":{"kind":"rss_factor","accounts":["local"]},
                "selfEnrollment":false,"role":null}
            }}),
        )),
    )
    .await?;
    let path = "/api/v1/agent/runtime/policy-event-batches";
    let mut anonymous = connect_agent(agent_address, None).await?;
    let denied = agent_http(&mut anonymous, "GET", path, None)
        .await
        .context("anonymous policy event read")?;
    ensure!(
        denied.0 == 401 && denied.1["code"] == "invalid_identity",
        "anonymous Agent ingress: {denied:?}"
    );
    drop(anonymous);
    let mut peer = connect_agent(agent_address, Some(chain)).await?;
    let context = software_execution::context(software_execution::Platform::MacOs);
    let claim = agent_http(
        &mut peer,
        "POST",
        "/api/v1/agent/runtime/tasks/claim",
        Some(json!({
            "wireVersion":1,"operationId":Uuid::new_v4(),"executionContext":context,
            "environment":{"edition":null,"tools":{},"nativeEngines":{}},
            "profiles":["posix_sh","bash","power_shell7","osquery"]
        })),
    )
    .await?;
    ensure!(claim.0 == 200, "task claim: {claim:?}");
    let claim: rss_mdm_agent_wire::runtime::TaskClaimResponse = serde_json::from_value(claim.1)?;
    ensure!(claim.task().is_none(), "fixture has no pending task");
    let operation = Uuid::new_v4();
    let input = json!({"operationId":operation,"event":"listener-ready",
        "source":{"kind":"human"},"executionContext":context});
    let accepted = agent_http(
        &mut peer,
        "POST",
        "/api/v1/agent/runtime/policy-events",
        Some(input.clone()),
    )
    .await?;
    ensure!(
        accepted.0 == 202
            && accepted.1["operationId"] == operation.to_string()
            && accepted.1["members"] == 1,
        "event acceptance: {accepted:?}"
    );
    let batch = accepted.1["batchId"].as_str().context("batch identity")?;
    let list = agent_http(
        &mut peer,
        "GET",
        &format!("{path}?filter=operationId=={operation}"),
        None,
    )
    .await?;
    ensure!(
        list.0 == 200 && list.1["items"][0]["id"] == batch,
        "batch list: {list:?}"
    );
    let detail = format!("{path}/{batch}");
    let read = agent_http(&mut peer, "GET", &detail, None).await?;
    ensure!(
        read.0 == 200 && read.1["request"] == input,
        "batch detail: {read:?}"
    );
    let members = agent_http(&mut peer, "GET", &format!("{detail}/members"), None).await?;
    ensure!(members.0 == 200 && members.1["items"].as_array().is_some_and(|items|
        items.len() == 1 && items[0]["policyId"] == policy.to_string()), "batch members: {members:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=agent.listener"]
async fn production_agent_listener_reaches_readiness_and_serves_events_and_tasks() -> Result<()> {
    let (device, chain) = prepare_peer().await?;
    let mut config = identity::config(case_tenant())?;
    config.native_protocols.windows = None;
    config.native_protocols.apple = None;
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    config.listen = reservation.local_addr()?;
    drop(reservation);
    let address = config.listen;
    let agent_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let agent_address = agent_listener.local_addr()?;
    let crate::agent_pki::Config::StepCa { endpoint, .. } = &config.agent_pki else {
        anyhow::bail!("Agent PKI must be enabled");
    };
    ensure!(
        config.task_signing.is_some(),
        "task signing must be enabled"
    );
    let mut gateway = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(5))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    gateway.startup()?.stage_task_with_token(gateway::proxy(
        agent_listener,
        address,
        PathBuf::from(std::env::var("MDM_AGENT_PKI_FIXTURES")?),
        endpoint.origin.clone(),
        "agent-tls.pk8",
    )?);
    let stop = tokio_util::sync::CancellationToken::new();
    let stopped = stop.clone();
    let mut server = tokio::spawn(crate::lifecycle::serve(
        config,
        async move {
            stopped.cancelled().await;
            Ok(())
        },
        monotonic(),
    ));
    let result = std::panic::AssertUnwindSafe(async {
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()?;
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                ensure!(
                    !server.is_finished(),
                    "production Agent host exited before readiness"
                );
                let response = client
                    .get(format!("http://{address}/readyz"))
                    .header("host", "mdm.example.test")
                    .header("x-rss-public-origin", "https://mdm.example.test")
                    .header("x-forwarded-for", "127.0.0.1")
                    .send()
                    .await;
                if response.is_ok_and(|r| r.status() == StatusCode::OK) {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .context("production Agent readiness deadline")??;
        tokio::time::timeout(
            Duration::from_secs(30),
            exercise(address, agent_address, &device, &chain),
        )
        .await
        .context("production Agent route deadline")?
    })
    .catch_unwind()
    .await;
    stop.cancel();
    let shutdown = tokio::time::timeout(Duration::from_secs(65), &mut server).await;
    if shutdown.is_err() {
        server.abort();
        let _ = server.await;
    }
    let gateway_shutdown = gateway.shutdown().join().await;
    ensure!(
        gateway_shutdown?.is_clean(),
        "Agent gateway shutdown incomplete"
    );
    shutdown
        .context("production Agent shutdown deadline")??
        .map_err(|e| anyhow::anyhow!("production Agent host failed: {e:?}"))?;
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
