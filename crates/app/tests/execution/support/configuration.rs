//! Shared real Resource/Policy HTTP preparation and bounded query waits.
use super::*;
use axum::{body::Body, http::Request};
use tower::ServiceExt;
pub(crate) async fn change(
    client: &mut Client,
    path: &str,
    revision: u64,
    input: Value,
) -> anyhow::Result<Value> {
    let reply = client
        .browser
        .call(
            &client.router,
            Method::POST,
            path,
            Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input})),
        )
        .await?;
    ensure!(
        reply.0 == StatusCode::OK,
        "configuration write {path}: {reply:?}"
    );
    Ok(reply.1)
}
pub(crate) async fn resource_input(client: &mut Client, input: Value) -> anyhow::Result<String> {
    let id = Uuid::new_v4().to_string();
    let bytes = serde_json::to_vec(&input)?;
    let sha = rss_mdm_resource::Digest::of(&bytes).bytes();
    let version: rss_mdm_resource::Version = rss_mdm_resource::Version::new(
        client.app.identity.tenant,
        rss_mdm_resource::Id::new(id.clone())?,
        rss_mdm_resource::Id::new("1")?,
        rss_mdm_resource::Kind::Configuration,
        vec![rss_mdm_resource::Variant::new(
            rss_mdm_resource::Platform::Windows,
            rss_mdm_resource::Architecture::X86_64,
            rss_mdm_resource::Id::new("native")?,
            rss_mdm_resource::Declaration::Configuration {
                artifact: rss_mdm_resource::Artifact::new(
                    rss_mdm_resource::Id::new("native-input")?,
                    bytes.len() as u64,
                    rss_mdm_resource::Digest::from_bytes(sha),
                )?,
            },
        )],
    )?;
    client
        .app
        .flow
        .planning
        .runtime
        .local_tx(
            client.app.identity.tenant,
            crate::identity::deadline(),
            move |tx| {
                Box::pin(async move {
                    rss_mdm_resource_postgres::fixture::active_version_in(
                        tx,
                        version,
                        rss_contract::Timepoint::try_from(1_i64).expect("fixture time"),
                    )
                    .await
                })
            },
        )
        .await
        .fold(
            Ok,
            |e| Err(anyhow::anyhow!(e)),
            |e| Err(anyhow::anyhow!(e)),
            |_| Err(anyhow::anyhow!("resource rollback unknown")),
            |_| Err(anyhow::anyhow!("resource commit unknown")),
            |e| Err(anyhow::anyhow!(e)),
        )?;
    let upload = format!(
        "/api/v1/resources/{id}/content?version=1&variant=native&platform=windows&architecture=x86_64&operation={}",
        Uuid::new_v4()
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri(upload)
        .header("host", "mdm.example.test")
        .header("origin", "https://mdm.example.test")
        .header("x-identity-request", "1")
        .header("x-csrf-token", client.browser.csrf.as_ref().unwrap())
        .header(
            "cookie",
            client
                .browser
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
        .header("content-type", "application/octet-stream")
        .body(Body::from(bytes))?;
    let response = client.router.clone().oneshot(request).await?;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 65536).await?;
    ensure!(
        status == StatusCode::CREATED,
        "configuration artifact upload: {status} {}",
        String::from_utf8_lossy(&body)
    );
    Ok(id)
}
pub(crate) async fn published(client: &mut Client, policy: Uuid) -> anyhow::Result<Vec<Uuid>> {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let page = client
                .browser
                .call(
                    &client.router,
                    Method::GET,
                    &format!("/api/v1/policies/{policy}/assignments"),
                    None,
                )
                .await?;
            ensure!(page.0 == StatusCode::OK, "configuration assignments: {page:?}");
            let ids: Vec<Uuid> = page.1["items"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|d| d["operationIds"].as_array().unwrap())
                .map(|id| Uuid::parse_str(id.as_str().unwrap()))
                .collect::<std::result::Result<_, _>>()?;
            if !ids.is_empty() {
                let mut ready = true;
                for id in &ids {
                    let read = client.call(Method::GET, &format!("/{id}"), None).await?;
                    ensure!(
                        !matches!(read.1["commandStatus"].as_str(), Some("cancelled" | "rejected" | "timed_out" | "superseded")),
                        "configuration operation {id} terminated before publication: status={}, failure={}",
                        read.1["commandStatus"], read.1["dispatchFailure"]
                    );
                    ready &= read.1["commandStatus"] == "published";
                }
                if ready {
                    return Ok::<_, anyhow::Error>(ids);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await.map_err(|error| {
        let evidence=crate::test_support::pg(&format!("SELECT jsonb_build_object('assignments',(SELECT jsonb_agg(to_jsonb(a)) FROM mdm_planning.policy_assignments a WHERE a.tenant_id='{tenant}' AND a.policy='{policy}'),'scope',(SELECT to_jsonb(s) FROM mdm_planning.scopes s JOIN mdm_policy.policies p ON(p.tenant_id,p.definition->>'scope')=(s.tenant_id,s.id::text) WHERE p.tenant_id='{tenant}' AND p.id='{policy}'),'admission',(SELECT mdm_planning.scope_admission((p.definition->>'scope')::uuid,NULL) FROM mdm_policy.policies p WHERE p.tenant_id='{tenant}' AND p.id='{policy}'),'runs',(SELECT jsonb_agg(to_jsonb(r)) FROM mdm_planning.scope_runs r WHERE r.tenant_id='{tenant}'),'sourceHeads',(SELECT jsonb_agg(to_jsonb(h)) FROM mdm_planning.source_heads h WHERE h.tenant_id='{tenant}'),'members',(SELECT jsonb_agg(to_jsonb(m)) FROM mdm_planning.scope_source_members m WHERE m.tenant_id='{tenant}'),'claims',(SELECT jsonb_agg(to_jsonb(c)) FROM mdm_planning.configuration_claims c WHERE c.tenant_id='{tenant}' AND c.policy='{policy}'),'objects',(SELECT jsonb_agg(to_jsonb(o)) FROM mdm_planning.configuration_objects o WHERE o.tenant_id='{tenant}'),'jobs',(SELECT jsonb_agg(jsonb_build_object('kind',j.kind,'target',j.target,'done',j.completed,'failure',j.failure,'detail',j.failure_detail)) FROM mdm_automation.automation_jobs j WHERE j.tenant_id='{tenant}'))",tenant=case_tenant())).unwrap_or_else(|_| "diagnostic unavailable".into());
        anyhow::anyhow!("publication wait: {error}; {evidence}")
    })?
}
pub(crate) async fn wait_diagnosis(
    client: &mut Client,
    policy: Uuid,
    expected: &str,
) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let read = client
                .browser
                .call(
                    &client.router,
                    Method::GET,
                    &format!("/api/v1/policies/{policy}/assignments"),
                    None,
                )
                .await?;
            ensure!(read.0 == StatusCode::OK);
            if read.1["items"][0]["reason"] == expected {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("Policy {policy} did not report {expected}"))?
}
