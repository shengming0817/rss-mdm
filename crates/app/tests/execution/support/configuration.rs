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
pub(crate) async fn resource_input(
    client: &mut Client,
    input: Value,
    secrets: &[&str],
) -> anyhow::Result<String> {
    let id = Uuid::new_v4().to_string();
    let path = format!("/api/v1/resources/{id}");
    change(
        client,
        &path,
        0,
        json!({"action":"create","kind":"configuration"}),
    )
    .await?;
    let bytes = serde_json::to_vec(&input)?;
    let sha = rss_mdm_resource::Digest::of(&bytes).bytes();
    change(client,&path,1,json!({"action":"version","version":"1","kind":"configuration","variants":[{"platform":"windows","architecture":"x86_64","key":"native","declaration":{"kind":"configuration","artifact":{"reference":"native-input","length":bytes.len(),"sha256":sha}}}]})).await?;
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
    let content_root = client
        .app
        .content_writer
        .as_ref()
        .unwrap()
        .config
        .storage
        .volume_directory()
        .unwrap()
        .join(case_tenant());
    use sqlx::Connection;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let pieces: Vec<Uuid> = sqlx::query_scalar("SELECT (piece->>'id')::uuid FROM mdm_content.manifests m CROSS JOIN LATERAL jsonb_array_elements(m.document->'value'->'pieces') piece WHERE m.tenant_id=$1::uuid AND m.class='native_configuration' AND m.sha256=$2 AND m.state='ready'")
        .bind(case_tenant()).bind(sha.as_slice()).fetch_all(&mut pg).await?;
    ensure!(
        !pieces.is_empty(),
        "current configuration has no stored content pieces"
    );
    for piece in pieces {
        let stored = std::fs::read(content_root.join(piece.to_string()))?;
        for node in secrets {
            ensure!(
                !stored
                    .windows(node.len())
                    .any(|part| part == node.as_bytes()),
                "native configuration content remained plaintext"
            );
        }
    }
    pg.close().await?;
    change(client, &path, 2, json!({"action":"activate","version":"1"})).await?;
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
