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
    let path = format!("/api/v4/resources/{id}");
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
        "/api/v3/resources/{id}/content?version=1&variant=native&platform=windows&architecture=x86_64&operation={}",
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
        .directory
        .join(case_tenant());
    for entry in std::fs::read_dir(content_root)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let stored = std::fs::read(entry.path())?;
            for node in secrets {
                ensure!(
                    !stored
                        .windows(node.len())
                        .any(|part| part == node.as_bytes()),
                    "native configuration content remained plaintext"
                );
            }
        }
    }
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
                    &format!("/api/v3/policies/{policy}/devices"),
                    None,
                )
                .await?;
            ensure!(page.0 == StatusCode::OK, "configuration devices: {page:?}");
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
    .await?
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
                    &format!("/api/v3/policies/{policy}/devices"),
                    None,
                )
                .await?;
            ensure!(read.0 == StatusCode::OK);
            if read.1["items"][0]["diagnoses"]
                .as_array()
                .is_some_and(|d| d.iter().any(|value| value == expected))
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("Policy {policy} did not report {expected}"))?
}
