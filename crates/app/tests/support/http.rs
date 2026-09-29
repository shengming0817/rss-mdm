use super::*;
use uuid::Uuid;
pub(crate) fn request(revision: u64, input: Value) -> Value {
    json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input})
}
pub(crate) async fn ok(
    browser: &mut Browser,
    router: &Router,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let query = method == Method::POST && path == "/api/v2/device-queries";
    let saved = method == Method::POST && path.ends_with("/execute");
    let body = if query || saved {
        Some(request(
            if saved { 1 } else { 0 },
            body.unwrap_or_else(|| json!({})),
        ))
    } else {
        body
    };
    let (s, v) = browser.call(router, method, path, body).await?;
    ensure!(
        s == StatusCode::OK || s == StatusCode::ACCEPTED,
        "asset request {path}: {s} {v}"
    );
    if query || saved {
        ensure!(s == StatusCode::ACCEPTED, "query must be asynchronous");
        let status = v["asset"]["statusUrl"].as_str().unwrap();
        await_task(browser, router, status).await?;
        let (s, page) = browser
            .call(router, Method::GET, &format!("{status}/items"), None)
            .await?;
        ensure!(s == StatusCode::OK, "query result: {s} {page}");
        return Ok(page);
    }
    if let Some(task) = v["task"].as_str() {
        let status = if let Some(url) = v["statusUrl"].as_str() {
            url.to_owned()
        } else {
            format!("{path}/tasks/{task}")
        };
        await_task(browser, router, &status).await?;
    }
    Ok(v)
}
