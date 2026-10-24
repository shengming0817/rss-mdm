use crate::audit_test_support::audit_count;
use crate::test_support::agent_execution::*;
use crate::test_support::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.content"]
async fn task_content_range_and_attempt_authorization() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources
        .finish(async {
            fixture.register().await?;
            let (id, bytes, _definition) = fixture.resource().await?;
            fixture
                .scope(
                    case_task_scope(),
                    json!([{"kind":"device","id":case_device_id()}]),
                )
                .await?;
            let stack = crate::test_support::software_execution::worker(&fixture.base, fixture.execution.clone()).await?;
            let router = fixture.router;
            let mut author = fixture.author;
            let _policy = publish(&mut author, &router, id).await?;
            let task = claim(&router).await?;
            let expected = bytes;
            let path = format!(
                "/api/v1/agent/runtime/tasks/{}/content?attempt={}",
                task["payload"]["task"]["taskId"].as_str().unwrap(),
                task["payload"]["task"]["attemptId"].as_str().unwrap()
            );
            for (range, if_range, status, bytes) in [
                (
                    "bytes=0-3",
                    None,
                    StatusCode::PARTIAL_CONTENT,
                    &expected[..4],
                ),
                ("bytes=0-3", Some("\"different\""), StatusCode::OK, expected),
                (
                    "bytes=999999-",
                    None,
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    &[][..],
                ),
            ] {
                let mut request = Request::builder()
                    .uri(&path)
                    .header("host", "mdm.example.test:9445")
                    .extension(
                        crate::test_support::agent::evidence(case_credential())
                            .expect("registered TLS peer"),
                    )
                    .header("range", range);
                if let Some(tag) = if_range {
                    request = request.header("if-range", tag);
                }
                let response = router.clone().oneshot(request.body(Body::empty())?).await?;
                ensure!(
                    response.status() == status,
                    "range {range}: {}",
                    response.status()
                );
                let request_id = response.headers()["x-request-id"].to_str()?;
                ensure!(
                    audit_count(|record| record.request() == Some(request_id)
                        && record.source() == "mdm.request"
                        && record.status() == status.as_u16()
                        && record.result()
                            == if status.is_success() {
                                "success"
                            } else {
                                "failed"
                            })
                    .await?
                        == 1
                );
                ensure!(audit_count(|record| record.request() == Some(request_id)).await? == 1);
                if status.is_success() {
                    ensure!(response.headers().contains_key("etag"));
                    ensure!(response.into_body().collect().await?.to_bytes().as_ref() == bytes);
                }
            }
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(&path)
                        .header("host", "mdm.example.test:9445")
                        .extension(
                            crate::test_support::agent::evidence(case_credential())
                                .expect("registered TLS peer"),
                        )
                        .header("range", "bytes=0-3")
                        .header("range", "bytes=4-7")
                        .body(Body::empty())?,
                )
                .await?;
            ensure!(response.status() == StatusCode::BAD_REQUEST);
            let request_id = response.headers()["x-request-id"].to_str()?;
            ensure!(
                audit_count(|record| record.request() == Some(request_id)
                    && record.status() == 400
                    && record.result() == "failed")
                .await?
                    == 1
            );
            let wrong = path.replace(
                task["payload"]["task"]["attemptId"].as_str().unwrap(),
                &Uuid::new_v4().to_string(),
            );
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(wrong)
                        .header("host", "mdm.example.test:9445")
                        .extension(
                            crate::test_support::agent::evidence(case_credential())
                                .expect("registered TLS peer"),
                        )
                        .body(Body::empty())?,
                )
                .await?;
            ensure!(response.status() == StatusCode::FORBIDDEN);
            crate::test_support::runtime::stop_worker(stack).await?;
            Ok(())
        })
        .await
}
