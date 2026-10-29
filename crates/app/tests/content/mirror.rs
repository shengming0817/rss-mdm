#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use super::content_pg as pg;
use crate::test_support::software::{Fixture, seed_software_version, write};
use crate::test_support::{http::*, runtime::*, *};
async fn mirror_resource(
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    definition: &Value,
    server: &publication_support::Server,
    path: &str,
    digest: &[u8],
) -> Result<(String, Uuid)> {
    let mut definition = definition.clone();
    definition["artifacts"]["package"]["length"] = json!(3);
    definition["artifacts"]["package"]["sha256"] =
        json!(rss_mdm_resource::Digest::of(digest).bytes());
    definition["artifacts"]["package"]["origin"] =
        json!(format!("{}artifacts/{path}", server.base));
    let (resource, _) = seed_software_version(runtime, definition).await?;
    let operation = Uuid::new_v4();
    Ok((
        format!(
            "/api/v1/resources/{resource}/content/mirror?version=v1&variant=default&platform=windows&architecture=x86_64&operation={operation}"
        ),
        operation,
    ))
}
async fn mirror_matrix(
    user: &mut Browser,
    router: &Router,
    definition: &Value,
    server: &publication_support::Server,
    runtime: &Arc<rss_transactional_messaging_postgres::PgRuntime>,
) -> Result<()> {
    {
        let (path, bytes) = ("wrong.msi", &b"abd"[..]);
        let (url, operation) = mirror_resource(runtime, definition, server, path, bytes).await?;
        let response = user.call(router, Method::POST, &url, None).await?;
        ensure!(
            response.0 == StatusCode::BAD_REQUEST && response.1["code"] == "malformed_request",
            "unsafe mirror succeeded: {response:?}"
        );
        ensure!(
            pg(&format!(
                "SELECT count(*) FROM mdm_content.bindings WHERE operation='{operation}'"
            ))?
            .trim()
                == "0"
        );
    }
    let (url, operation) =
        mirror_resource(runtime, definition, server, "audit.msi", b"abc").await?;
    pg(
        "REVOKE EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) FROM mdm_content_runtime",
    )?;
    let failed = user.call(router, Method::POST, &url, None).await;
    pg(
        "GRANT EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) TO mdm_content_runtime",
    )?;
    let failed = failed?;
    ensure!(
        failed.0 == StatusCode::SERVICE_UNAVAILABLE && failed.1["code"] == "service_unavailable",
        "audit failure: {failed:?}"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_content.bindings WHERE operation='{operation}'"
        ))?
        .trim()
            == "0"
    );
    ensure!(user.call(router, Method::POST, &url, None).await?.0 == StatusCode::CREATED);
    ensure!(user.call(router, Method::POST, &url, None).await?.0 == StatusCode::CREATED);
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_content.bindings WHERE operation='{operation}'"
        ))?
        .trim()
            == "1"
    );
    for revoke in [false, true] {
        let (url, operation) =
            mirror_resource(runtime, definition, server, "paused.msi", b"abc").await?;
        let started = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        server.state.lock().unwrap().artifact_pause = Some((started.clone(), resume.clone()));
        let mut client = user.clone();
        let app = router.clone();
        let request = url.clone();
        let mirror =
            tokio::spawn(async move { client.call(&app, Method::POST, &request, None).await });
        tokio::time::timeout(Duration::from_secs(10), started.notified()).await?;
        let source_path = format!("/api/v1/software/sources/{}/revisions/1", server.logical);
        if revoke {
            write(user, router, &source_path, 1, json!({"action":"disable"})).await?;
        } else {
            runtime.inject_next_transaction_fault(
                rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            );
        }
        resume.notify_one();
        let response = mirror.await??;
        if revoke {
            let persisted = pg(&format!(
                "SELECT count(*) FROM mdm_content.bindings WHERE operation='{operation}'"
            ))?;
            write(user, router, &source_path, 2, json!({"action":"enable"})).await?;
            ensure!(
                response.0 == StatusCode::FORBIDDEN && persisted.trim() == "0",
                "withdrawn origin committed mirror: {response:?}, bindings={persisted}"
            );
        } else {
            ensure!(
                response.0 == StatusCode::SERVICE_UNAVAILABLE
                    && response.1["code"] == "operation_unknown",
                "mirror lost commit: {response:?}"
            );
            ensure!(pg(&format!("SELECT count(*) FROM mdm_content.bindings WHERE tenant_id='{}' AND operation='{operation}'", case_tenant()))?.trim() == "1");
            let content_path = url.split("/mirror?").next().unwrap();
            let receipt = user
                .call(
                    router,
                    Method::GET,
                    &format!("{content_path}/operations/{operation}"),
                    None,
                )
                .await?;
            ensure!(
                receipt.0 == StatusCode::OK
                    && receipt.1["committed"] == true
                    && receipt.1["operationId"] == operation.to_string()
            );
        }
        ensure!(user.call(router, Method::POST, &url, None).await?.0 == StatusCode::CREATED);
        ensure!(
            pg(&format!(
                "SELECT count(*) FROM mdm_content.bindings WHERE operation='{operation}'"
            ))?
            .trim()
                == "1"
        );
    }
    ensure!(!server.state.lock().unwrap().artifact_auth_leaked);
    Ok(())
}
#[tokio::test]
#[ignore = "MODULE=content.mirror: controlled HTTPS and durable bindings"]
async fn mirror_transport_atomicity_and_recovery() -> Result<()> {
    let mut fixture = Fixture::open(true).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources
        .finish(async {
            let definition = publication_support::private_definition(
                fixture.registered["snapshot"].clone(),
                b"abc",
            );
            mirror_matrix(
                &mut fixture.user.clone(),
                &fixture.router,
                &definition,
                fixture.peer.as_ref().unwrap(),
                &fixture.runtime,
            )
            .await
        })
        .await
}
