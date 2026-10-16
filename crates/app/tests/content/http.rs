use crate::test_support::software::{Fixture, write};
use crate::test_support::*;
#[tokio::test]
#[ignore = "MODULE=content.http: real streamed HTTP, binding transactions and storage"]
async fn upload_recovery_download_range_and_authorization() -> Result<()> {
    // Exceed the default HTTP body limit while keeping fault recovery within the host budget.
    // Large storage pieces have independent provider coverage.
    upload_contract(Fixture::open(false).await?, 2 * 1024 * 1024 + 1).await
}
pub(super) async fn upload_contract(mut fixture: Fixture, length: usize) -> Result<()> {
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let router = &fixture.router;
    let runtime = &fixture.runtime;
    let client = &fixture.client;
    let origin = &fixture.origin;
    let registered = &fixture.registered;
    let mut user = fixture.user.clone();
    let resource = Uuid::new_v4();
    let resource_path = format!("/api/v1/resources/{resource}");
    write(
        &mut user,
        router,
        &resource_path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    let bytes = vec![7u8; length];
    let definition =
        publication_support::private_definition(registered["snapshot"].clone(), &bytes);
    write(&mut user,router,&resource_path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":"windows","architecture":"x86_64","key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
    write(
        &mut user,
        router,
        &resource_path,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let admission_path = format!("/api/v1/software/resources/{resource}/versions/v1");
    let enable =
        json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"enable"}});
    ensure!(
        user.call(router, Method::POST, &admission_path, Some(enable.clone()))
            .await?
            .0
            .is_client_error()
    );
    let operation = Uuid::new_v4();
    let upload_path = format!(
        "{origin}/api/v1/resources/{resource}/content?version=v1&variant=default&platform=windows&architecture=x86_64&operation={operation}"
    );
    let cookie = user
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let length = bytes.len();
    let fault_runtime = runtime.clone();
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(crate::device::test_support::options("postgres")?)
        .await?;
    let settlement_observer = observer.clone();
    let stream = futures::stream::unfold(
        (0usize, fault_runtime, observer),
        move |(position, runtime, observer)| async move {
            if position >= length {
                inject_after_upload_intent(&observer, &runtime, operation)
                    .await
                    .expect("upload preflight settled before commit fault");
                None
            } else {
                let n = (length - position).min(65536);
                Some((
                    Ok::<_, std::io::Error>(vec![7u8; n]),
                    (position + n, runtime, observer),
                ))
            }
        },
    );
    let response = client
        .post(&upload_path)
        .header("host", "mdm.example.test")
        .header("origin", "https://mdm.example.test")
        .header("x-identity-request", "1")
        .header("x-csrf-token", user.csrf.as_ref().unwrap())
        .header("cookie", &cookie)
        .header("content-type", "application/octet-stream")
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    ensure!(
        status == StatusCode::SERVICE_UNAVAILABLE
            && serde_json::from_str::<Value>(&body)?["code"] == "operation_unknown",
        "lost upload commit: {status} {body}"
    );
    let committed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_content.bindings WHERE tenant_id=$1::uuid AND operation=$2)")
        .bind(case_tenant()).bind(operation).fetch_one(&settlement_observer).await?;
    ensure!(
        committed,
        "upload 503 preceded the committed binding; expected commit acknowledgement loss"
    );
    settlement_observer.close().await;
    let recovered = client
        .post(&upload_path)
        .header("host", "mdm.example.test")
        .header("origin", "https://mdm.example.test")
        .header("x-identity-request", "1")
        .header("x-csrf-token", user.csrf.as_ref().unwrap())
        .header("cookie", &cookie)
        .header("content-type", "application/octet-stream")
        .body(Vec::new())
        .send()
        .await?;
    let status = recovered.status();
    let body = recovered.text().await?;
    ensure!(
        status == StatusCode::CREATED,
        "upload recovery: {status} {body}"
    );
    let receipt = user
        .call(
            router,
            Method::GET,
            &format!("/api/v1/resources/{resource}/content/operations/{operation}"),
            None,
        )
        .await?;
    ensure!(
        receipt.0 == StatusCode::OK
            && receipt.1["committed"] == true
            && receipt.1["operationId"] == operation.to_string()
    );
    let enabled = lifecycle_contract(&fixture, &mut user, &admission_path, &enable).await?;
    download_contract(
        &fixture,
        &mut user,
        &admission_path,
        &bytes,
        enable,
        enabled,
    )
    .await
    }).await
}
// Client EOF can precede the server's authorization/preflight transaction. Wait for
// its committed upload intent so the injected runtime fault belongs to final binding.
async fn inject_after_upload_intent(
    observer: &sqlx::PgPool,
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    operation: Uuid,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let ready: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM mdm_content.uploads WHERE tenant_id=$1::uuid AND document->'value'->'upload'->>'id'=$2)",
            )
            .bind(case_tenant())
            .bind(operation.to_string())
            .fetch_one(observer)
            .await?;
            if ready {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    runtime.inject_next_transaction_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    Ok(())
}
async fn lifecycle_contract(
    fixture: &Fixture,
    user: &mut Browser,
    admission_path: &str,
    enable: &Value,
) -> Result<Value> {
    let router = &fixture.router;
    // The content owner is independently usable without task-signing configuration.
    pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_flow_runtime")?;
    let failed = user
        .call(router, Method::POST, admission_path, Some(enable.clone()))
        .await?;
    pg("GRANT INSERT ON mdm_audit.receipts TO mdm_flow_runtime")?;
    ensure!(failed.0.is_server_error(), "audit failure: {failed:?}");
    let before = user.call(router, Method::GET, admission_path, None).await?;
    ensure!(
        before.0 == StatusCode::OK && before.1["lifecycle"].is_null(),
        "rollback: {before:?}"
    );
    let enabled = user
        .call(router, Method::POST, admission_path, Some(enable.clone()))
        .await?;
    ensure!(enabled.0 == StatusCode::OK, "enable: {enabled:?}");
    let replay = user
        .call(router, Method::POST, admission_path, Some(enable.clone()))
        .await?;
    ensure!(replay.0 == StatusCode::OK && replay.1 == enabled.1);
    Ok(enabled.1)
}
async fn download_contract(
    fixture: &Fixture,
    user: &mut Browser,
    admission_path: &str,
    bytes: &[u8],
    enable: Value,
    enabled: Value,
) -> Result<()> {
    let router = &fixture.router;
    let client = &fixture.client;
    let origin = &fixture.origin;
    let subject = &fixture.subject;
    let cookie = user
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let digest = rss_mdm_resource::Digest::of(bytes).bytes();
    let download = format!(
        "{origin}{admission_path}/content?platform=windows&architecture=x86_64&variant=default"
    );
    let store = fixture.content.as_ref().expect("configured content");
    let artifact = rss_mdm_resource::Artifact::new(
        rss_mdm_resource::Id::new("installer")?,
        bytes.len() as u64,
        rss_mdm_resource::Digest::from_bytes(digest),
    )?;
    let mut pinned = Vec::new();
    for _ in 0..4 {
        pinned.push(store.verify(&artifact).await?);
    }
    let exhausted = client
        .get(&download)
        .header("host", "mdm.example.test")
        .header("cookie", &cookie)
        .send()
        .await?;
    let exhausted_status = exhausted.status();
    drop(exhausted);
    drop(pinned);
    let shared_budget = exhausted_status == StatusCode::CONFLICT;
    let response = client
        .get(&download)
        .header("host", "mdm.example.test")
        .header("cookie", &cookie)
        .send()
        .await?;
    ensure!(response.status() == StatusCode::OK);
    ensure!(response.bytes().await?.as_ref() == bytes);
    let partial = client
        .get(&download)
        .header("host", "mdm.example.test")
        .header("cookie", &cookie)
        .header("Range", format!("bytes={}-", bytes.len() - 7))
        .send()
        .await?;
    ensure!(
        partial.status() == StatusCode::PARTIAL_CONTENT
            && partial.bytes().await?.as_ref() == &bytes[bytes.len() - 7..]
    );
    let rejected = client
        .get(&download)
        .header("host", "mdm.example.test")
        .header("cookie", &cookie)
        .header("Range", "bytes=99999999-")
        .send()
        .await?;
    ensure!(rejected.status() == StatusCode::RANGE_NOT_SATISFIABLE);
    write(
        user,
        router,
        admission_path,
        1,
        json!({"action":"withdraw"}),
    )
    .await?;
    let read = user.call(router, Method::GET, admission_path, None).await?;
    ensure!(read.1["lifecycle"]["state"] == "withdrawn");
    let denied = client
        .get(&download)
        .header("host", "mdm.example.test")
        .header("cookie", &cookie)
        .send()
        .await?;
    ensure!(denied.status() == StatusCode::FORBIDDEN);
    let original = user
        .call(router, Method::POST, admission_path, Some(enable))
        .await?;
    ensure!(
        original.0 == StatusCode::OK && original.1 == enabled,
        "recovery preserves the historical enable receipt without granting new access"
    );
    crate::test_support::identity::set_grants(case_tenant(), subject, vec![]).await?;
    ensure!(
        user.call(router, Method::GET, admission_path, None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(shared_budget, "shared content budget was not enforced");
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=content.http: corrupt uploads reject and distinct operations reuse content"]
async fn corrupt_uploads_have_no_binding_and_new_operations_reuse_verified_content() -> Result<()> {
    let mut fixture = Fixture::open(false).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let mut user = fixture.user.clone();
    let router = &fixture.router;
    let resource = Uuid::new_v4();
    let path = format!("/api/v1/resources/{resource}");
    let bytes = b"validated";
    write(
        &mut user,
        router,
        &path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    let definition =
        publication_support::private_definition(fixture.registered["snapshot"].clone(), bytes);
    write(&mut user,router,&path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":"windows","architecture":"x86_64","key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
    write(
        &mut user,
        router,
        &path,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let cookie = user
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    for (body, expected) in [
        (b"bad value".as_slice(), StatusCode::BAD_REQUEST),
        (b"x".as_slice(), StatusCode::BAD_REQUEST),
        (bytes.as_slice(), StatusCode::CREATED),
        (bytes.as_slice(), StatusCode::CREATED),
    ] {
        let operation = Uuid::new_v4();
        let response = fixture.client.post(format!("{}/api/v1/resources/{resource}/content?version=v1&variant=default&platform=windows&architecture=x86_64&operation={operation}", fixture.origin))
            .header("host","mdm.example.test").header("origin","https://mdm.example.test")
            .header("x-identity-request","1").header("x-csrf-token",user.csrf.as_ref().unwrap())
            .header("cookie",&cookie).header("content-type","application/octet-stream")
            .body(body.to_vec()).send().await?;
        ensure!(
            response.status() == expected,
            "upload: {} {}",
            response.status(),
            response.text().await?
        );
        let count = pg(&format!(
            "SELECT count(*) FROM mdm_content.bindings WHERE tenant_id='{TENANT}' AND operation='{operation}'",
            TENANT = case_tenant()
        ))?;
        let expected_count = usize::from(expected == StatusCode::CREATED);
        ensure!(count.trim() == expected_count.to_string());
        ensure!(
            audit_count(|record| record.source() == "mdm.business"
                && record.operation() == Some(operation.to_string().as_str())
                && record.status() == 201
                && record.result() == "success")?
                == expected_count
        );
        if expected == StatusCode::BAD_REQUEST {
            // Rejected bodies remain resumable and reserve tenant upload capacity.
            // Retire only this case's finished negative request, retaining successful
            // content/bindings and every other case's active upload.
            super::expire_upload(operation)?;
            fixture
                .content
                .as_ref()
                .unwrap()
                .garbage(crate::windows::test_support::now())
                .await?;
        }
    }
    ensure!(pg(&format!("SELECT count(*) FROM mdm_content.bindings WHERE tenant_id='{TENANT}' AND resource='{resource}'", TENANT = case_tenant()))?.trim() == "2");
    Ok(())
    }).await
}
