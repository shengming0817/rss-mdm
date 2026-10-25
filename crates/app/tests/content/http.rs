use crate::audit_test_support::audit_count;
use crate::test_support::http::Browser;
use crate::test_support::software::{Fixture, write};
use crate::test_support::{process::*, runtime::*, *};
#[tokio::test]
#[ignore = "MODULE=content.http: real streamed HTTP, binding transactions and storage"]
async fn upload_recovery_download_range_and_authorization() -> Result<()> {
    let mut fixture = Fixture::open(false).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources
        .finish(async {
            let (admission_path, bytes, enable) =
                upload_recovery(&fixture, 2 * 1024 * 1024 + 1).await?;
            let mut user = fixture.user.clone();
            let enabled = lifecycle_contract(&fixture, &mut user, &admission_path, &enable).await?;
            let download = download_contract(&fixture, &user, &admission_path, &bytes).await?;
            let client = &fixture.client;
            let cookie = user
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            write(
                &mut user,
                &fixture.router,
                &admission_path,
                1,
                json!({"action":"withdraw"}),
            )
            .await?;
            let read = user
                .call(&fixture.router, Method::GET, &admission_path, None)
                .await?;
            ensure!(read.1["lifecycle"]["state"] == "withdrawn");
            let denied = client
                .get(&download)
                .header("host", "mdm.example.test")
                .header("cookie", &cookie)
                .send()
                .await?;
            ensure!(denied.status() == StatusCode::FORBIDDEN);
            let original = user
                .call(&fixture.router, Method::POST, &admission_path, Some(enable))
                .await?;
            ensure!(
                original.0 == StatusCode::OK && original.1 == enabled,
                "recovery preserves the historical enable receipt without granting new access"
            );
            crate::test_support::identity::change_grants(case_tenant(), &fixture.subject, vec![])
                .await?;
            ensure!(
                user.call(&fixture.router, Method::GET, &admission_path, None)
                    .await?
                    .0
                    == StatusCode::FORBIDDEN
            );
            Ok(())
        })
        .await
}
pub(super) async fn upload_recovery(
    fixture: &Fixture,
    length: usize,
) -> Result<(String, Vec<u8>, Value)> {
    let router = &fixture.router;
    let runtime = &fixture.runtime;
    let client = &fixture.client;
    let origin = &fixture.origin;
    let registered = &fixture.registered;
    let mut user = fixture.user.clone();
    let bytes = vec![7u8; length];
    let definition =
        publication_support::private_definition(registered["snapshot"].clone(), &bytes);
    let (resource, _) =
        crate::test_support::software::seed_software_version(runtime, definition).await?;
    let admission_path = format!("/api/v1/software/resources/{resource}/versions/v1");
    let enable =
        json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"enable"}});
    let absent = user
        .call(router, Method::POST, &admission_path, Some(enable.clone()))
        .await?;
    ensure!(
        absent.0 == StatusCode::BAD_REQUEST && absent.1["code"] == "malformed_request",
        "missing content: {absent:?}"
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
    Ok((admission_path, bytes, enable))
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
    pg(
        "REVOKE EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) FROM mdm_flow_runtime",
    )?;
    let failed = user
        .call(router, Method::POST, admission_path, Some(enable.clone()))
        .await?;
    pg(
        "GRANT EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) TO mdm_flow_runtime",
    )?;
    ensure!(
        failed.0 == StatusCode::SERVICE_UNAVAILABLE && failed.1["code"] == "service_unavailable",
        "audit failure: {failed:?}"
    );
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
pub(super) async fn download_contract(
    fixture: &Fixture,
    user: &Browser,
    admission_path: &str,
    bytes: &[u8],
) -> Result<String> {
    let client = &fixture.client;
    let origin = &fixture.origin;
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
    ensure!(shared_budget, "shared content budget was not enforced");
    Ok(download)
}

#[tokio::test]
#[ignore = "MODULE=content.http: corrupt uploads reject and distinct operations reuse content"]
async fn corrupt_uploads_have_no_binding_and_distinct_operations_bind_verified_content()
-> Result<()> {
    let mut fixture = Fixture::open(false).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let user = fixture.user.clone();
    let bytes = b"validated";
    let definition = publication_support::private_definition(fixture.registered["snapshot"].clone(), bytes);
    let (resource, _) = crate::test_support::software::seed_software_version(&fixture.runtime, definition).await?;
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
                && record.result() == "success").await?
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

async fn upload_resource(fixture: &Fixture, bytes: &[u8]) -> Result<Uuid> {
    let definition =
        publication_support::private_definition(fixture.registered["snapshot"].clone(), bytes);
    let (resource, _) =
        crate::test_support::software::seed_software_version(&fixture.runtime, definition).await?;
    Ok(Uuid::parse_str(&resource)?)
}
fn streaming_request(fixture: &Fixture, method: Method, path: &str) -> reqwest::RequestBuilder {
    let cookie = fixture
        .user
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    fixture
        .client
        .request(method, format!("{}{path}", fixture.origin))
        .header("host", "mdm.example.test")
        .header("origin", "https://mdm.example.test")
        .header("x-identity-request", "1")
        .header("x-csrf-token", fixture.user.csrf.as_ref().unwrap())
        .header("cookie", cookie)
        .header("content-type", "application/octet-stream")
}
async fn streaming_path(
    fixture: &Fixture,
    resource: Uuid,
    operation: Uuid,
    append: bool,
) -> Result<String> {
    let selection = "version=v1&variant=default&platform=windows&architecture=x86_64";
    if append {
        let mut user = fixture.user.clone();
        let begun = user
            .call(
                &fixture.router,
                Method::POST,
                &format!("/api/v1/resources/{resource}/uploads/{operation}?{selection}"),
                None,
            )
            .await?;
        ensure!(begun.0 == StatusCode::OK, "begin: {begun:?}");
        Ok(format!(
            "/api/v1/resources/{resource}/uploads/{operation}?offset=0"
        ))
    } else {
        Ok(format!(
            "/api/v1/resources/{resource}/content?{selection}&operation={operation}"
        ))
    }
}
#[tokio::test]
#[ignore = "MODULE=content.http: both real streaming paths exceed the old management deadline"]
async fn large_streams_use_content_budget_and_bind_exact_bytes() -> Result<()> {
    let mut fixture = Fixture::with_transfer_seconds(120).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
        let length = 16 * 1024 * 1024 + 1;
        let bytes = vec![7; length];
        let resource = upload_resource(&fixture, &bytes).await?;
        for append in [false, true] {
            let operation = Uuid::new_v4();
            let path = streaming_path(&fixture, resource, operation, append).await?;
            let stream = futures::stream::unfold(0usize, move |offset| async move {
                if offset == length { return None; }
                if offset == 0 { tokio::time::sleep(std::time::Duration::from_secs(9)).await; }
                let n = (length-offset).min(65536);
                Some((Ok::<_, std::io::Error>(vec![7u8;n]), offset+n))
            });
            let response = streaming_request(&fixture, if append { Method::PATCH } else { Method::POST }, &path)
                .body(reqwest::Body::wrap_stream(stream)).send().await?;
            let status = response.status(); let body = response.text().await?;
            ensure!(status == if append { StatusCode::OK } else { StatusCode::CREATED }, "stream: {status} {body}");
            if append {
                let completed = streaming_request(&fixture, Method::POST, &format!("/api/v1/resources/{resource}/uploads/{operation}/complete")).send().await?;
                let status = completed.status(); let body = completed.text().await?;
                ensure!(status == StatusCode::CREATED, "complete: {status} {body}");
            }
            let mut user = fixture.user.clone();
            let receipt = user.call(&fixture.router, Method::GET, &format!("/api/v1/resources/{resource}/content/operations/{operation}"), None).await?;
            ensure!(receipt.0 == StatusCode::OK && receipt.1["length"] == length);
            let digest = rss_mdm_resource::Digest::of(&bytes).bytes();
            ensure!(receipt.1["sha256"] == json!(digest.to_vec()));
            ensure!(pg(&format!("SELECT count(*) FROM mdm_content.bindings WHERE tenant_id='{}' AND operation='{operation}'",case_tenant()))?.trim() == "1");
            ensure!(audit_count(|r| r.source()=="mdm.business" && r.operation()==Some(operation.to_string().as_str()) && r.status()==201 && r.result()=="success").await? == 1);
        }
        Ok(())
    }).await
}
#[tokio::test]
#[ignore = "MODULE=content.http: content deadline releases exact leases and permits request recovery"]
async fn stalled_streams_expire_without_binding_and_release_their_leases() -> Result<()> {
    let mut fixture = Fixture::with_transfer_seconds(4).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
        let bytes = b"deadline recovery";
        let resource = upload_resource(&fixture, bytes).await?;
        for append in [false, true] {
            let operation = Uuid::new_v4();
            let path = streaming_path(&fixture, resource, operation, append).await?;
            let stream = futures::stream::pending::<Result<Vec<u8>, std::io::Error>>();
            let response = streaming_request(&fixture, if append { Method::PATCH } else { Method::POST }, &path)
                .body(reqwest::Body::wrap_stream(stream)).send().await?;
            let status = response.status(); let body: Value = response.json().await?;
            ensure!(status == StatusCode::SERVICE_UNAVAILABLE && body["code"] == "service_unavailable", "deadline: {status} {body}");
            ensure!(pg(&format!("SELECT count(*) FROM mdm_content.bindings WHERE tenant_id='{}' AND operation='{operation}'",case_tenant()))?.trim() == "0");
            ensure!(pg(&format!("SELECT count(*) FROM mdm_content.uploads WHERE tenant_id='{}' AND document->'value'->'upload'->>'id'='{operation}' AND epoch IS NULL AND held_until=0",case_tenant()))?.trim() == "1");
            let recovered = streaming_request(&fixture, if append { Method::PATCH } else { Method::POST }, &path).body(bytes.to_vec()).send().await?;
            let status = recovered.status(); let body = recovered.text().await?;
            ensure!(status == if append { StatusCode::OK } else { StatusCode::CREATED }, "recovery: {status} {body}");
        }
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=content.http: revoking rights or the browser session during streaming rejects completion"]
async fn streaming_revalidates_permission_and_original_session_before_success() -> Result<()> {
    let mut fixture = Fixture::with_transfer_seconds(60).await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
        let bytes = b"revocation-boundary";
        let resource = upload_resource(&fixture, bytes).await?;
        for revoke_session in [false, true] {
            let append = revoke_session;
            let operation = Uuid::new_v4();
            let path = streaming_path(&fixture, resource, operation, append).await?;
            use futures::SinkExt;
            let (mut sender, body) = futures::channel::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(1);
            let request = streaming_request(&fixture, if append { Method::PATCH } else { Method::POST }, &path)
                .body(reqwest::Body::wrap_stream(body));
            let request = tokio::spawn(async move { request.send().await });
            sender.send(Ok(bytes[..1].to_vec())).await?;
            // Async PG observation lets this current-thread runtime drive HTTP and DB I/O.
            let observer = sqlx::postgres::PgPoolOptions::new().max_connections(1)
                .connect_with(crate::device::test_support::options("postgres")?).await?;
            let claimed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if sqlx::query_scalar::<_,i64>("SELECT count(*) FROM mdm_content.uploads WHERE tenant_id=$1::uuid AND document->'value'->'upload'->>'id'=$2 AND epoch IS NOT NULL")
                        .bind(case_tenant()).bind(operation.to_string()).fetch_one(&observer).await? == 1 {
                        break Ok::<_,anyhow::Error>(());
                    }
                    tokio::task::yield_now().await;
                }
            }).await;
            observer.close().await;
            let changed: Result<()> = async {
                claimed??;
                if revoke_session {
                    let mut user = fixture.user.clone();
                    let logged_out = user.call(&fixture.router, Method::POST, &format!("/api/v1/identity/tenants/{}/session/logout",case_tenant()), None).await?;
                    ensure!(logged_out.0 == StatusCode::NO_CONTENT, "logout: {logged_out:?}");
                } else {
                    crate::test_support::identity::change_grants(case_tenant(), &fixture.subject, vec![]).await?;
                }
                sender.send(Ok(bytes[1..].to_vec())).await?;
                Ok(())
            }.await;
            drop(sender);
            let response = request.await?;
            changed?;
            let response = response?;
            let status = response.status(); let body = response.text().await?;
            ensure!(status == if revoke_session { StatusCode::UNAUTHORIZED } else { StatusCode::FORBIDDEN }, "revoked authority: {status} {body}");
            ensure!(pg(&format!("SELECT count(*) FROM mdm_content.bindings WHERE tenant_id='{}' AND operation='{operation}'",case_tenant()))?.trim()=="0");
            ensure!(audit_count(|r| r.source()=="mdm.business" && r.operation()==Some(operation.to_string().as_str()) && r.status()==201 && r.result()=="success").await? == 0);
            if !revoke_session {
                let grants = [crate::authorization::Permission::ResourceRead, crate::authorization::Permission::ResourceWrite]
                    .into_iter().map(|operation| crate::authorization::Grant {operation, scope:crate::authorization::Scope::Tenant}).collect();
                crate::test_support::identity::change_grants(case_tenant(), &fixture.subject, grants).await?;
            }
        }
        Ok(())
    }).await
}
