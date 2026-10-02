use crate::test_support::software::{Fixture, write};
use crate::test_support::*;
#[tokio::test]
#[ignore = "MODULE=content.http: real streamed HTTP, binding transactions and files"]
async fn upload_recovery_download_range_and_authorization() -> Result<()> {
    let fixture = Fixture::open(false).await?;
    let router = &fixture.router;
    let runtime = &fixture.runtime;
    let client = &fixture.client;
    let origin = &fixture.origin;
    let subject = &fixture.subject;
    let registered = &fixture.registered;
    let mut user = fixture.user.clone();
    let resource = Uuid::new_v4();
    let resource_path = format!("/api/v4/resources/{resource}");
    write(
        &mut user,
        router,
        &resource_path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    let bytes = vec![7u8; 16_777_217];
    let digest = rss_mdm_resource::Digest::of(&bytes).bytes();
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
    let admission_path = format!("/api/v3/software/resources/{resource}/versions/v1");
    let approve = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"approve","evidence":["package-review"]}});
    ensure!(
        user.call(router, Method::POST, &admission_path, Some(approve.clone()))
            .await?
            .0
            .is_client_error()
    );
    let operation = Uuid::new_v4();
    let upload_path = format!(
        "{origin}/api/v3/resources/{resource}/content?version=v1&variant=default&platform=windows&architecture=x86_64&operation={operation}"
    );
    let cookie = user
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let length = bytes.len();
    let fault_runtime = runtime.clone();
    let stream = futures::stream::unfold(
        (0usize, fault_runtime),
        move |(position, runtime)| async move {
            if position >= length {
                runtime.inject_next_transaction_fault(
                    rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
                );
                None
            } else {
                let n = (length - position).min(65536);
                Some((
                    Ok::<_, std::io::Error>(vec![7u8; n]),
                    (position + n, runtime),
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
        status == StatusCode::SERVICE_UNAVAILABLE,
        "lost upload commit: {status} {body}"
    );
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
            &format!("/api/v3/resources/{resource}/content/operations/{operation}"),
            None,
        )
        .await?;
    ensure!(
        receipt.0 == StatusCode::OK
            && receipt.1["committed"] == true
            && receipt.1["operationId"] == operation.to_string()
    );
    // The content owner is independently usable without task-signing configuration.
    let denied=user.call(router,Method::POST,&admission_path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"approve","evidence":[]}}))).await?;
    ensure!(denied.0 == StatusCode::BAD_REQUEST);
    pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_flow_runtime")?;
    let failed = user
        .call(router, Method::POST, &admission_path, Some(approve.clone()))
        .await?;
    pg("GRANT INSERT ON mdm_audit.receipts TO mdm_flow_runtime")?;
    ensure!(failed.0.is_server_error(), "audit failure: {failed:?}");
    let before = user
        .call(router, Method::GET, &admission_path, None)
        .await?;
    ensure!(
        before.0 == StatusCode::OK && before.1["admission"].is_null(),
        "rollback: {before:?}"
    );
    let approved = user
        .call(router, Method::POST, &admission_path, Some(approve.clone()))
        .await?;
    ensure!(approved.0 == StatusCode::OK, "approve: {approved:?}");
    let replay = user
        .call(router, Method::POST, &admission_path, Some(approve.clone()))
        .await?;
    ensure!(replay.0 == StatusCode::OK && replay.1 == approved.1);
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
        .header("Range", "bytes=16777210-")
        .send()
        .await?;
    ensure!(
        partial.status() == StatusCode::PARTIAL_CONTENT
            && partial.bytes().await?.as_ref() == &bytes[16777210..]
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
        &mut user,
        router,
        &admission_path,
        1,
        json!({"action":"withdraw","evidence":["withdrawal"]}),
    )
    .await?;
    let read = user
        .call(router, Method::GET, &admission_path, None)
        .await?;
    ensure!(read.1["admission"]["state"] == "withdrawn");
    let denied = client
        .get(&download)
        .header("host", "mdm.example.test")
        .header("cookie", &cookie)
        .send()
        .await?;
    ensure!(denied.status() == StatusCode::FORBIDDEN);
    let original = user
        .call(router, Method::POST, &admission_path, Some(approve))
        .await?;
    ensure!(
        original.0 == StatusCode::OK && original.1 == approved.1,
        "recovery preserves historical approval, not a new grant"
    );
    crate::test_support::identity::set_grants(case_tenant(), subject, vec![]).await?;
    ensure!(
        user.call(router, Method::GET, &admission_path, None)
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
    let fixture = Fixture::open(false).await?;
    let mut user = fixture.user.clone();
    let router = &fixture.router;
    let resource = Uuid::new_v4();
    let path = format!("/api/v4/resources/{resource}");
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
        let response = fixture.client.post(format!("{}/api/v3/resources/{resource}/content?version=v1&variant=default&platform=windows&architecture=x86_64&operation={operation}", fixture.origin))
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
            let directory = fixture.directory.join(case_tenant());
            let _directory = lock_upload_fixture(&directory.join(".upload.lock"))?;
            let metadata = super::upload_metadata(&directory, operation)?;
            let _session = lock_upload_fixture(&metadata.with_extension("part"))?;
            for extension in ["json", "next", "part"] {
                match std::fs::remove_file(metadata.with_extension(extension)) {
                    Ok(()) => (),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    ensure!(pg(&format!("SELECT count(*) FROM mdm_content.bindings WHERE tenant_id='{TENANT}' AND resource='{resource}'", TENANT = case_tenant()))?.trim() == "2");
    Ok(())
}

// Match the filesystem lock protocol while cleaning this test's rejected resumable upload.
fn lock_upload_fixture(path: &std::path::Path) -> anyhow::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    anyhow::ensure!(file.metadata()?.is_file());
    file.try_lock()?;
    Ok(file)
}
