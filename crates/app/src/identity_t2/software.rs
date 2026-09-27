//! Real TCP/PG/filesystem enterprise admission; no external publication or task signer required.
use super::*;
use uuid::Uuid;
struct Server(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn write(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    revision: u64,
    input: Value,
) -> Result<Value> {
    let body = json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input});
    let response = browser.call(router, Method::POST, path, Some(body)).await?;
    ensure!(response.0 == StatusCode::OK, "{path}: {response:?}");
    Ok(response.1)
}
#[tokio::test]
#[ignore = "make t2 SUITE=software: real product TCP, TLS PostgreSQL and files"]
async fn enterprise_catalog_content_and_atomic_admission() -> Result<()> {
    let origin_server = publication_support::Server::new().await;
    let directory = tempfile::tempdir()?;
    let mut base: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    base["content"] = json!({"directory":directory.path(),"imports":{},"max_artifact_bytes":33554432,"max_temporary_bytes":67108864,"max_uploads":4,"transfer_seconds":60,"retention_seconds":3600,"max_bundle_bytes":67108864,"max_bundle_entries":100,"max_expansion_ratio":100});
    base["content"]["imports"][&origin_server.logical] = json!([{"base":format!("{}artifacts/",origin_server.base),"addresses":[origin_server.address],"private_ca":origin_server.ca}]);
    let (router, execution, runtime) = crate::api::application_fixture(
        serde_json::from_value(base.clone())?,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        database(&base).await?,
        None,
        database(&base)
            .await?
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    )
    .await?;
    let storage_admission = software_admission_rejects_drift(&runtime).await;
    let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
        "127.0.0.1".parse()?,
    )));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let hosted = router.clone();
    let _server = Server(tokio::spawn(
        async move { axum::serve(listener, hosted).await },
    ));
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let origin = format!("http://{address}");
    let mut user = Browser {
        network: Some((client.clone(), origin.clone())),
        ..Browser::default()
    };
    ensure!(user.login(&router, "admin").await? == StatusCode::OK);
    let subject = browser_subject(&user, &router).await?;
    let grants = [
        "resource_read",
        "resource_write",
        "software_read",
        "software_write",
        "software_approve",
        "software_withdraw",
    ]
    .into_iter()
    .map(|s| {
        Ok(crate::authorization::Grant {
            operation: serde_json::from_value(json!(s))?,
            scope: crate::authorization::Scope::Tenant,
        })
    })
    .collect::<Result<Vec<_>>>()?;
    crate::identity_fixture::set_grants(TENANT, &subject, grants).await?;
    let source = origin_server.logical.clone();
    let source_path = format!("/api/v3/software/sources/{source}/revisions/1");
    let registered=write(&mut user,&router,&source_path,0,json!({"action":"register","definition":{"id":source,"revision":"1","kind":"private","location":null,"publishers":[]}})).await?;
    write(
        &mut user,
        &router,
        &source_path,
        1,
        json!({"action":"approve","evidence":["source-review"]}),
    )
    .await?;
    let resource = Uuid::new_v4();
    let resource_path = format!("/api/v3/resources/{resource}");
    write(
        &mut user,
        &router,
        &resource_path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    let bytes = vec![7u8; 16_777_217];
    let digest = rss_mdm_resource::Digest::of(&bytes).bytes();
    let definition = json!({"source":registered["snapshot"],"package":"Acme.Private","version":"1+enterprise","format":"msi","primary":"package","artifacts":{"package":{"reference":"installer","length":bytes.len(),"sha256":digest}},"install":{"executor":"msi","entry":null,"runAs":"system","arguments":["/qn"],"environment":{},"timeoutSeconds":600,"outputBytes":4096},"uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1+enterprise"},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"bundle":null});
    write(&mut user,&router,&resource_path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":"windows","architecture":"x86_64","key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
    write(
        &mut user,
        &router,
        &resource_path,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let admission_path = format!("/api/v3/software/resources/{resource}/versions/v1");
    let approve = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"approve","evidence":["package-review"]}});
    ensure!(
        user.call(
            &router,
            Method::POST,
            &admission_path,
            Some(approve.clone())
        )
        .await?
        .0
        .is_client_error()
    );
    let operation = Uuid::new_v4();
    let upload_path = format!(
        "{origin}{resource_path}/content?version=v1&variant=default&platform=windows&architecture=x86_64&operation={operation}"
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
            &router,
            Method::GET,
            &format!("{resource_path}/content/operations/{operation}"),
            None,
        )
        .await?;
    ensure!(
        receipt.0 == StatusCode::OK
            && receipt.1["committed"] == true
            && receipt.1["operationId"] == operation.to_string()
    );
    // The content owner is independently usable without task-signing configuration.
    let denied=user.call(&router,Method::POST,&admission_path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"approve","evidence":[]}}))).await?;
    ensure!(denied.0 == StatusCode::BAD_REQUEST);
    pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_flow_runtime")?;
    let failed = user
        .call(
            &router,
            Method::POST,
            &admission_path,
            Some(approve.clone()),
        )
        .await?;
    pg("GRANT INSERT ON mdm_audit.receipts TO mdm_flow_runtime")?;
    ensure!(failed.0.is_server_error(), "audit failure: {failed:?}");
    let before = user
        .call(&router, Method::GET, &admission_path, None)
        .await?;
    ensure!(
        before.0 == StatusCode::OK && before.1["admission"].is_null(),
        "rollback: {before:?}"
    );
    let approved = user
        .call(
            &router,
            Method::POST,
            &admission_path,
            Some(approve.clone()),
        )
        .await?;
    ensure!(approved.0 == StatusCode::OK, "approve: {approved:?}");
    let replay = user
        .call(
            &router,
            Method::POST,
            &admission_path,
            Some(approve.clone()),
        )
        .await?;
    ensure!(replay.0 == StatusCode::OK && replay.1 == approved.1);
    let download = format!(
        "{origin}{admission_path}/content?platform=windows&architecture=x86_64&variant=default"
    );
    gc_reference_race(&runtime, execution.content.as_ref().unwrap()).await?;
    mirror_matrix(&mut user, &router, &definition, &origin_server, &runtime).await?;
    dependency_admission_matrix(&mut user, &router, &definition).await?;
    let store = execution.content.as_ref().expect("configured content");
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
    cleanup_preserves_resource_references(&mut user, &router, store, directory.path()).await?;
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
        &router,
        &admission_path,
        1,
        json!({"action":"withdraw","evidence":["withdrawal"]}),
    )
    .await?;
    let read = user
        .call(&router, Method::GET, &admission_path, None)
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
        .call(&router, Method::POST, &admission_path, Some(approve))
        .await?;
    ensure!(
        original.0 == StatusCode::OK && original.1 == approved.1,
        "recovery preserves historical approval, not a new grant"
    );
    // Private PKG and RSS Bundle use the same catalog and approval path without external manifests.
    private_formats(
        &mut user,
        &router,
        &client,
        &origin,
        &cookie,
        registered["snapshot"].clone(),
    )
    .await?;
    crate::identity_fixture::set_grants(TENANT, &subject, vec![]).await?;
    ensure!(
        user.call(&router, Method::GET, &admission_path, None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(
        shared_budget && storage_admission.is_ok(),
        "shared content budget: {shared_budget}; storage admission: {storage_admission:?}"
    );
    Ok(())
}

async fn private_formats(
    user: &mut Browser,
    router: &Router,
    client: &Client,
    origin: &str,
    cookie: &str,
    source: Value,
) -> Result<()> {
    use std::io::Write;
    let manifest = rss_mdm_resource::BundleManifest {
        schema: 1,
        platform: rss_mdm_resource::Platform::Windows,
        architecture: rss_mdm_resource::Architecture::X86_64,
        entries: std::collections::BTreeMap::from([
            (
                "install.ps1".into(),
                rss_mdm_resource::BundleEntry {
                    length: 4,
                    sha256: rss_mdm_resource::Digest::of(b"exit").bytes(),
                },
            ),
            (
                "payload.bin".into(),
                rss_mdm_resource::BundleEntry {
                    length: 3,
                    sha256: rss_mdm_resource::Digest::of(b"abc").bytes(),
                },
            ),
        ]),
    };
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, bytes) in [
        ("manifest.json", serde_json::to_vec(&manifest)?),
        ("install.ps1", b"exit".to_vec()),
        ("payload.bin", b"abc".to_vec()),
    ] {
        zip.start_file(name, options)?;
        zip.write_all(&bytes)?;
    }
    let bundle = zip.finish()?.into_inner();
    for (format, platform, executor, bytes, manifest) in [
        (
            "pkg",
            "macos",
            "package_installer",
            b"controlled PKG fixture".to_vec(),
            Value::Null,
        ),
        (
            "bundle",
            "windows",
            "power_shell7",
            bundle,
            serde_json::to_value(manifest)?,
        ),
    ] {
        let id = Uuid::new_v4();
        let path = format!("/api/v3/resources/{id}");
        write(
            user,
            router,
            &path,
            0,
            json!({"action":"create","kind":"software"}),
        )
        .await?;
        let definition = json!({"source":source,"package":format!("Private.{format}"),"version":"1","format":format,"primary":"package","artifacts":{"package":{"reference":"installer","length":bytes.len(),"sha256":rss_mdm_resource::Digest::of(&bytes).bytes()}},"install":{"executor":executor,"entry":if format=="bundle"{Some("install.ps1")}else{None},"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096},"uninstall":null,"detect":if format=="pkg"{json!({"kind":"pkg_receipt","receipt":"com.acme.pkg","version":"1"})}else{json!({"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1"})},"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"bundle":manifest});
        write(user,router,&path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":platform,"architecture":"x86_64","key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
        let upload = Uuid::new_v4();
        let session = format!("{origin}{path}/uploads/{upload}");
        let csrf = user.csrf.as_ref().unwrap().clone();
        let request = |method, url: &str| {
            client
                .request(method, url)
                .header("host", "mdm.example.test")
                .header("origin", "https://mdm.example.test")
                .header("x-identity-request", "1")
                .header("x-csrf-token", &csrf)
                .header("cookie", cookie)
                .header("content-type", "application/octet-stream")
        };
        let begin = request(
            Method::POST,
            &format!(
                "{session}?version=v1&variant=default&platform={platform}&architecture=x86_64"
            ),
        )
        .send()
        .await?;
        ensure!(begin.status() == StatusCode::OK);
        let half = bytes.len() / 2;
        ensure!(
            request(Method::PATCH, &format!("{session}?offset=0"))
                .body(bytes[..half].to_vec())
                .send()
                .await?
                .status()
                == StatusCode::OK
        );
        let resumed: Value = request(Method::GET, &session).send().await?.json().await?;
        ensure!(resumed["offset"] == half);
        let conflict = request(Method::PATCH, &format!("{session}?offset=0"))
            .body(vec![0])
            .send()
            .await?;
        ensure!(conflict.status() == StatusCode::CONFLICT);
        ensure!(conflict.json::<Value>().await?["offset"] == half);
        let foreign = request(
            Method::GET,
            &format!(
                "{origin}/api/v3/resources/{}/uploads/{upload}",
                Uuid::new_v4()
            ),
        )
        .send()
        .await?;
        ensure!(foreign.status() == StatusCode::FORBIDDEN);
        ensure!(
            request(Method::PATCH, &format!("{session}?offset={half}"))
                .body(bytes[half..].to_vec())
                .send()
                .await?
                .status()
                == StatusCode::OK
        );
        let response = request(Method::POST, &format!("{session}/complete"))
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        ensure!(status == StatusCode::CREATED, "{format}: {status} {body}");
        let approved = write(
            user,
            router,
            &format!("/api/v3/software/resources/{id}/versions/v1"),
            0,
            json!({"action":"approve","evidence":["private-format-review"]}),
        )
        .await?;
        ensure!(approved["admission"]["state"] == "approved");
    }
    Ok(())
}

async fn create_software_version(
    user: &mut Browser,
    router: &Router,
    mut definition: Value,
) -> Result<(String, Value)> {
    let resource = Uuid::new_v4().to_string();
    definition["package"] = json!(format!("Private.{resource}"));
    let path = format!("/api/v3/resources/{resource}");
    write(
        user,
        router,
        &path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    write(user, router, &path, 1, json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":"windows","architecture":"x86_64","key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
    let read = user
        .call(
            router,
            Method::GET,
            &format!("/api/v3/software/resources/{resource}/versions/v1"),
            None,
        )
        .await?;
    ensure!(read.0 == StatusCode::OK, "read dependency: {read:?}");
    Ok((resource, read.1["resourceDigest"].clone()))
}

async fn dependency_admission_matrix(
    user: &mut Browser,
    router: &Router,
    definition: &Value,
) -> Result<()> {
    let (dependency, digest) = create_software_version(user, router, definition.clone()).await?;
    let mut dependent_definition = definition.clone();
    dependent_definition["dependencies"] =
        json!([{"resource":dependency,"version":"v1","sha256":digest}]);
    let (dependent, _) =
        create_software_version(user, router, dependent_definition.clone()).await?;
    let path = format!("/api/v3/software/resources/{dependent}/versions/v1");
    let operation = Uuid::new_v4();
    let approve = json!({"operationId":operation,"expectedRevision":0,"input":{"action":"approve","evidence":["dependency-review"]}});
    let denied = user
        .call(router, Method::POST, &path, Some(approve.clone()))
        .await?;
    ensure!(
        denied.0 == StatusCode::FORBIDDEN,
        "unapproved dependency: {denied:?}"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_software.operations WHERE id='{operation}'"
        ))?
        .trim()
            == "0"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_software.approvals WHERE resource='{dependent}'"
        ))?
        .trim()
            == "0"
    );
    let dependency_path = format!("/api/v3/software/resources/{dependency}/versions/v1");
    write(
        user,
        router,
        &dependency_path,
        0,
        json!({"action":"approve","evidence":["dependency-approved"]}),
    )
    .await?;
    let admitted = user
        .call(router, Method::POST, &path, Some(approve))
        .await?;
    ensure!(
        admitted.0 == StatusCode::OK,
        "approved dependency: {admitted:?}"
    );
    let mut wrong = dependent_definition.clone();
    wrong["dependencies"][0]["sha256"] = json!(vec![0; 32]);
    let (wrong, _) = create_software_version(user, router, wrong).await?;
    let denied = user.call(router, Method::POST, &format!("/api/v3/software/resources/{wrong}/versions/v1"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"approve","evidence":["wrong-digest"]}}))).await?;
    ensure!(
        denied.0 == StatusCode::FORBIDDEN,
        "wrong dependency digest: {denied:?}"
    );
    write(
        user,
        router,
        &dependency_path,
        1,
        json!({"action":"withdraw","evidence":["dependency-withdrawn"]}),
    )
    .await?;
    let denied = user
        .call(
            router,
            Method::GET,
            &format!("{path}/content?platform=windows&architecture=x86_64&variant=default"),
            None,
        )
        .await?;
    ensure!(
        denied.0 == StatusCode::FORBIDDEN,
        "withdrawn dependency download: {denied:?}"
    );
    let (after, _) = create_software_version(user, router, dependent_definition).await?;
    let denied = user.call(router, Method::POST, &format!("/api/v3/software/resources/{after}/versions/v1"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"approve","evidence":["withdrawn-dependency"]}}))).await?;
    ensure!(
        denied.0 == StatusCode::FORBIDDEN,
        "withdrawn dependency approval: {denied:?}"
    );
    Ok(())
}

async fn software_admission_rejects_drift(
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
) -> Result<()> {
    let tenant = rss_request_context::TenantId::parse(TENANT)?;
    crate::flow::storage::admit(runtime, tenant).await?;
    let mut accepted = Vec::new();
    for (change, restore) in [
        (
            "ALTER TABLE mdm_software.sources DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_software.sources ENABLE ROW LEVEL SECURITY",
        ),
        (
            "ALTER TABLE mdm_software.sources NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE mdm_software.sources FORCE ROW LEVEL SECURITY",
        ),
        (
            "ALTER POLICY tenant ON mdm_software.sources USING (true) WITH CHECK (true)",
            "ALTER POLICY tenant ON mdm_software.sources USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
        (
            "CREATE TABLE mdm_software.unexpected(id integer)",
            "DROP TABLE mdm_software.unexpected",
        ),
        (
            "GRANT DELETE ON mdm_software.sources TO mdm_flow_runtime",
            "REVOKE DELETE ON mdm_software.sources FROM mdm_flow_runtime",
        ),
        (
            "GRANT UPDATE(definition) ON mdm_software.sources TO mdm_flow_runtime",
            "REVOKE UPDATE(definition) ON mdm_software.sources FROM mdm_flow_runtime",
        ),
        (
            "CREATE ROLE mdm_software_drift; GRANT USAGE ON SCHEMA mdm_software TO mdm_software_drift; GRANT UPDATE(definition) ON mdm_software.sources TO mdm_software_drift; GRANT mdm_software_drift TO mdm_flow_runtime WITH INHERIT FALSE, SET TRUE",
            "REVOKE mdm_software_drift FROM mdm_flow_runtime; DROP OWNED BY mdm_software_drift; DROP ROLE mdm_software_drift",
        ),
        (
            "CREATE ROLE mdm_content_drift; GRANT USAGE ON SCHEMA mdm_content TO mdm_content_drift; GRANT DELETE ON mdm_content.bindings TO mdm_content_drift; GRANT mdm_content_drift TO mdm_flow_runtime WITH INHERIT FALSE, SET TRUE",
            "REVOKE mdm_content_drift FROM mdm_flow_runtime; DROP OWNED BY mdm_content_drift; DROP ROLE mdm_content_drift",
        ),
    ] {
        pg(change)?;
        let result = crate::flow::storage::admit(runtime, tenant).await;
        pg(restore)?;
        if result.is_ok() {
            accepted.push(change);
        }
        crate::flow::storage::admit(runtime, tenant).await?;
    }
    pg(
        "CREATE ROLE mdm_software_dormant; GRANT UPDATE(definition) ON mdm_software.sources TO mdm_software_dormant; GRANT mdm_software_dormant TO mdm_flow_runtime WITH INHERIT FALSE, SET FALSE",
    )?;
    let dormant = crate::flow::storage::admit(runtime, tenant).await;
    pg(
        "REVOKE mdm_software_dormant FROM mdm_flow_runtime; DROP OWNED BY mdm_software_dormant; DROP ROLE mdm_software_dormant",
    )?;
    ensure!(
        dormant.is_ok(),
        "non-executable role was treated as authority: {dormant:?}"
    );
    ensure!(
        accepted.is_empty(),
        "accepted privilege drift: {accepted:?}"
    );
    Ok(())
}

async fn cleanup_preserves_resource_references(
    user: &mut Browser,
    router: &Router,
    store: &Arc<crate::content::Store>,
    directory: &std::path::Path,
) -> Result<()> {
    let data = b"orphaned upload without resource reference";
    let upload = Uuid::new_v4();
    let binding = crate::content::Binding {
        resource: "orphan".into(),
        version: "1".into(),
        variant: "default".into(),
        platform: rss_mdm_resource::Platform::Windows,
        architecture: rss_mdm_resource::Architecture::X86_64,
        resource_digest: [1; 32],
        source: None,
        origin: None,
        reference: "orphan".into(),
        length: data.len() as u64,
        sha256: rss_mdm_resource::Digest::of(data).bytes(),
        actor: "fixture".into(),
    };
    let artifact = binding.artifact()?;
    store.begin(upload, binding, 1).await?;
    store.append(upload, 0, 1, &data[..]).await?;
    store.finish(upload, 1).await?;
    let tenant_dir = directory.join(TENANT);
    for entry in std::fs::read_dir(&tenant_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(".upload-") && name.ends_with(".json") {
            let mut metadata: Value = serde_json::from_slice(&std::fs::read(entry.path())?)?;
            metadata["expires"] = json!(0);
            std::fs::write(entry.path(), serde_json::to_vec(&metadata)?)?;
        } else if name.len() == 64 {
            std::fs::File::options()
                .write(true)
                .open(entry.path())?
                .set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))?;
        }
    }
    let cleanup = user
        .call(
            router,
            Method::POST,
            "/api/v3/software/content/cleanup",
            None,
        )
        .await?;
    ensure!(
        cleanup.0 == StatusCode::OK && cleanup.1["removed"] == 1,
        "cleanup retained references: {cleanup:?}"
    );
    ensure!(
        store.verify(&artifact).await.is_err(),
        "unreferenced object survived cleanup"
    );
    Ok(())
}

async fn mirror_resource(
    user: &mut Browser,
    router: &Router,
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
    let (resource, _) = create_software_version(user, router, definition).await?;
    let operation = Uuid::new_v4();
    Ok((
        format!(
            "/api/v3/resources/{resource}/content/mirror?version=v1&variant=default&platform=windows&architecture=x86_64&operation={operation}"
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
    for (path, bytes) in [("redirect", &b"abc"[..]), ("wrong.msi", &b"abd"[..])] {
        let (url, operation) =
            mirror_resource(user, router, definition, server, path, bytes).await?;
        let response = user.call(router, Method::POST, &url, None).await?;
        ensure!(
            !response.0.is_success(),
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
        mirror_resource(user, router, definition, server, "audit.msi", b"abc").await?;
    pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_flow_runtime")?;
    let failed = user.call(router, Method::POST, &url, None).await;
    pg("GRANT INSERT ON mdm_audit.receipts TO mdm_flow_runtime")?;
    ensure!(failed?.0.is_server_error());
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
            mirror_resource(user, router, definition, server, "paused.msi", b"abc").await?;
        let started = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        server.state.lock().unwrap().artifact_pause = Some((started.clone(), resume.clone()));
        let mut client = user.clone();
        let app = router.clone();
        let request = url.clone();
        let mirror =
            tokio::spawn(async move { client.call(&app, Method::POST, &request, None).await });
        tokio::time::timeout(Duration::from_secs(10), started.notified()).await?;
        let source_path = format!("/api/v3/software/sources/{}/revisions/1", server.logical);
        if revoke {
            write(
                user,
                router,
                &source_path,
                2,
                json!({"action":"withdraw","evidence":["revoked-during-download"]}),
            )
            .await?;
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
            write(
                user,
                router,
                &source_path,
                3,
                json!({"action":"approve","evidence":["source-restored"]}),
            )
            .await?;
            ensure!(
                response.0 == StatusCode::FORBIDDEN && persisted.trim() == "0",
                "withdrawn origin committed mirror: {response:?}, bindings={persisted}"
            );
        } else {
            ensure!(
                response.0 == StatusCode::SERVICE_UNAVAILABLE,
                "mirror lost commit: {response:?}"
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

async fn gc_reference_race(
    runtime: &Arc<rss_transactional_messaging_postgres::PgRuntime>,
    content: &Arc<crate::content::Store>,
) -> Result<()> {
    use rss_mdm_resource as r;
    use rss_mdm_resource_postgres as rp;
    let tenant = rss_request_context::TenantId::parse(TENANT)?;
    let resources = Arc::new(
        rp::ResourceStore::new(runtime.clone(), tenant, crate::transaction::deadline()).await?,
    );
    let resource = r::Id::new(Uuid::new_v4().to_string())?;
    let data = b"gc-concurrent-reference";
    let artifact = r::Artifact::new(
        r::Id::new("gc-bytes")?,
        data.len() as u64,
        r::Digest::of(data),
    )?;
    let request = |revision, command| rp::Request {
        id: r::Id::new(Uuid::new_v4().to_string()).unwrap(),
        resource: resource.clone(),
        expected_storage_revision: revision,
        as_of: rss_contract::Timepoint::try_from(1i64).unwrap(),
        command,
    };
    resources
        .execute(
            &request(0, rp::Command::Create(r::Kind::Configuration)),
            crate::transaction::deadline(),
        )
        .await?;
    let version = r::Version::new(
        tenant,
        resource.clone(),
        r::Id::new("v1")?,
        r::Kind::Configuration,
        vec![r::Variant::new(
            r::Platform::Windows,
            r::Architecture::X86_64,
            r::Id::new("default")?,
            r::Declaration::Configuration {
                artifact: artifact.clone(),
                schema: r::Id::new("schema")?,
                apply: r::Id::new("apply")?,
                detect: r::Id::new("detect")?,
                remove: None,
            },
        )],
    )?;
    let insert = request(1, rp::Command::Insert(version));
    let id = Uuid::new_v4();
    content
        .begin(
            id,
            crate::content::Binding {
                resource: resource.as_str().into(),
                version: "v1".into(),
                variant: "default".into(),
                platform: r::Platform::Windows,
                architecture: r::Architecture::X86_64,
                resource_digest: [1; 32],
                source: None,
                origin: None,
                reference: artifact.reference().as_str().into(),
                length: artifact.length(),
                sha256: artifact.digest().bytes(),
                actor: "fixture".into(),
            },
            1,
        )
        .await?;
    content.append(id, 0, 1, &data[..]).await?;
    content.finish(id, 1).await?;
    let candidate = content
        .garbage(i64::MAX / 2)
        .await?
        .into_iter()
        .find(|c| c.digest == artifact.digest().bytes())
        .expect("aged candidate");
    let checked = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let gc_runtime = runtime.clone();
    let ready = checked.clone();
    let release = resume.clone();
    let gc = tokio::spawn(async move {
        crate::transaction::inspect(
            &gc_runtime,
            tenant,
            (Some(candidate), ready, release),
            |ctx, tx| {
                Box::pin(async move {
                    let (candidate, ready, release) = ctx;
                    let digest = r::Digest::from_bytes(candidate.as_ref().unwrap().digest);
                    let referenced = rp::artifact_referenced_in(tx, digest).await?;
                    assert!(!referenced);
                    ready.notify_one();
                    release.notified().await;
                    assert!(
                        crate::content::http::reclaim_in(tx, candidate.take().unwrap(), || Ok(()))
                            .await?
                    );
                    Ok(())
                })
            },
            crate::transaction::TransactionOwner::ResourceCatalog,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), checked.notified()).await?;
    let mut writer = tokio::spawn(async move {
        resources
            .execute(&insert, crate::transaction::deadline())
            .await
    });
    let early = tokio::time::timeout(Duration::from_millis(750), &mut writer).await;
    let raced = early.is_ok();
    resume.notify_one();
    gc.await??;
    match early {
        Ok(result) => {
            result??;
        }
        Err(_) => {
            writer.await??;
        }
    }
    ensure!(
        !raced,
        "Resource reference committed between GC inspection and file deletion"
    );
    ensure!(content.verify(&artifact).await.is_err());
    Ok(())
}
