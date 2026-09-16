use super::*;
async fn call(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    revision: u64,
    input: Value,
) -> Result<Value> {
    let (status,result)=browser.call(router,Method::POST,path,Some(json!({"operation_id":uuid::Uuid::new_v4(),"expected_revision":revision,"input":input}))).await?;
    ensure!(
        status == StatusCode::OK,
        "management request {path}: {status} {result}"
    );
    Ok(result)
}
pub(super) async fn matrix(
    base: &Value,
    reader: Arc<InventoryReader>,
    web: &Client,
    origin: &str,
    csrf: &str,
    admin: &Client,
    admin_csrf: &str,
) -> Result<()> {
    let mut cfg = base.clone();
    cfg["bindings"][0]["management"] = json!([
        "group_read",
        "group_write",
        "group_recompute",
        "scope_read",
        "scope_write",
        "policy_read",
        "policy_write",
        "plan_preview",
        "plan_save",
        "resource_read",
        "resource_write"
    ]);
    let router = app(&cfg, reader.clone()).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let hosted = router.clone();
    let task = tokio::spawn(async move { axum::serve(listener, hosted).await });
    struct Server(tokio::task::JoinHandle<std::io::Result<()>>);
    impl Drop for Server {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _server = Server(task);
    let mut browser = Browser {
        network: Some((
            Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(12))
                .build()?,
            format!("http://{address}"),
        )),
        ..Default::default()
    };
    ensure!(browser.login(&router, web, origin, csrf).await? == StatusCode::SEE_OTHER);
    let group = uuid::Uuid::new_v4();
    let scope = uuid::Uuid::new_v4();
    let policy = uuid::Uuid::new_v4();
    let resource = uuid::Uuid::new_v4();
    let group_path = format!("/api/v1/groups/{group}");
    call(&mut browser,&router,&group_path,0,json!({"action":"create","name":"managed","description":"","criteria":{"kind":"eq","field":"device.model","value":"Model-A"}})).await?;
    let (status, preview) = browser
        .call(
            &router,
            Method::GET,
            &format!("{group_path}/preview?expected_revision=1"),
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK && preview["members"] == json!(["device-1"]),
        "trusted inventory mapping: {preview}"
    );
    let recompute = json!({"operation_id":uuid::Uuid::new_v4(),"expected_revision":1,"input":{"action":"recompute","snapshot":preview["snapshot"]}});
    let (status, members) = browser
        .call(&router, Method::POST, &group_path, Some(recompute.clone()))
        .await?;
    ensure!(status == StatusCode::OK && members["group"]["member_count"] == 1);
    ensure!(
        browser
            .call(&router, Method::POST, &group_path, Some(recompute))
            .await?
            .1
            == members,
        "replay changed members"
    );
    call(&mut browser,&router,&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"group","id":group}],"limitations":null,"exclusions":[]}})).await?;
    let resource_path = format!("/api/v1/resources/{resource}");
    call(
        &mut browser,
        &router,
        &resource_path,
        0,
        json!({"action":"create","kind":"configuration"}),
    )
    .await?;
    call(&mut browser,&router,&resource_path,1,json!({"action":"version","version":"v1","kind":"configuration","variants":[{"platform":"windows","architecture":"x86_64","key":"config","declaration":{"kind":"configuration","artifact":{"reference":"config","length":1,"sha256":vec![1;32]},"schema":"v1","apply":"set","detect":"get","remove":null}}]})).await?;
    let policy_path = format!("/api/v1/policies/{policy}");
    let created = call(
        &mut browser,
        &router,
        &policy_path,
        0,
        json!({"action":"create"}),
    )
    .await?;
    let active = call(
        &mut browser,
        &router,
        &policy_path,
        created["storage_revision"].as_u64().unwrap(),
        json!({"action":"activate","version":1,"resource":resource,"resource_version":"v1"}),
    )
    .await?;
    let revision = active["storage_revision"].as_u64().unwrap();
    let planned = call(
        &mut browser,
        &router,
        &format!("{policy_path}/previews"),
        revision,
        json!({"scope":scope,"expected_revision":revision}),
    )
    .await?;
    ensure!(
        planned["devices"] == json!(["device-1"]) && planned["plan"]["intents"][0]["kind"] == "add"
    );
    let saved = call(
        &mut browser,
        &router,
        &format!("{policy_path}/plans"),
        revision,
        json!({"preview":planned["id"]}),
    )
    .await?;
    ensure!(saved["plan"] == planned["plan"] && saved["plan"]["dispatch"] == "not_requested");
    let stored = browser
        .call(
            &router,
            Method::GET,
            &format!("/api/v1/plan-previews/{}", planned["id"].as_str().unwrap()),
            None,
        )
        .await?;
    ensure!(stored.0 == StatusCode::OK && stored.1 == planned);
    // The common protected tree never inherits management access from super_admin.
    software(base, reader.clone(), web, origin, csrf, admin, admin_csrf).await?;
    let restricted = app(base, reader).await?;
    let mut denied = Browser::default();
    denied.login(&restricted, web, origin, csrf).await?;
    for path in [&group_path, &policy_path, &resource_path] {
        ensure!(
            denied.call(&restricted, Method::GET, path, None).await?.0 == StatusCode::FORBIDDEN
        );
    }
    pg("REVOKE INSERT ON mdm_access.audit FROM mdm_management_runtime")?;
    let failed=browser.call(&router,Method::POST,&format!("/api/v1/groups/{}",uuid::Uuid::new_v4()),Some(json!({"operation_id":uuid::Uuid::new_v4(),"expected_revision":0,"input":{"action":"create","name":"must-rollback","description":"","criteria":null}}))).await?;
    pg("GRANT INSERT ON mdm_access.audit TO mdm_management_runtime")?;
    ensure!(failed.0 == StatusCode::SERVICE_UNAVAILABLE);
    ensure!(pg("SELECT count(*) FROM mdm_group.groups WHERE name='must-rollback'")?.trim() == "0");
    println!("MDM_MANAGEMENT_HTTP_MATRIX_PASSED");
    Ok(())
}

async fn software(
    base: &Value,
    reader: Arc<InventoryReader>,
    web: &Client,
    origin: &str,
    csrf: &str,
    admin: &Client,
    admin_csrf: &str,
) -> Result<()> {
    let server = publication_support::Server::new().await;
    let mut cfg = base.clone();
    let source_config = |ring: &str| json!({"Winget":{"base":format!("{}{ring}/",server.base),"addresses":[server.address],"private_ca":server.ca,"credential_reference":"source-key","credential_file":server.secret}});
    cfg["management"]["sources"] = json!([{"name":server.logical,"rings":{"test":source_config("test"),"pilot":source_config("pilot"),"production":source_config("production")},"artifacts":[{"base":format!("{}artifacts/",server.base),"addresses":[server.address],"private_ca":server.ca}],"max_artifact_bytes":1048576}]);
    cfg["bindings"][0]["management"] = json!([
        "resource_read",
        "resource_write",
        "release_read",
        "release_write",
        "release_validate",
        "release_publish",
        "release_recover"
    ]);
    let initial = app(&cfg, reader.clone()).await?;
    let mut approver = Browser::default();
    approver.login(&initial, admin, origin, admin_csrf).await?;
    let subject = approver
        .call(&initial, Method::GET, "/api/v1/auth/me", None)
        .await?
        .1["subject"]
        .clone();
    let mut binding = cfg["bindings"][0].clone();
    binding["subject"] = subject.clone();
    binding["management"] = json!(["release_read", "release_approve"]);
    cfg["bindings"].as_array_mut().unwrap().push(binding);
    let router = app(&cfg, reader).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let hosted = router.clone();
    let task = tokio::spawn(async move { axum::serve(listener, hosted).await });
    struct Server(tokio::task::JoinHandle<std::io::Result<()>>);
    impl Drop for Server {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _server = Server(task);
    let transport = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(12))
        .build()?;
    let mut publisher = Browser {
        network: Some((transport.clone(), format!("http://{address}"))),
        ..Default::default()
    };
    approver = Browser {
        network: Some((transport, format!("http://{address}"))),
        ..Default::default()
    };
    publisher.login(&router, web, origin, csrf).await?;
    approver.login(&router, admin, origin, admin_csrf).await?;
    let resource = uuid::Uuid::new_v4();
    let resource_path = format!("/api/v1/resources/{resource}");
    call(
        &mut publisher,
        &router,
        &resource_path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    let digest = rss_mdm_resource::Digest::of(b"abc").bytes();
    let variants=[("x86_64","x64"),("aarch64","arm64")].iter().map(|(arch,key)|json!({"platform":"windows","architecture":arch,"key":"msi.machine.no-id","declaration":{"kind":"software","source":server.logical,"package":"Acme.App","version":"1","artifact":{"reference":key,"length":3,"sha256":digest},"install":"install","detect":"detect","uninstall":null}})).collect::<Vec<_>>();
    call(
        &mut publisher,
        &router,
        &resource_path,
        1,
        json!({"action":"version","version":"v1","kind":"software","variants":variants}),
    )
    .await?;
    let path = format!(
        "/api/v1/software-sources/{}/candidates/{}",
        server.logical,
        uuid::Uuid::new_v4()
    );
    let candidate=call(&mut publisher,&router,&path,0,json!({"action":"candidate","resource":resource,"version":"v1","expected_resource_revision":2,"submission":server.winget_submission()})).await?;
    let validated = call(
        &mut publisher,
        &router,
        &path,
        candidate["revision"].as_u64().unwrap(),
        json!({"action":"validate","ring":"test"}),
    )
    .await?;
    let approval = json!({"operation_id":uuid::Uuid::new_v4(),"expected_revision":validated["revision"],"input":{"action":"approve","ring":"test","publisher_subject":cfg["bindings"][0]["subject"]}});
    ensure!(
        publisher
            .call(&router, Method::POST, &path, Some(approval.clone()))
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    let (status, approved) = approver
        .call(&router, Method::POST, &path, Some(approval))
        .await?;
    ensure!(status == StatusCode::OK, "approve: {status} {approved}");
    let authorized = call(
        &mut publisher,
        &router,
        &path,
        approved["revision"].as_u64().unwrap(),
        json!({"action":"authorize","ring":"test"}),
    )
    .await?;
    let publication = &authorized["rings"][0]["publication"];
    let request = json!({"operation_id":uuid::Uuid::new_v4(),"expected_revision":authorized["revision"],"input":{"action":"publish","ring":"test","publication":publication["id"],"attempt":publication["attempt"]}});
    let (status, published) = publisher
        .call(&router, Method::POST, &path, Some(request.clone()))
        .await?;
    ensure!(
        status == StatusCode::OK && published["rings"][0]["publication"]["outcome"] == "published",
        "publish: {status} {published}"
    );
    ensure!(
        publisher
            .call(&router, Method::POST, &path, Some(request))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        server.state.lock().unwrap().posts == 1,
        "HTTP replay republished content"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE action='software_approve' AND actor='{}' AND client='mdm'",subject.as_str().unwrap()))?.trim()=="1","approval lost real actor");
    println!("MDM_SOFTWARE_MANAGEMENT_HTTP_MATRIX_PASSED");
    Ok(())
}
