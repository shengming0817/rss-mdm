use super::*;
async fn call(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    revision: u64,
    input: Value,
) -> Result<Value> {
    let (status,result)=browser.call(router,Method::POST,path,Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":revision,"input":input}))).await?;
    ensure!(
        status == StatusCode::OK,
        "management request {path}: {status} {result}"
    );
    Ok(result)
}
pub(super) async fn matrix(
    base: &Value,
    reader: Arc<InventoryReader>,
    session: &Browser,
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
        ..session.clone()
    };
    let original_csrf = browser.csrf.take();
    for token in [None, Some("incorrect-token".to_owned())] {
        browser.csrf = token;
        let blocked = uuid::Uuid::new_v4();
        let response=browser.call(&router,Method::POST,&format!("/api/v1/groups/{blocked}"),Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"input":{"action":"create","name":"csrf-must-not-write","description":"","criteria":null}}))).await?;
        ensure!(
            response.0 == StatusCode::FORBIDDEN,
            "management write accepted absent/incorrect csrf token: {}",
            response.0
        );
        ensure!(
            pg(&format!(
                "SELECT count(*) FROM mdm_group.groups WHERE id='{blocked}'"
            ))?
            .trim()
                == "0"
        );
    }
    browser.csrf = original_csrf;
    let group = uuid::Uuid::new_v4();
    let scope = uuid::Uuid::new_v4();
    let policy = uuid::Uuid::new_v4();
    let resource = uuid::Uuid::new_v4();
    let group_path = format!("/api/v1/groups/{group}");
    call(&mut browser,&router,&group_path,0,json!({"action":"create","name":"managed","description":"","criteria":{"kind":"eq","field":"device.model","value":"Model-A"}})).await?;
    let (status, mut preview) = browser
        .call(
            &router,
            Method::GET,
            &format!("{group_path}/preview?expectedRevision=1"),
            None,
        )
        .await?;
    ensure!(
        status == StatusCode::OK && preview["members"] == json!(["device-1"]),
        "trusted inventory mapping: {preview}"
    );
    let old_snapshot = preview["snapshot"].clone();
    pg("UPDATE mdm.inventory SET value='Model-B' WHERE field='device.model'")?;
    let stale = json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":1,"input":{"action":"recompute","snapshot":old_snapshot}});
    ensure!(
        browser
            .call(&router, Method::POST, &group_path, Some(stale))
            .await?
            .0
            == StatusCode::CONFLICT,
        "stale asset snapshot accepted"
    );
    ensure!(
        browser
            .call(&router, Method::GET, &group_path, None)
            .await?
            .1["group"]["memberCount"]
            == 0
    );
    let changed = browser
        .call(
            &router,
            Method::GET,
            &format!("{group_path}/preview?expectedRevision=1"),
            None,
        )
        .await?;
    ensure!(changed.0 == StatusCode::OK && changed.1["members"] == json!([]));
    pg("UPDATE mdm.inventory SET value='Model-A' WHERE field='device.model'")?;
    pg(
        "UPDATE mdm_access.report_sources SET enabled=false WHERE registration='99999999-9999-4999-8999-999999999991'",
    )?;
    let stale = json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":1,"input":{"action":"recompute","snapshot":old_snapshot}});
    ensure!(
        browser
            .call(&router, Method::POST, &group_path, Some(stale))
            .await?
            .0
            == StatusCode::CONFLICT,
        "disabled report source accepted stale recompute"
    );
    pg(
        "UPDATE mdm_access.report_sources SET enabled=true WHERE registration='99999999-9999-4999-8999-999999999991'",
    )?;
    preview = browser
        .call(
            &router,
            Method::GET,
            &format!("{group_path}/preview?expectedRevision=1"),
            None,
        )
        .await?
        .1;
    let recompute = json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":1,"input":{"action":"recompute","snapshot":preview["snapshot"]}});
    let (status, members) = browser
        .call(&router, Method::POST, &group_path, Some(recompute.clone()))
        .await?;
    ensure!(status == StatusCode::OK && members["group"]["memberCount"] == 1);
    ensure!(
        browser
            .call(&router, Method::POST, &group_path, Some(recompute))
            .await?
            .1
            == members,
        "replay changed members"
    );
    let second = format!("scope-second-{}", uuid::Uuid::new_v4());
    let third = format!("scope-third-{}", uuid::Uuid::new_v4());
    for device in [&second, &third] {
        seed_management_device(device)?;
    }
    let target_group = uuid::Uuid::new_v4();
    let limit_group = uuid::Uuid::new_v4();
    for (id, members) in [
        (target_group, json!(["device-1", second, third])),
        (limit_group, json!(["device-1", second])),
    ] {
        let path = format!("/api/v1/groups/{id}");
        call(
            &mut browser,
            &router,
            &path,
            0,
            json!({"action":"create","name":"set-algebra","description":"","criteria":null}),
        )
        .await?;
        call(
            &mut browser,
            &router,
            &path,
            1,
            json!({"action":"members","add":members,"remove":[]}),
        )
        .await?;
    }
    call(&mut browser,&router,&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"group","id":target_group}],"limitations":[{"kind":"group","id":limit_group}],"exclusions":[{"kind":"device","id":second}]}})).await?;
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
        created["storageRevision"].as_u64().unwrap(),
        json!({"action":"activate","version":1,"resource":resource,"resourceVersion":"v1"}),
    )
    .await?;
    let revision = active["storageRevision"].as_u64().unwrap();
    let planned = call(
        &mut browser,
        &router,
        &format!("{policy_path}/previews"),
        revision,
        json!({"scope":scope,"expectedRevision":revision}),
    )
    .await?;
    ensure!(
        planned["devices"] == json!(["device-1"]) && planned["plan"]["intents"][0]["kind"] == "add"
    );
    let explanations = planned["explanation"]["members"].as_array().unwrap();
    ensure!(explanations.iter().any(|e| {
        e["device"] == second
            && e["reasons"]
                .as_array()
                .unwrap()
                .contains(&json!("explicit_exclusion"))
    }));
    ensure!(explanations.iter().any(|e| {
        e["device"] == third
            && e["reasons"]
                .as_array()
                .unwrap()
                .contains(&json!("missing_limitation_match"))
    }));
    let saved = call(
        &mut browser,
        &router,
        &format!("{policy_path}/plans"),
        revision,
        json!({"preview":planned["id"]}),
    )
    .await?;
    ensure!(saved["plan"] == planned["plan"] && saved["plan"]["dispatch"] == "not_requested");
    let policy_state = browser
        .call(&router, Method::GET, &policy_path, None)
        .await?
        .1;
    ensure!(policy_state["plan"] == saved["plan"]["id"] && policy_state["status"] == "active");

    let stored = browser
        .call(
            &router,
            Method::GET,
            &format!("/api/v1/plan-previews/{}", planned["id"].as_str().unwrap()),
            None,
        )
        .await?;
    ensure!(stored.0 == StatusCode::OK && stored.1 == planned);
    let current_revision = policy_state["storageRevision"].as_u64().unwrap();
    let stale = call(
        &mut browser,
        &router,
        &format!("{policy_path}/previews"),
        current_revision,
        json!({"scope":scope,"expectedRevision":current_revision}),
    )
    .await?;
    call(
        &mut browser,
        &router,
        &format!("/api/v1/groups/{limit_group}"),
        2,
        json!({"action":"members","add":[],"remove":["device-1"]}),
    )
    .await?;
    ensure!(browser.call(&router,Method::POST,&format!("{policy_path}/plans"),Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":current_revision,"input":{"preview":stale["id"]}}))).await?.0==StatusCode::CONFLICT);
    scale_preview(&mut browser, &router, &policy_path, current_revision).await?;
    // The common protected tree never inherits management access from super_admin.
    software(base, reader.clone(), session).await?;
    let restricted = app(base, reader).await?;
    let mut denied = session.clone();
    for path in [&group_path, &policy_path, &resource_path] {
        ensure!(
            denied.call(&restricted, Method::GET, path, None).await?.0 == StatusCode::FORBIDDEN
        );
    }
    pg("REVOKE INSERT ON mdm_access.audit FROM mdm_management_runtime")?;
    let failed=browser.call(&router,Method::POST,&format!("/api/v1/groups/{}",uuid::Uuid::new_v4()),Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"input":{"action":"create","name":"must-rollback","description":"","criteria":null}}))).await?;
    pg("GRANT INSERT ON mdm_access.audit TO mdm_management_runtime")?;
    ensure!(failed.0 == StatusCode::SERVICE_UNAVAILABLE);
    ensure!(pg("SELECT count(*) FROM mdm_group.groups WHERE name='must-rollback'")?.trim() == "0");
    println!("MDM_MANAGEMENT_HTTP_MATRIX_PASSED");
    Ok(())
}

async fn software(base: &Value, reader: Arc<InventoryReader>, session: &Browser) -> Result<()> {
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
        "release_recover",
        "release_withdraw"
    ]);
    let initial = app(&cfg, reader.clone()).await?;
    let mut approver = Browser::default();
    approver.login(&initial, "admin").await?;
    let subject = approver
        .call(&initial, Method::GET, "/api/v1/authorization", None)
        .await?
        .1["principal_id"]
        .clone();
    let mut binding = cfg["bindings"][0].clone();
    binding["principal_id"] = subject.clone();
    binding["management"] = json!(["release_read", "release_approve"]);
    cfg["bindings"].as_array_mut().unwrap().push(binding);
    permission_matrix(&cfg, reader.clone(), session).await?;
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
        ..approver
    };
    publisher.cookies = session.cookies.clone();
    publisher.csrf = session.csrf.clone();
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
    let original_csrf = publisher.csrf.take();
    for token in [None, Some("incorrect-token".to_owned())] {
        publisher.csrf = token;
        let blocked = uuid::Uuid::new_v4();
        let response=publisher.call(&router,Method::POST,&path,Some(json!({"operationId":blocked,"expectedRevision":0,"input":{"action":"candidate","resource":resource,"version":"v1","expectedResourceRevision":2,"submission":server.winget_submission()}}))).await?;
        ensure!(
            response.0 == StatusCode::FORBIDDEN,
            "publication accepted absent/incorrect csrf token"
        );
        ensure!(
            pg(&format!(
                "SELECT count(*) FROM mdm_management.operations WHERE id='{blocked}'"
            ))?
            .trim()
                == "0"
        );
    }
    publisher.csrf = original_csrf;
    let bad_operation = uuid::Uuid::new_v4();
    let (bad_status,_)=publisher.call(&router,Method::POST,&path,Some(json!({"operationId":bad_operation,"expectedRevision":0,"input":{"action":"candidate","resource":"missing","version":"v1","expectedResourceRevision":1,"submission":server.winget_submission()}}))).await?;
    ensure!(bad_status.is_client_error());
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE operation_id='{bad_operation}' AND result='success'"))?.trim()=="0","failed publication intent claimed success");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE operation_id='{bad_operation}' AND result='unknown' AND status=202 AND software->>'stage'='management_admission'"))?.trim()=="1");
    let candidate=call(&mut publisher,&router,&path,0,json!({"action":"candidate","resource":resource,"version":"v1","expectedResourceRevision":2,"submission":server.winget_submission()})).await?;
    let validated = call(
        &mut publisher,
        &router,
        &path,
        candidate["revision"].as_u64().unwrap(),
        json!({"action":"validate","ring":"test"}),
    )
    .await?;
    let approval = json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":validated["revision"],"input":{"action":"approve","ring":"test","publisherSubject":cfg["bindings"][0]["principal_id"]}});
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
    let request = json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":authorized["revision"],"input":{"action":"publish","ring":"test","publication":publication["id"],"attempt":publication["attempt"]}});
    {
        let mut state = server.state.lock().unwrap();
        state.drop_post_response = true;
        state.hidden_reads = 1;
    }
    let (unknown, _) = publisher
        .call(&router, Method::POST, &path, Some(request.clone()))
        .await?;
    ensure!(
        unknown == StatusCode::SERVICE_UNAVAILABLE,
        "uncertain source result claimed HTTP success"
    );
    let operation = request["operationId"].as_str().unwrap();
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE operation_id='{operation}' AND action='management_write' AND result='unknown'"))?.trim()=="1");
    let (status, published) = publisher
        .call(&router, Method::POST, &path, Some(request.clone()))
        .await?;
    ensure!(
        status == StatusCode::OK && published["rings"][0]["publication"]["outcome"] == "published",
        "publish: {status} {published}"
    );
    let publication_operation = request["operationId"].as_str().unwrap().to_owned();
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE operation_id='{publication_operation}' AND action='management_write' AND result='success'"))?.trim()=="1", "first publication mislabeled as replay");
    ensure!(
        publisher
            .call(&router, Method::POST, &path, Some(request))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE operation_id='{publication_operation}' AND action='management_write' AND result='replay'"))?.trim()=="1", "terminal retry was not audited as replay");
    ensure!(
        server.state.lock().unwrap().posts == 1,
        "HTTP replay republished content"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE action='software_approve' AND actor='{}' AND instance='{INSTANCE}'",subject.as_str().unwrap()))?.trim()=="1","approval lost real actor");
    let withdraw = json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":published["revision"],"input":{"action":"withdraw","ring":"pilot"}});
    let (status, withdrawn) = publisher
        .call(&router, Method::POST, &path, Some(withdraw.clone()))
        .await?;
    ensure!(
        status == StatusCode::OK,
        "unpublished withdrawal: {status} {withdrawn}"
    );
    let (status, _) = publisher
        .call(&router, Method::POST, &path, Some(withdraw.clone()))
        .await?;
    ensure!(status == StatusCode::OK);
    let operation = withdraw["operationId"].as_str().unwrap();
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE operation_id='{operation}' AND action='management_write' AND result='success'"))?.trim()=="1","unpublished withdrawal replay was marked as performed");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE operation_id='{operation}' AND action='management_write' AND result='replay'"))?.trim()=="1");
    let fresh = json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":withdrawn["revision"],"input":{"action":"withdraw","ring":"pilot"}});
    ensure!(
        publisher
            .call(&router, Method::POST, &path, Some(fresh.clone()))
            .await?
            .0
            == StatusCode::OK
    );
    let operation = fresh["operationId"].as_str().unwrap();
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE operation_id='{operation}' AND action='management_write' AND result='success'"))?.trim()=="1");
    println!("MDM_SOFTWARE_MANAGEMENT_HTTP_MATRIX_PASSED");
    Ok(())
}

fn seed_management_device(device: &str) -> Result<()> {
    let grant = uuid::Uuid::new_v4();
    let request = uuid::Uuid::new_v4();
    let registration = uuid::Uuid::new_v4();
    pg(&format!(
        "INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{TENANT}','{grant}','fixture','{INSTANCE}','{device}','enrollment','consumed',clock_timestamp()+interval '200 seconds');INSERT INTO mdm_access.requests(tenant_id,id,grant_id) VALUES('{TENANT}','{request}','{grant}');INSERT INTO mdm_access.devices VALUES('{TENANT}','{device}');INSERT INTO mdm_access.registrations VALUES('{TENANT}','{registration}','{device}','mdm',1,'{request}','active');"
    ))?;
    Ok(())
}
async fn scale_preview(
    browser: &mut Browser,
    router: &Router,
    policy: &str,
    revision: u64,
) -> Result<()> {
    let prefix = uuid::Uuid::new_v4();
    pg(&format!(
        "CREATE TEMP TABLE scale_devices AS SELECT '{prefix}-'||n::text AS device,gen_random_uuid() AS grant_id,gen_random_uuid() AS request,gen_random_uuid() AS registration FROM generate_series(1,1001) n;INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) SELECT '{TENANT}',grant_id,'fixture','{INSTANCE}',device,'enrollment','consumed',clock_timestamp()+interval '200 seconds' FROM scale_devices;INSERT INTO mdm_access.requests(tenant_id,id,grant_id) SELECT '{TENANT}',request,grant_id FROM scale_devices;INSERT INTO mdm_access.devices SELECT '{TENANT}',device FROM scale_devices;INSERT INTO mdm_access.registrations SELECT '{TENANT}',registration,device,'mdm',1,request,'active' FROM scale_devices;"
    ))?;
    let group = uuid::Uuid::new_v4();
    let scope = uuid::Uuid::new_v4();
    let group_path = format!("/api/v1/groups/{group}");
    call(
        browser,
        router,
        &group_path,
        0,
        json!({"action":"create","name":"scale","description":"","criteria":null}),
    )
    .await?;
    let devices = (1..=1001)
        .map(|n| format!("{prefix}-{n}"))
        .collect::<Vec<_>>();
    for (index, batch) in devices.chunks(100).enumerate() {
        call(
            browser,
            router,
            &group_path,
            index as u64 + 1,
            json!({"action":"members","add":batch,"remove":[]}),
        )
        .await?;
    }
    call(browser,router,&format!("/api/v1/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"group","id":group}],"limitations":null,"exclusions":[]}})).await?;
    let preview = call(
        browser,
        router,
        &format!("{policy}/previews"),
        revision,
        json!({"scope":scope,"expectedRevision":revision}),
    )
    .await?;
    ensure!(preview["devices"].as_array().unwrap().len() == 1001);
    let saved = call(
        browser,
        router,
        &format!("{policy}/plans"),
        revision,
        json!({"preview":preview["id"]}),
    )
    .await?;
    let revision = saved["receipt"]["storageRevision"].as_u64().unwrap();
    let next = call(
        browser,
        router,
        &format!("{policy}/previews"),
        revision,
        json!({"scope":scope,"expectedRevision":revision}),
    )
    .await?;
    ensure!(
        next["devices"].as_array().unwrap().len() == 1001,
        "facts pagination truncated"
    );
    ensure!(
        next["plan"]["intents"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["kind"] == "retain")
            .count()
            >= 1001
    );
    Ok(())
}

// Exercise the route-to-capability map independently of the full business flow.
// Authorized missing/stale targets must reach domain validation; denied calls
// must stop before any management, policy, resource or release mutation.
async fn permission_matrix(
    base: &Value,
    reader: Arc<InventoryReader>,
    session: &Browser,
) -> Result<()> {
    let id = uuid::Uuid::new_v4();
    let source = base["management"]["sources"][0]["name"].as_str().unwrap();
    let release = format!("/api/v1/software-sources/{source}/candidates/{id}");
    let op = |input: Value| {
        Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":999,"input":input}))
    };
    let mut cases = vec![
        (
            "group_read",
            Method::GET,
            format!("/api/v1/groups/{id}"),
            None,
        ),
        (
            "group_write",
            Method::POST,
            format!("/api/v1/groups/{id}"),
            op(json!({"action":"edit","name":"denied","description":""})),
        ),
        (
            "group_recompute",
            Method::POST,
            format!("/api/v1/groups/{id}"),
            op(json!({"action":"recompute","snapshot":"old"})),
        ),
        (
            "scope_read",
            Method::GET,
            format!("/api/v1/scopes/{id}"),
            None,
        ),
        (
            "scope_write",
            Method::POST,
            format!("/api/v1/scopes/{id}"),
            op(json!({"action":"delete"})),
        ),
        (
            "policy_read",
            Method::GET,
            format!("/api/v1/policies/{id}"),
            None,
        ),
        (
            "policy_write",
            Method::POST,
            format!("/api/v1/policies/{id}"),
            op(json!({"action":"pause"})),
        ),
        (
            "plan_preview",
            Method::POST,
            format!("/api/v1/policies/{id}/previews"),
            op(json!({"scope":id,"expectedRevision":999})),
        ),
        (
            "plan_save",
            Method::POST,
            format!("/api/v1/policies/{id}/plans"),
            op(json!({"preview":id})),
        ),
        (
            "resource_read",
            Method::GET,
            format!("/api/v1/resources/{id}"),
            None,
        ),
        (
            "resource_write",
            Method::POST,
            format!("/api/v1/resources/{id}"),
            op(json!({"action":"activate","version":"missing"})),
        ),
        ("release_read", Method::GET, release.clone(), None),
        (
            "release_write",
            Method::POST,
            release.clone(),
            Some(
                json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"input":{"action":"candidate","resource":"missing","version":"v1","expectedResourceRevision":1,"submission":{"kind":"Winget","manifest":{}}}}),
            ),
        ),
        (
            "release_validate",
            Method::POST,
            release.clone(),
            op(json!({"action":"validate","ring":"test"})),
        ),
        (
            "release_approve",
            Method::POST,
            release.clone(),
            op(
                json!({"action":"approve","ring":"test","publisherSubject":base["bindings"][1]["principal_id"]}),
            ),
        ),
        (
            "release_publish",
            Method::POST,
            release.clone(),
            op(json!({"action":"authorize","ring":"test"})),
        ),
        (
            "release_withdraw",
            Method::POST,
            release.clone(),
            op(json!({"action":"withdraw","ring":"test"})),
        ),
        (
            "release_recover",
            Method::POST,
            release,
            op(json!({"action":"retry","ring":"test","attempt":1})),
        ),
    ];
    cases.extend([
        (
            "group_read",
            Method::GET,
            format!("/api/v1/groups/{id}/preview?expectedRevision=999"),
            None,
        ),
        (
            "policy_read",
            Method::GET,
            format!("/api/v1/plan-previews/{id}"),
            None,
        ),
        (
            "release_publish",
            Method::POST,
            format!("/api/v1/software-sources/{source}/candidates/{id}"),
            op(json!({"action":"publish","ring":"test","publication":vec![0;32],"attempt":1})),
        ),
        (
            "release_recover",
            Method::POST,
            format!("/api/v1/software-sources/{source}/candidates/{id}"),
            op(json!({"action":"recover","ring":"test","publication":vec![0;32],"attempt":1})),
        ),
    ]);
    let grants = cases
        .iter()
        .map(|c| c.0)
        .collect::<std::collections::BTreeSet<_>>();
    let expected_denied = cases.len() * (grants.len() - 1);
    let counts = || {
        pg(
            "SELECT jsonb_build_array((SELECT count(*) FROM mdm_group.groups),(SELECT count(*) FROM mdm_management.operations),(SELECT count(*) FROM mdm_management.scope_versions),(SELECT count(*) FROM mdm_management.previews),(SELECT count(*) FROM mdm_management.plan_references),(SELECT count(*) FROM mdm_software_composition.subjects))::text",
        )
    };
    for grant in &grants {
        let mut config = base.clone();
        config["bindings"][0]["management"] = json!([grant]);
        config["bindings"][1]["management"] = json!(["release_publish"]);
        let router = app(&config, reader.clone()).await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let hosted = router.clone();
        let task = tokio::spawn(async move { axum::serve(listener, hosted).await });
        let mut browser = Browser {
            network: Some((
                Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?,
                format!("http://{address}"),
            )),
            ..session.clone()
        };
        let before = counts()?;
        for (needed, method, path, body) in &cases {
            if grant == needed {
                continue;
            }
            let (status, _) = browser
                .call(&router, method.clone(), path, body.clone())
                .await?;
            ensure!(
                status == StatusCode::FORBIDDEN,
                "grant {grant} allowed {needed}: {status}"
            );
        }
        ensure!(
            before == counts()?,
            "denied capability mutated product state"
        );
        for (_, method, path, body) in cases.iter().filter(|c| c.0 == *grant) {
            let (status, result) = browser
                .call(&router, method.clone(), path, body.clone())
                .await?;
            ensure!(
                matches!(
                    status,
                    StatusCode::NOT_FOUND | StatusCode::CONFLICT | StatusCode::BAD_REQUEST
                ),
                "grant {grant} failed to reach domain validation: {status} {result}"
            );
            if *method == Method::GET {
                let code = if path.contains("plan-previews") {
                    "plan_preview_not_found"
                } else {
                    match *grant {
                        "group_read" => "group_not_found",
                        "scope_read" => "scope_not_found",
                        "policy_read" => "policy_not_found",
                        "resource_read" => "resource_not_found",
                        "release_read" => "software_candidate_not_found",
                        _ => unreachable!(),
                    }
                };
                ensure!(
                    status == StatusCode::NOT_FOUND && result["code"] == code,
                    "wrong missing-object contract: {result}"
                );
            }
        }
        task.abort();
    }
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE target='{id}' AND result='denied' AND action IN ('management_read','management_write','plan_preview','plan_save') AND actor IS NOT NULL AND instance='{INSTANCE}'"))?.trim()==expected_denied.to_string(),"denied action/target/actor audit incomplete");
    Ok(())
}
