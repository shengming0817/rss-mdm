use super::*;
use anyhow::Context;
struct Server(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn call(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    revision: u64,
    input: Value,
) -> Result<Value> {
    let (status, result) = settled_write(
        browser,
        router,
        path,
        json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":revision,"input":input}),
    )
    .await?;
    if status == StatusCode::CONFLICT && path.starts_with("/api/v2/groups/") {
        let current = browser.call(router, Method::GET, path, None).await?;
        anyhow::bail!(
            "group write at expected revision {revision}: {status} {result}; observed {current:?}"
        );
    }
    ensure!(
        status == StatusCode::OK || status == StatusCode::ACCEPTED,
        "management request {path}: {status} {result}"
    );
    if let Some(task) = result["task"].as_str() {
        let status_url = result["statusUrl"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{path}/tasks/{task}"));
        await_task(browser, router, &status_url).await?;
    }
    Ok(result)
}
// Normal writes can collide with the live automation worker's serializable
// transaction. Retry the exact identity/body; injected failures bypass this helper.
async fn settled_write(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    body: Value,
) -> Result<(StatusCode, Value)> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let result = browser
                .call(router, Method::POST, path, Some(body.clone()))
                .await?;
            if result.0 != StatusCode::SERVICE_UNAVAILABLE {
                return Ok(result);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("management write did not settle")?
}
pub(super) async fn matrix(
    base: &Value,
    reader: Arc<InventoryReader>,
    session: &Browser,
) -> Result<()> {
    let automation = start_automation(base).await?;
    await_ingress().await?;
    let initial = app(base, reader.clone()).await?;
    let member = browser_subject(session, &initial).await?;
    set_management_grants(
        &member,
        json!([
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
        ]),
    )
    .await?;
    let router = initial;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let hosted = router.clone();
    let task = tokio::spawn(async move { axum::serve(listener, hosted).await });
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
        let response=browser.call(&router,Method::POST,&format!("/api/v2/groups/{blocked}"),Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"input":{"action":"create","name":"csrf-must-not-write","description":"","criteria":null}}))).await?;
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
    let group_path = format!("/api/v2/groups/{group}");
    call(&mut browser,&router,&group_path,0,json!({"action":"create","name":"managed","description":"","criteria":{"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"Model-A"}}})).await?;
    let (_, current) = browser
        .call(&router, Method::GET, &group_path, None)
        .await?;
    let revision = current["group"]["revision"].as_u64().unwrap();
    let accepted = call(
        &mut browser,
        &router,
        &format!("{group_path}/previews"),
        revision,
        json!({}),
    )
    .await?;
    let result_path = format!(
        "{group_path}/results/{}/members",
        accepted["task"].as_str().unwrap()
    );
    let (status, preview) = browser
        .call(&router, Method::GET, &result_path, None)
        .await?;
    ensure!(
        status == StatusCode::OK && preview["page"]["items"] == json!(["device-1"]),
        "trusted inventory mapping: {preview}"
    );
    pg("UPDATE mdm.inventory SET value='Model-B' WHERE field='device.model'")?;
    await_ingress().await?;
    // Immutable previews retain their fixed input even after a fact writer advances it.
    ensure!(
        browser
            .call(&router, Method::GET, &result_path, None)
            .await?
            .1
            == preview
    );
    let (_, current) = browser
        .call(&router, Method::GET, &group_path, None)
        .await?;
    let changed = call(
        &mut browser,
        &router,
        &format!("{group_path}/previews"),
        current["group"]["revision"].as_u64().unwrap(),
        json!({}),
    )
    .await?;
    let (_, members) = browser
        .call(
            &router,
            Method::GET,
            &format!(
                "{group_path}/results/{}/members",
                changed["task"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        members["page"]["items"] == json!([]),
        "new watermark did not observe the changed fact: {members}"
    );
    pg("UPDATE mdm.inventory SET value='Model-A' WHERE field='device.model'")?;
    await_ingress().await?;
    // The old synchronous endpoint and snapshot request shape are gone.
    ensure!(
        browser
            .call(
                &router,
                Method::GET,
                &format!("{group_path}/preview?expectedRevision=1"),
                None
            )
            .await?
            .0
            == StatusCode::NOT_FOUND
    );
    let stale = json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":revision,"input":{"action":"recompute","snapshot":"obsolete"}});
    ensure!(
        browser
            .call(&router, Method::POST, &group_path, Some(stale))
            .await?
            .0
            .is_client_error()
    );
    let second = format!("scope-second-{}", uuid::Uuid::new_v4());
    let third = format!("scope-third-{}", uuid::Uuid::new_v4());
    for device in [&second, &third] {
        seed_management_device(device)?;
    }
    await_ingress().await?;
    let target_group = uuid::Uuid::new_v4();
    let limit_group = uuid::Uuid::new_v4();
    for (id, members) in [
        (target_group, json!(["device-1", second, third])),
        (limit_group, json!(["device-1", second])),
    ] {
        let path = format!("/api/v2/groups/{id}");
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
    let scope_receipt = call(&mut browser,&router,&format!("/api/v2/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"group","id":target_group}],"limitations":[{"kind":"group","id":limit_group}],"exclusions":[{"kind":"device","id":second}]}})).await?;
    let resource_path = format!("/api/v3/resources/{resource}");
    call(
        &mut browser,
        &router,
        &resource_path,
        0,
        json!({"action":"create","kind":"configuration"}),
    )
    .await?;
    call(&mut browser,&router,&resource_path,1,json!({"action":"version","version":"v1","kind":"configuration","variants":[{"platform":"windows","architecture":"x86_64","key":"config","declaration":{"kind":"configuration","artifact":{"reference":"config","length":1,"sha256":vec![1;32]},"schema":"v1","apply":"set","detect":"get","remove":null}}]})).await?;
    let policy_path = format!("/api/v2/policies/{policy}");
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
    let planned_id = planned["task"].as_str().unwrap();
    let (_, targets) = browser
        .call(
            &router,
            Method::GET,
            &format!("{policy_path}/results/{planned_id}/targets"),
            None,
        )
        .await?;
    let (_, intents) = browser
        .call(
            &router,
            Method::GET,
            &format!("{policy_path}/results/{planned_id}/add"),
            None,
        )
        .await?;
    ensure!(
        targets["page"]["items"] == json!(["device-1"])
            && intents["page"]["items"][0]["kind"] == "add",
        "policy result: {targets} {intents}"
    );
    Box::pin(derived_result_authorization(
        &mut browser,
        &router,
        &member,
        &group_path,
        accepted["task"].as_str().unwrap(),
        scope,
        scope_receipt["task"].as_str().unwrap(),
        &policy_path,
        planned_id,
    ))
    .await?;
    let (_, decisions) = browser
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v2/scopes/{scope}/results/{}/decisions",
                scope_receipt["task"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    let explanations = decisions["page"]["items"].as_array().unwrap();
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
    let facts_before = pg("SELECT count(*) FROM mdm_policy.facts")?;
    let saved = call(
        &mut browser,
        &router,
        &format!("{policy_path}/plans"),
        revision,
        json!({"preview":planned["task"]}),
    )
    .await?;
    ensure!(saved["plan"].is_string() && saved["dispatch"] == "not_requested");
    ensure!(
        pg("SELECT count(*) FROM mdm_policy.facts")? == facts_before,
        "save created execution facts"
    );
    let policy_state = browser
        .call(&router, Method::GET, &policy_path, None)
        .await?
        .1;
    ensure!(policy_state["plan"] == saved["plan"] && policy_state["status"] == "active");

    let stored = browser
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v2/plan-previews/{}",
                planned["task"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(
        stored.0 == StatusCode::OK
            && stored.1["status"] == "completed"
            && stored.1["plan"] == saved["plan"]
    );
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
        &format!("/api/v2/groups/{limit_group}"),
        2,
        json!({"action":"members","add":[],"remove":["device-1"]}),
    )
    .await?;
    ensure!(settled_write(&mut browser,&router,&format!("{policy_path}/plans"),json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":current_revision,"input":{"preview":stale["task"]}})).await?.0==StatusCode::CONFLICT);
    scale_preview(&mut browser, &router, &policy_path, current_revision).await?;
    // Revocation is persistent and visible to every existing router/session.
    software(base, reader.clone(), session).await?;
    set_management_grants(&member, json!([])).await?;
    let restricted = app(base, reader).await?;
    let mut denied = session.clone();
    for path in [&group_path, &policy_path, &resource_path] {
        ensure!(
            denied.call(&restricted, Method::GET, path, None).await?.0 == StatusCode::FORBIDDEN
        );
    }
    set_management_grants(&member, json!(["group_write"])).await?;
    pg("REVOKE INSERT ON mdm_access.audit FROM mdm_management_runtime")?;
    let failed=browser.call(&router,Method::POST,&format!("/api/v2/groups/{}",uuid::Uuid::new_v4()),Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"input":{"action":"create","name":"must-rollback","description":"","criteria":null}}))).await?;
    pg("GRANT INSERT ON mdm_access.audit TO mdm_management_runtime")?;
    ensure!(failed.0 == StatusCode::SERVICE_UNAVAILABLE);
    ensure!(pg("SELECT count(*) FROM mdm_group.groups WHERE name='must-rollback'")?.trim() == "0");
    ensure!(automation.shutdown().join().await?.is_clean());
    println!("MDM_MANAGEMENT_HTTP_MATRIX_PASSED");
    Ok(())
}

async fn software(base: &Value, reader: Arc<InventoryReader>, session: &Browser) -> Result<()> {
    let server = publication_support::Server::new().await;
    let mut cfg = base.clone();
    let source_config = |ring: &str| json!({"Winget":{"base":format!("{}{ring}/",server.base),"addresses":[server.address],"private_ca":server.ca,"credential_reference":"source-key","credential_file":server.secret}});
    cfg["management"]["sources"] = json!([{"name":server.logical,"rings":{"test":source_config("test"),"pilot":source_config("pilot"),"production":source_config("production")},"artifacts":[{"base":format!("{}artifacts/",server.base),"addresses":[server.address],"private_ca":server.ca}],"max_artifact_bytes":1048576}]);
    let initial = app(&cfg, reader.clone()).await?;
    let member = browser_subject(session, &initial).await?;
    let publisher_grants = json!([
        "resource_read",
        "resource_write",
        "release_read",
        "release_write",
        "release_validate",
        "release_publish",
        "release_recover",
        "release_withdraw"
    ]);
    set_management_grants(&member, publisher_grants.clone()).await?;
    let mut approver = Browser::default();
    approver.login(&initial, "admin").await?;
    let subject = approver
        .call(&initial, Method::GET, "/api/v1/authorization", None)
        .await?
        .1["principalId"]
        .clone();
    set_management_grants(
        subject.as_str().unwrap(),
        json!(["release_read", "release_approve"]),
    )
    .await?;
    permission_matrix(&cfg, reader.clone(), session).await?;
    set_management_grants(&member, publisher_grants.clone()).await?;
    set_management_grants(
        subject.as_str().unwrap(),
        json!(["release_read", "release_approve"]),
    )
    .await?;
    let router = app(&cfg, reader).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let hosted = router.clone();
    let task = tokio::spawn(async move { axum::serve(listener, hosted).await });
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
    let resource_path = format!("/api/v3/resources/{resource}");
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
    let approval = json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":validated["revision"],"input":{"action":"approve","ring":"test","publisherSubject":member}});
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
    // Hold the actual management lock after HTTP admission, revoke, then let the intent finish.
    use sqlx::Connection;
    let mut holder =
        sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
    sqlx::query("SELECT pg_advisory_lock(hashtextextended($1,2390))")
        .bind(TENANT)
        .execute(&mut holder)
        .await?;
    let posts_before = server.state.lock().unwrap().posts;
    let mut delayed = publisher.clone();
    let revoke = async {
        let deadline = rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
            + Duration::from_millis(750);
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='mdm_management_runtime' AND wait_event='advisory')").fetch_one(&mut holder).await?;
            if waiting {
                break;
            }
            ensure!(
                rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer) < deadline,
                "publication did not wait at management lock"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        set_management_grants(&member, json!([])).await?;
        sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1,2390))")
            .bind(TENANT)
            .execute(&mut holder)
            .await?;
        anyhow::Ok(())
    };
    let (delayed, revoked) = tokio::join!(
        delayed.call(&router, Method::POST, &path, Some(request.clone())),
        revoke
    );
    holder.close().await?;
    revoked?;
    set_management_grants(&member, publisher_grants).await?;
    ensure!(
        delayed?.0 == StatusCode::FORBIDDEN,
        "delayed publication used revoked permission"
    );
    ensure!(
        server.state.lock().unwrap().posts == posts_before,
        "revoked publication reached source"
    );
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
        "INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{TENANT}','{grant}','fixture','{INSTANCE}','{device}','enrollment','consumed',clock_timestamp()+interval '200 seconds');INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source) VALUES('{TENANT}','{request}','{grant}','mdm.windows');INSERT INTO mdm_access.devices VALUES('{TENANT}','{device}');INSERT INTO mdm_access.registrations VALUES('{TENANT}','{registration}','{device}','mdm',1,'{request}','active'); INSERT INTO mdm_access.credentials VALUES('{TENANT}',gen_random_uuid(),'{registration}','mdm',md5('{registration}')||md5('{registration}'),'active'); INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) VALUES('{TENANT}','{registration}','mdm.windows','77777777-7777-4777-8777-777777777777','device-basics/2/model-os/typed-v2',true);"
    ))?;
    Ok(())
}
// Establish a settled fixture boundary before introducing definitions: prior
// enrollment/report writes legitimately supersede a concurrent preview.
async fn await_ingress() -> Result<()> {
    let settled=tokio::time::timeout(Duration::from_secs(90),async {
        loop {
            let ready=pg(&format!("SELECT coalesce((SELECT consumed FROM mdm_management.asset_dispatch WHERE tenant_id='{TENANT}'),0)=coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id='{TENANT}'),0) AND NOT EXISTS(SELECT 1 FROM mdm_management.automation_jobs WHERE tenant_id='{TENANT}' AND NOT completed)"))?;
            if ready.trim()=="t" { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }).await;
    if let Ok(outcome) = settled {
        return outcome;
    }
    let progress = pg(&format!(
        "SELECT jsonb_build_object('clock',(SELECT revision FROM mdm.asset_clock WHERE tenant_id='{TENANT}'),'checkpoint',(SELECT to_jsonb(d)-'group_cursor' FROM mdm_management.asset_dispatch d WHERE tenant_id='{TENANT}'),'jobs',(SELECT jsonb_agg(p) FROM (SELECT j.id,j.kind,j.forwarded,j.failure,r.phase,r.object_count FROM mdm_management.automation_jobs j LEFT JOIN mdm_group.member_runs r ON (r.tenant_id,r.id)=(j.tenant_id,j.id) WHERE j.tenant_id='{TENANT}' AND NOT j.completed ORDER BY j.id LIMIT 16)p))"
    ))?;
    anyhow::bail!("fixture ingress did not settle: {progress}")
}

async fn scale_preview(
    browser: &mut Browser,
    router: &Router,
    policy: &str,
    revision: u64,
) -> Result<()> {
    let prefix = uuid::Uuid::new_v4();
    pg(&format!(
        "CREATE TEMP TABLE scale_devices AS SELECT '{prefix}-'||n::text AS device,gen_random_uuid() AS grant_id,gen_random_uuid() AS request,gen_random_uuid() AS registration FROM generate_series(1,1001) n;INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) SELECT '{TENANT}',grant_id,'fixture','{INSTANCE}',device,'enrollment','consumed',clock_timestamp()+interval '200 seconds' FROM scale_devices;INSERT INTO mdm_access.requests(tenant_id,id,grant_id,source) SELECT '{TENANT}',request,grant_id,'mdm.windows' FROM scale_devices;INSERT INTO mdm_access.devices SELECT '{TENANT}',device FROM scale_devices;INSERT INTO mdm_access.registrations SELECT '{TENANT}',registration,device,'mdm',1,request,'active' FROM scale_devices; INSERT INTO mdm_access.credentials SELECT '{TENANT}',gen_random_uuid(),registration,'mdm',md5(registration::text)||md5(registration::text),'active' FROM scale_devices; INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,coverage,enabled) SELECT '{TENANT}',registration,'mdm.windows','77777777-7777-4777-8777-777777777777','device-basics/2/model-os/typed-v2',true FROM scale_devices;"
    ))?;
    await_ingress().await?;
    let group = uuid::Uuid::new_v4();
    let scope = uuid::Uuid::new_v4();
    let group_path = format!("/api/v2/groups/{group}");
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
    call(browser,router,&format!("/api/v2/scopes/{scope}"),0,json!({"action":"put","definition":{"targets":[{"kind":"group","id":group}],"limitations":null,"exclusions":[]}})).await?;
    let preview = call(
        browser,
        router,
        &format!("{policy}/previews"),
        revision,
        json!({"scope":scope,"expectedRevision":revision}),
    )
    .await?;
    let task = preview["task"].as_str().unwrap();
    ensure!(policy_item_count(browser, router, policy, task, "targets").await? == 1001);
    let facts_before = pg("SELECT count(*) FROM mdm_policy.facts")?;
    let saved = call(
        browser,
        router,
        &format!("{policy}/plans"),
        revision,
        json!({"preview":task}),
    )
    .await?;
    ensure!(
        pg("SELECT count(*) FROM mdm_policy.facts")? == facts_before,
        "save created execution facts"
    );
    let revision = saved["receipt"]["storageRevision"].as_u64().unwrap();
    let next = call(
        browser,
        router,
        &format!("{policy}/previews"),
        revision,
        json!({"scope":scope,"expectedRevision":revision}),
    )
    .await?;
    let task = next["task"].as_str().unwrap();
    ensure!(policy_item_count(browser, router, policy, task, "targets").await? == 1001);
    ensure!(policy_item_count(browser, router, policy, task, "add").await? == 1001);
    ensure!(policy_item_count(browser, router, policy, task, "retain").await? == 0);
    Ok(())
}

async fn policy_item_count(
    browser: &mut Browser,
    router: &Router,
    policy: &str,
    task: &str,
    kind: &str,
) -> Result<usize> {
    let mut cursor = None;
    let mut count = 0;
    loop {
        let mut path = format!("{policy}/results/{task}/{kind}?limit=500");
        if let Some(c) = &cursor {
            path.push_str(&format!("&cursor={c}"));
        }
        let (status, page) = browser.call(router, Method::GET, &path, None).await?;
        ensure!(status == StatusCode::OK, "policy page: {status} {page}");
        let items = page["page"]["items"].as_array().unwrap();
        ensure!(items.len() <= 500);
        count += items.len();
        cursor = page["nextCursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            return Ok(count);
        }
    }
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
            format!("/api/v2/groups/{id}"),
            None,
        ),
        (
            "group_write",
            Method::POST,
            format!("/api/v2/groups/{id}"),
            op(json!({"action":"edit","name":"denied","description":""})),
        ),
        (
            "group_recompute",
            Method::POST,
            format!("/api/v2/groups/{id}"),
            op(json!({"action":"recompute"})),
        ),
        (
            "scope_read",
            Method::GET,
            format!("/api/v2/scopes/{id}"),
            None,
        ),
        (
            "scope_write",
            Method::POST,
            format!("/api/v2/scopes/{id}"),
            op(json!({"action":"delete"})),
        ),
        (
            "policy_read",
            Method::GET,
            format!("/api/v2/policies/{id}"),
            None,
        ),
        (
            "policy_write",
            Method::POST,
            format!("/api/v2/policies/{id}"),
            op(json!({"action":"pause"})),
        ),
        (
            "plan_preview",
            Method::POST,
            format!("/api/v2/policies/{id}/previews"),
            op(json!({"scope":id,"expectedRevision":999})),
        ),
        (
            "plan_save",
            Method::POST,
            format!("/api/v2/policies/{id}/plans"),
            op(json!({"preview":id})),
        ),
        (
            "resource_read",
            Method::GET,
            format!("/api/v3/resources/{id}"),
            None,
        ),
        (
            "resource_write",
            Method::POST,
            format!("/api/v3/resources/{id}"),
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
            op(json!({"action":"approve","ring":"test","publisherSubject":ADMIN})),
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
            Method::POST,
            format!("/api/v2/groups/{id}/previews"),
            op(json!({})),
        ),
        (
            "policy_read",
            Method::GET,
            format!("/api/v2/plan-previews/{id}"),
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
            "SELECT jsonb_build_array((SELECT count(*) FROM mdm_group.groups),(SELECT count(*) FROM mdm_management.operations),(SELECT count(*) FROM mdm_management.scope_versions),(SELECT count(*) FROM mdm_management.automation_jobs),(SELECT count(*) FROM mdm_management.policy_assignments),(SELECT count(*) FROM mdm_software_composition.subjects))::text",
        )
    };
    // Exercise every permission change against the same running service. Rebuilding
    // full applications per grant needlessly multiplies component connection pools.
    let router = app(base, reader).await?;
    let member = browser_subject(session, &router).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let hosted = router.clone();
    let _server = Server(tokio::spawn(
        async move { axum::serve(listener, hosted).await },
    ));
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
    for grant in &grants {
        set_management_grants(&member, json!([grant])).await?;
        set_management_grants(ADMIN, json!(["release_publish"])).await?;
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
    }
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.audit WHERE target='{id}' AND result='denied' AND action IN ('management_read','management_write','plan_preview','plan_save') AND actor IS NOT NULL AND instance='{INSTANCE}'"))?.trim()==expected_denied.to_string(),"denied action/target/actor audit incomplete");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn derived_result_authorization(
    browser: &mut Browser,
    router: &Router,
    member: &str,
    group: &str,
    group_result: &str,
    scope: uuid::Uuid,
    scope_result: &str,
    policy: &str,
    policy_result: &str,
) -> Result<()> {
    let permissions = json!([
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
    let mut paths = vec![
        format!("{group}/tasks/{group_result}"),
        format!("/api/v2/scopes/{scope}/tasks/{scope_result}"),
        format!("/api/v2/plan-previews/{policy_result}"),
    ];
    for kind in ["members", "changes", "decisions"] {
        paths.push(format!("{group}/results/{group_result}/{kind}?limit=1"));
    }
    for kind in ["members", "decisions"] {
        paths.push(format!(
            "/api/v2/scopes/{scope}/results/{scope_result}/{kind}?limit=1"
        ));
    }
    for kind in [
        "targets",
        "add",
        "supersede",
        "retain",
        "cancel",
        "predecessors",
    ] {
        paths.push(format!("{policy}/results/{policy_result}/{kind}?limit=1"));
    }
    // Keep an actually issued cursor, then shrink the subject's device access.
    let (status, page) = Box::pin(browser.call(router, Method::GET, &paths[3], None)).await?;
    ensure!(status == StatusCode::OK, "authorized derived page: {page}");
    let cursor = page["nextCursor"].as_str().unwrap();
    paths.push(format!("{}&cursor={cursor}", paths[3]));
    let criteria = json!({"kind":"predicate","field":"device.model","op":"eq","value":{"kind":"string","value":"Model-A"}});
    for limited in [false, true] {
        let mut grants = permissions
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                Ok(crate::authorization::Grant {
                    operation: serde_json::from_value(p.clone())?,
                    scope: crate::authorization::Scope::Tenant,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if limited {
            grants.extend(crate::identity_fixture::device_grants(
                Some("device-1"),
                &["inventory_read"],
            )?);
        }
        Box::pin(crate::identity_fixture::set_grants(TENANT, member, grants)).await?;
        let before = pg(
            "SELECT jsonb_build_array((SELECT count(*) FROM mdm_group.groups),(SELECT count(*) FROM mdm_management.automation_jobs))",
        )?;
        for (path, revision, input) in [
            (
                format!("/api/v2/groups/{}", uuid::Uuid::new_v4()),
                0,
                json!({"action":"create","name":"denied-dynamic","description":"","criteria":criteria}),
            ),
            (
                group.to_owned(),
                0,
                json!({"action":"rule","criteria":criteria}),
            ),
        ] {
            let (status,body)=browser.call(router,Method::POST,&path,Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":revision,"input":input}))).await?;
            ensure!(
                status == StatusCode::FORBIDDEN,
                "derived writer accepted absent/full-inventory gap: {status} {body}"
            );
        }
        for path in &paths {
            let (status, body) = Box::pin(browser.call(router, Method::GET, path, None)).await?;
            ensure!(
                status == StatusCode::FORBIDDEN,
                "derived page leaked after inventory grant shrink at {path}: {status} {body}"
            );
        }
        ensure!(
            pg(
                "SELECT jsonb_build_array((SELECT count(*) FROM mdm_group.groups),(SELECT count(*) FROM mdm_management.automation_jobs))"
            )? == before,
            "denied dynamic write enqueued work"
        );
    }
    Box::pin(set_management_grants(member, permissions)).await?;
    for path in &paths {
        let (status, body) = Box::pin(browser.call(router, Method::GET, path, None)).await?;
        ensure!(
            status == StatusCode::OK,
            "restored full inventory grant: {path} {status} {body}"
        );
    }
    Ok(())
}
