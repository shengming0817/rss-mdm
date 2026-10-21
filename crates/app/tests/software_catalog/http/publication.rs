mod brew;
use crate::test_support::software::write;
use crate::test_support::software_execution::{self as execution, Platform};
use crate::test_support::{agent::*, http::*, runtime::*, *};
use sha2::{Digest, Sha256};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=software.http"]
async fn publication_http_authority_receipts_and_public_native_binding() -> Result<()> {
    let server = publication_support::Server::new().await;
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let mut cfg = publication_http::configuration(&base, &server);
    let secondary = format!("{}-secondary", server.logical);
    let mut target_config = cfg["flow"]["publication"]["sources"][0].clone();
    target_config["name"] = json!(secondary);
    target_config["target"]["Winget"]["base"] = json!(format!(
        "{}/api/v1/software/native/sources/{secondary}/",
        base["product_origin"].as_str().unwrap()
    ));
    target_config["target"]["Winget"]["artifacts_base"] = json!(format!(
        "{}/api/v1/software/native/sources/{secondary}/artifacts/",
        base["product_origin"].as_str().unwrap()
    ));
    cfg["flow"]["publication"]["sources"]
        .as_array_mut()
        .unwrap()
        .push(target_config);
    let mut local = execution::context(Platform::Windows);
    local["interactiveUser"] = json!({"generatedUid":null,"identity":"S-1-5-21-100-200-300-1001","sessionId":Uuid::new_v4(),"administrator":true});
    let mut f = execution::Fixture::with_config(
        Platform::Windows,
        json!([
            "inventory.collect.v1",
            "software.msi.system.v1",
            "software.winget.system.v1"
        ]),
        local.clone(),
        cfg.clone(),
        false,
        false,
    )
    .await?;
    let subject = browser_subject(&f.author, &f.router).await?;
    let mut grants = crate::test_support::identity::device_grants(
        None,
        &[
            "enrollment",
            "inventory_read",
            "software_deploy",
            "operation_read",
        ],
    )?;
    for name in [
        "resource_read",
        "resource_write",
        "software_read",
        "software_write",
        "software_withdraw",
        "policy_read",
        "policy_write",
        "scope_read",
        "scope_write",
        "release_read",
        "release_publish",
        "release_recover",
        "release_withdraw",
    ] {
        grants.push(crate::authorization::Grant {
            operation: serde_json::from_value(json!(name))?,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    crate::test_support::identity::set_grants(case_tenant(), &subject, grants.clone()).await?;
    let stack = execution::worker_for(
        &serde_json::from_value(cfg)?,
        f.execution.clone(),
        Default::default(),
    )
    .await?;
    let resource = Uuid::new_v4();
    let resource_path = format!("/api/v1/resources/{resource}");
    let bytes = b"frozen native MSI bytes";
    let invocation = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let definition = json!({"source":f.source_snapshot,"package":"Acme.App","version":"1.0","provenance":{"kind":"private"},"artifacts":{"package":{"reference":"installer","length":bytes.len(),"sha256":<[u8;32]>::from(Sha256::digest(bytes))}},"behavior":{"kind":"winget","installer":"package","scope":"system","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1.0"}},"signatures":[],"reboot":"report","downgrade":"deny","dependencies":[],"export":{"kind":"winget","locale":"en-US","name":"Acme App","publisher":"Acme","description":"Frozen enterprise application","license":"Proprietary"}});
    write(
        &mut f.author,
        &f.router,
        &resource_path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    write(&mut f.author,&f.router,&resource_path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":"windows","architecture":"x86_64","key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
    execution::upload_windows(&f.author, &f.router, resource, bytes).await?;
    let catalog = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/software/resources/{resource}/versions/v1"),
            None,
        )
        .await?;
    let targets = f
        .author
        .call(
            &f.router,
            Method::GET,
            "/api/v1/software/publication-targets?limit=1",
            None,
        )
        .await?;
    ensure!(targets.0 == StatusCode::OK && targets.1["items"].as_array().unwrap().len() == 1);
    let target = targets.1["items"][0].clone();
    ensure!(target["id"] == server.logical);
    ensure!(targets.1["nextCursor"] == server.logical);
    let target_page = discovery_page(
        &mut f,
        &format!(
            "/api/v1/software/publication-targets?limit=1&after={}",
            server.logical
        ),
    )
    .await?;
    ensure!(
        target_page["items"].as_array().unwrap().len() == 1
            && target_page["items"][0]["id"] == secondary
    );
    ensure!(target_page["nextCursor"].is_null());
    let secondary_target = target_page["items"][0].clone();
    let empty = discovery_page(
        &mut f,
        &format!("/api/v1/software/publication-targets?after={secondary}"),
    )
    .await?;
    ensure!(empty["items"] == json!([]) && empty["nextCursor"].is_null());
    let source = Uuid::new_v4().to_string();
    for revision in ["a", "b"] {
        write(&mut f.author, &f.router, &format!("/api/v1/software/sources/{source}/revisions/{revision}"), 0,
            json!({"action":"register","definition":{"id":source,"revision":revision,"protocol":{"kind":"private"}}})).await?;
    }
    write(
        &mut f.author,
        &f.router,
        &format!("/api/v1/software/sources/{source}/revisions/b"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    let source_url = format!("/api/v1/software/sources?source={source}&limit=1");
    let sources = discovery_page(&mut f, &source_url).await?;
    ensure!(
        sources["items"].as_array().unwrap().len() == 1
            && sources["items"][0]["source"]["revision"] == "a"
    );
    let cursor = sources["nextCursor"].as_str().unwrap();
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("after", cursor)
        .finish();
    let sources = discovery_page(&mut f, &format!("{source_url}&{query}")).await?;
    ensure!(
        sources["items"].as_array().unwrap().len() == 1
            && sources["items"][0]["source"]["revision"] == "b"
    );
    ensure!(sources["nextCursor"].is_null());
    for (filter, expected) in [
        ("protocol=private", 2),
        ("protocol=winget_rest", 0),
        ("state=enabled", 1),
        ("state=disabled", 1),
    ] {
        let page = discovery_page(
            &mut f,
            &format!("/api/v1/software/sources?source={source}&{filter}"),
        )
        .await?;
        ensure!(
            page["items"].as_array().unwrap().len() == expected,
            "source filter {filter}: {page}"
        );
        if expected == 1 {
            ensure!(
                page["items"][0]["lifecycle"]["state"] == filter.strip_prefix("state=").unwrap()
            );
        }
    }
    let missing = discovery_page(
        &mut f,
        &format!("/api/v1/software/sources?source={}", Uuid::new_v4()),
    )
    .await?;
    ensure!(missing["items"] == json!([]));
    let input = json!({"action":"publish","resource":resource,"version":"v1","expectedResourceRevision":2,"resourceDigest":catalog.1["resourceDigest"],"target":server.logical,"targetDigest":target["digest"]});
    let operation = Uuid::new_v4();
    let request = json!({"operationId":operation,"expectedRevision":0,"input":input});
    let collection = "/api/v1/software/publications";
    let path = format!("{collection}/{operation}");
    let mut malformed = request.clone();
    malformed["input"]["unexpected"] = json!(true);
    ensure!(
        f.author
            .call(&f.router, Method::POST, collection, Some(malformed))
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    let csrf = f.author.csrf.take();
    ensure!(
        f.author
            .call(&f.router, Method::POST, collection, Some(request.clone()))
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    f.author.csrf = csrf;
    let without_enable = grants
        .iter()
        .filter(|g| g.operation != crate::authorization::Permission::SoftwareWrite)
        .cloned()
        .collect();
    crate::test_support::identity::set_grants(case_tenant(), &subject, without_enable).await?;
    let denied = f
        .author
        .call(&f.router, Method::POST, collection, Some(request.clone()))
        .await?;
    ensure!(
        denied.0 == StatusCode::FORBIDDEN,
        "draft permission: {denied:?}"
    );
    ensure!(f.author.call(&f.router, Method::GET, &path, None).await?.0 == StatusCode::NOT_FOUND);
    crate::test_support::identity::set_grants(case_tenant(), &subject, grants).await?;
    let accepted = f
        .author
        .call(&f.router, Method::POST, collection, Some(request.clone()))
        .await?;
    ensure!(
        accepted.0 == StatusCode::ACCEPTED,
        "direct publish: {accepted:?}"
    );
    let pending = accepted.1;
    let replay = f
        .author
        .call(&f.router, Method::POST, collection, Some(request))
        .await?;
    ensure!(
        replay.0 == StatusCode::ACCEPTED
            && replay.1["id"] == pending["id"]
            && replay.1["attempt"] == 1
    );
    let found = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("{collection}?operationId={operation}"),
            None,
        )
        .await?;
    ensure!(found.0 == StatusCode::OK && found.1["items"][0]["id"] == operation.to_string());
    let other_operation = Uuid::new_v4();
    let mut other_input = input.clone();
    other_input["target"] = json!(secondary);
    other_input["targetDigest"] = secondary_target["digest"].clone();
    let other = f
        .author
        .call(
            &f.router,
            Method::POST,
            collection,
            Some(json!({"operationId":other_operation,"expectedRevision":0,"input":other_input})),
        )
        .await?;
    ensure!(other.0 == StatusCode::ACCEPTED, "second target: {other:?}");
    let mut ids = [operation.to_string(), other_operation.to_string()];
    ids.sort();
    let first_page =
        discovery_page(&mut f, &format!("{collection}?resource={resource}&limit=1")).await?;
    ensure!(
        first_page["items"].as_array().unwrap().len() == 1
            && first_page["items"][0]["id"] == ids[0]
    );
    ensure!(first_page["nextCursor"] == ids[0] && first_page["items"][0].get("document").is_none());
    let last_page = discovery_page(
        &mut f,
        &format!("{collection}?resource={resource}&limit=1&after={}", ids[0]),
    )
    .await?;
    ensure!(
        last_page["items"].as_array().unwrap().len() == 1 && last_page["items"][0]["id"] == ids[1]
    );
    ensure!(last_page["nextCursor"].is_null());
    for (filter, expected) in [
        (format!("target={}", server.logical), Some(operation)),
        (format!("target={secondary}"), Some(other_operation)),
        ("target=missing".into(), None),
        ("version=v1".into(), Some(operation)),
        ("version=missing".into(), None),
        (format!("operationId={operation}"), Some(operation)),
        (format!("operationId={}", Uuid::new_v4()), None),
    ] {
        let page = discovery_page(
            &mut f,
            &format!("{collection}?resource={resource}&{filter}"),
        )
        .await?;
        let items = page["items"].as_array().unwrap();
        if let Some(id) = expected {
            ensure!(
                items.iter().any(|item| item["id"] == id.to_string()),
                "record filter {filter}: {page}"
            );
            if !filter.starts_with("version=") {
                ensure!(items.len() == 1);
            }
        } else {
            ensure!(items.is_empty(), "record filter {filter}: {page}");
        }
    }
    let missing =
        discovery_page(&mut f, &format!("{collection}?resource={}", Uuid::new_v4())).await?;
    ensure!(missing["items"] == json!([]));
    let id = pending["publication"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| format!("{:02x}", n.as_u64().unwrap()))
        .collect::<String>();
    let native = format!(
        "/api/v1/software/native/sources/{}/exports/{id}",
        server.logical
    );
    let public = |method: Method, url: String, body: Body| {
        Request::builder()
            .method(method)
            .uri(url)
            .header("host", "mdm.example.test")
            .header("Version", "1.0.0")
            .header("content-type", "application/json")
            .body(body)
    };
    ensure!(
        f.router
            .clone()
            .oneshot(public(
                Method::GET,
                format!("{native}/information"),
                Body::empty()
            )?)
            .await?
            .status()
            == StatusCode::NOT_FOUND
    );
    let recovery = json!({"operationId":Uuid::new_v4(),"expectedRevision":pending["revision"],"input":{"action":"recover"}});
    let published = f
        .author
        .call(&f.router, Method::POST, &path, Some(recovery.clone()))
        .await?;
    ensure!(published.0 == StatusCode::OK && published.1["outcome"] == "published");
    ensure!(published.1["revision"] != pending["revision"]);
    let replayed = f
        .author
        .call(&f.router, Method::POST, &path, Some(recovery.clone()))
        .await?;
    ensure!(replayed.0 == StatusCode::OK && replayed.1 == published.1);
    let found = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!(
                "{collection}?operationId={}",
                recovery["operationId"].as_str().unwrap()
            ),
            None,
        )
        .await?;
    ensure!(found.0 == StatusCode::OK && found.1["items"][0]["id"] == published.1["id"]);

    let info = f
        .router
        .clone()
        .oneshot(public(
            Method::GET,
            format!("{native}/information"),
            Body::empty(),
        )?)
        .await?;
    ensure!(info.status() == StatusCode::OK);
    ensure!(info.headers()["cache-control"] == "no-store");
    let search = f
        .router
        .clone()
        .oneshot(public(
            Method::POST,
            format!("{native}/manifestSearch"),
            Body::from(serde_json::to_vec(
                &json!({"Query":{"KeyWord":"Acme.App","MatchType":"Exact"}}),
            )?),
        )?)
        .await?;
    ensure!(search.status() == StatusCode::OK);
    let search: Value = serde_json::from_slice(&search.into_body().collect().await?.to_bytes())?;
    ensure!(search["Data"][0]["PackageIdentifier"] == "Acme.App");
    for prefix in [
        native.clone(),
        format!("/api/v1/software/native/sources/{}", server.logical),
    ] {
        let response = f
            .router
            .clone()
            .oneshot(public(
                Method::GET,
                format!("{prefix}/packageManifests/Acme.App"),
                Body::empty(),
            )?)
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "native exact ID request without Version: {}",
            response.status()
        );
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
        ensure!(body["Data"]["Versions"][0]["PackageVersion"] == "1.0");
    }
    let manifest = f
        .router
        .clone()
        .oneshot(public(
            Method::GET,
            format!("{native}/packageManifests/Acme.App?Version=1.0"),
            Body::empty(),
        )?)
        .await?;
    ensure!(manifest.status() == StatusCode::OK);
    let manifest: Value =
        serde_json::from_slice(&manifest.into_body().collect().await?.to_bytes())?;
    let artifact = url::Url::parse(
        manifest["Data"]["Versions"][0]["Installers"][0]["InstallerUrl"]
            .as_str()
            .unwrap(),
    )?
    .path()
    .to_owned();
    let served = f
        .router
        .clone()
        .oneshot(public(Method::GET, artifact.clone(), Body::empty())?)
        .await?;
    ensure!(served.status() == StatusCode::OK);
    ensure!(served.into_body().collect().await?.to_bytes() == bytes.as_slice());
    let policy = Uuid::new_v4();
    let policy_path = format!("/api/v1/policies/{policy}");
    write(&mut f.author,&f.router,&policy_path,0,json!({"action":"put","enabled":true,"definition":{"scope":f.scope,"action":{"kind":"software","resource":{"kind":"software","id":resource,"version":"v1","variants":{"windows_x86_64":"default"}},"intent":"required_install","delivery":{"kind":"native","target":server.logical},"runLifetimeSeconds":600,"rollout":{"stages":[{"scope":f.scope,"opensAt":0}]}}}})).await?;
    {
        use sqlx::Connection;
        let mut owner =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        sqlx::query("BEGIN").execute(&mut owner).await?;
        let catalog_lock = format!("mdm-software:{}", case_tenant());
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&catalog_lock)
            .execute(&mut owner)
            .await?;
        let probe_path = format!("/api/v1/policies/{policy}/assignments");
        let request = f.author.call(&f.router, Method::GET, &probe_path, None);
        tokio::pin!(request);
        tokio::select! {
            response=&mut request=>anyhow::bail!("support query bypassed catalog gate: {response:?}"),
            result=tokio::time::timeout(Duration::from_secs(10),async {
                loop {
                    let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND classid::bigint=((hashtextextended($1,0)>>32)&4294967295) AND objid::bigint=(hashtextextended($1,0)&4294967295))").bind(&catalog_lock).fetch_one(&mut owner).await?;
                    if waiting {break anyhow::Ok(());}
                    tokio::task::yield_now().await;
                }
            })=>result??,
        }
        let free: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,2388))")
                .bind(format!(
                    "mdm_resource:{}:resource:{resource}",
                    case_tenant()
                ))
                .fetch_one(&mut owner)
                .await?;
        sqlx::query("ROLLBACK").execute(&mut owner).await?;
        let response = request.await?;
        ensure!(
            free,
            "support query acquired Resource before software catalog lock"
        );
        ensure!(response.0 == StatusCode::OK, "support probe: {response:?}");
        owner.close().await?;
    }
    let task = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let r = agent_call(
                &f.router,
                Method::POST,
                "/api/v1/agent/runtime/tasks/claim",
                Some(&f.credential),
                Some(
                    json!({"wireVersion":1,"executionContext":local,"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":[],"operationId":Uuid::new_v4()}),
                ),
            )
            .await?;
            ensure!(r.0 == StatusCode::OK, "claim: {r:?}");
            if !r.1["task"].is_null() {
                break anyhow::Ok(r.1["task"].clone());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    ensure!(
        task["payload"]["task"]["steps"][0]["export"]["kind"] == "winget"
            && task["payload"]["task"]["steps"][0]["export"]["uri"]
                .as_str()
                .unwrap()
                .contains(&id),
        "binding: {task}"
    );
    ensure!(
        execution::event_with(&f.router, &f.credential, &task, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    write(
        &mut f.author,
        &f.router,
        &format!("/api/v1/software/resources/{resource}/versions/v1"),
        1,
        json!({"action":"withdraw"}),
    )
    .await?;
    let revoked = f.author.call(&f.router, Method::GET, &path, None).await?;
    ensure!(
        revoked.0 == StatusCode::OK
            && revoked.1["withdrawn"] == true
            && !revoked.1["withdrawal"].is_null()
    );
    let completed = write(
        &mut f.author,
        &f.router,
        &path,
        revoked.1["revision"].as_u64().unwrap(),
        json!({"action":"recover"}),
    )
    .await?;
    ensure!(completed["withdrawal"] == "withdrawn");
    ensure!(
        execution::event_with(&f.router, &f.credential, &task, json!({"kind":"start"}))
            .await?
            .0
            == StatusCode::FORBIDDEN,
        "withdrawn export started"
    );
    for url in [format!("{native}/information"), artifact] {
        ensure!(
            f.router
                .clone()
                .oneshot(public(Method::GET, url, Body::empty())?)
                .await?
                .status()
                == StatusCode::NOT_FOUND
        );
    }
    ensure!(
        server.state.lock().unwrap().posts == 0 && server.state.lock().unwrap().deletes == 0,
        "owned source used external writes"
    );
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
}

async fn discovery_page(f: &mut execution::Fixture, url: &str) -> Result<Value> {
    let response = f.author.call(&f.router, Method::GET, url, None).await?;
    ensure!(
        response.0 == StatusCode::OK,
        "discovery {url}: {response:?}"
    );
    Ok(response.1)
}
