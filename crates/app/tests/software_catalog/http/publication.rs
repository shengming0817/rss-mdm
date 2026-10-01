mod brew;
use crate::test_support::software::write;
use crate::test_support::software_execution::{self as execution, Platform};
use crate::test_support::*;
use sha2::{Digest, Sha256};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=software.http"]
async fn publication_http_authority_receipts_and_public_native_binding() -> Result<()> {
    let server = publication_support::Server::new().await;
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let cfg = publication_http::configuration(&base, &server);
    let mut local = execution::context(Platform::Windows);
    local["interactiveUser"] = json!({"identity":"S-1-5-21-100-200-300-1001","sessionId":Uuid::new_v4(),"administrator":true});
    let mut f = execution::Fixture::with_config(
        Platform::Windows,
        json!([
            "inventory.collect.v5",
            "software.msi.system.v5",
            "software.winget.system.v5"
        ]),
        local.clone(),
        cfg.clone(),
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
        "software_approve",
        "software_withdraw",
        "policy_read",
        "policy_write",
        "scope_read",
        "scope_write",
        "release_read",
        "release_write",
        "release_validate",
        "release_publish",
        "release_recover",
        "release_withdraw",
    ] {
        grants.push(crate::authorization::Grant {
            operation: serde_json::from_value(json!(name))?,
            scope: crate::authorization::Scope::Tenant,
        });
    }
    crate::test_support::identity::set_grants(case_tenant(), &subject, grants).await?;
    let stack = execution::worker_for(&serde_json::from_value(cfg)?, f.execution.clone()).await?;
    let resource = Uuid::new_v4();
    let resource_path = format!("/api/v3/resources/{resource}");
    let bytes = b"frozen native MSI bytes";
    let invocation = json!({"runAs":"system","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let definition = json!({"source":f.source_snapshot,"package":"Acme.App","version":"1.0","provenance":{"kind":"private"},"artifacts":{"package":{"reference":"installer","length":bytes.len(),"sha256":<[u8;32]>::from(Sha256::digest(bytes))}},"behavior":{"kind":"winget","installer":"package","scope":"system","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1.0"}},"signatures":[],"reboot":"report","downgrade":"deny","ownership":"managed_only","dependencies":[],"export":{"kind":"winget","locale":"en-US","name":"Acme App","publisher":"Acme","description":"Frozen enterprise application","license":"Proprietary"}});
    write(
        &mut f.author,
        &f.router,
        &resource_path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    write(&mut f.author,&f.router,&resource_path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":"windows","architecture":"x86_64","key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
    execution::upload_windows(&f.author, &f.router, &resource_path, bytes).await?;
    write(
        &mut f.author,
        &f.router,
        &resource_path,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let admitted = write(
        &mut f.author,
        &f.router,
        &format!("/api/v3/software/resources/{resource}/versions/v1"),
        0,
        json!({"action":"approve","evidence":["frozen enterprise materials"]}),
    )
    .await?;
    let catalog = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v3/software/resources/{resource}/versions/v1"),
            None,
        )
        .await?;
    let path = format!(
        "/api/v1/software-sources/{}/candidates/{}",
        server.logical,
        Uuid::new_v4()
    );
    let input = json!({"action":"candidate","resource":resource,"version":"v1","expectedResourceRevision":3,"resourceDigest":catalog.1["resourceDigest"]});
    let operation = Uuid::new_v4();
    let request = json!({"operationId":operation,"expectedRevision":0,"input":input});
    let mut old = request.clone();
    old["input"]["document"] = json!({});
    let malformed = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header("host", "mdm.example.test")
        .header("origin", "https://mdm.example.test")
        .header("x-identity-request", "1")
        .header("x-csrf-token", f.author.csrf.as_ref().unwrap())
        .header(
            "cookie",
            f.author
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&old)?))?;
    ensure!(
        f.router.clone().oneshot(malformed).await?.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "independent manifest input accepted"
    );
    let csrf = f.author.csrf.take();
    ensure!(
        f.author
            .call(&f.router, Method::POST, &path, Some(request.clone()))
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    f.author.csrf = csrf;
    let candidate = f
        .author
        .call(&f.router, Method::POST, &path, Some(request.clone()))
        .await?;
    ensure!(candidate.0 == StatusCode::OK, "candidate: {candidate:?}");
    let replay = f
        .author
        .call(&f.router, Method::POST, &path, Some(request))
        .await?;
    ensure!(
        replay.0 == StatusCode::OK && replay.1 == candidate.1,
        "candidate replay: {replay:?}"
    );
    let validated = write(
        &mut f.author,
        &f.router,
        &path,
        candidate.1["revision"].as_u64().unwrap(),
        json!({"action":"validate","ring":"test"}),
    )
    .await?;
    let mut approver = Browser::default();
    ensure!(approver.login(&f.router, "admin").await? == StatusCode::OK);
    let approver_subject = browser_subject(&approver, &f.router).await?;
    let grants = ["release_read", "release_approve"]
        .into_iter()
        .map(|name| {
            Ok(crate::authorization::Grant {
                operation: serde_json::from_value(json!(name))?,
                scope: crate::authorization::Scope::Tenant,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    crate::test_support::identity::set_grants(case_tenant(), &approver_subject, grants).await?;
    let approved = write(
        &mut approver,
        &f.router,
        &path,
        validated["revision"].as_u64().unwrap(),
        json!({"action":"approve","ring":"test","publisherSubject":subject}),
    )
    .await?;
    let authorized = write(
        &mut f.author,
        &f.router,
        &path,
        approved["revision"].as_u64().unwrap(),
        json!({"action":"authorize","ring":"test"}),
    )
    .await?;
    let publication = &authorized["rings"][0]["publication"];
    let id = publication["id"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| format!("{:02x}", n.as_u64().unwrap()))
        .collect::<String>();
    let native = format!(
        "/software/native/sources/{}/test/exports/{id}",
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
    let published=write(&mut f.author,&f.router,&path,authorized["revision"].as_u64().unwrap(),json!({"action":"publish","ring":"test","publication":publication["id"],"attempt":publication["attempt"]})).await?;
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
        format!("/software/native/sources/{}/test", server.logical),
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
    let policy_path = format!("/api/v2/policies/{policy}");
    write(&mut f.author,&f.router,&policy_path,0,json!({"action":"put","enabled":true,"definition":{"scope":f.scope,"action":{"kind":"software","resource":{"kind":"software","id":resource,"version":"v1","variants":{"windows_x86_64":"default"}},"intent":"required_install","delivery":{"kind":"native","source":server.logical,"ring":"test"},"admissionOperation":admitted["admission"]["operation"],"runLifetimeSeconds":600,"rollout":{"stages":[{"scope":f.scope,"opensAt":0}]}}}})).await?;
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
        let probe_path = format!("/api/v2/policies/{policy}/devices");
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
                "/api/agent/v5/tasks/claim",
                Some(&f.credential),
                Some(
                    json!({"wireVersion":5,"executionContext":local,"operationId":Uuid::new_v4()}),
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
        task["payload"]["steps"][0]["export"]["kind"] == "winget"
            && task["payload"]["steps"][0]["export"]["uri"]
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
        &path,
        published["revision"].as_u64().unwrap(),
        json!({"action":"withdraw","ring":"test"}),
    )
    .await?;
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
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
