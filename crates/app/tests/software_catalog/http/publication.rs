use crate::test_support::planning_http::*;
use crate::test_support::*;
use anyhow::Context;
#[tokio::test]
#[ignore = "make t2 MODULE=software.http"]
async fn publication_http_authority_receipts_and_unknown_outcome() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let base = &fixture.base;
    let reader = authority::reader(base).await?;
    let session = &fixture.browser("other")?;
    let server = publication_support::Server::new().await;
    let cfg = publication_http::configuration(base, &server);
    let initial = app(&cfg, reader.clone()).await?;
    let member = browser_subject(session, &initial).await?;
    let publisher_grants = json!([
        "group_read",
        "group_write",
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
    set_management_grants(&member, publisher_grants.clone()).await?;
    set_management_grants(
        subject.as_str().unwrap(),
        json!(["release_read", "release_approve"]),
    )
    .await?;
    let router = app(&cfg, reader.clone()).await?;
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
    let shared_operation = uuid::Uuid::new_v4();
    let resource_request = json!({"operationId":shared_operation,"expectedRevision":0,"input":{"action":"create","kind":"software"}});
    let (status, resource_receipt) = settled_write(
        &mut publisher,
        &router,
        &resource_path,
        resource_request.clone(),
    )
    .await?;
    ensure!(status.is_success(), "resource identity: {resource_receipt}");
    let shared_group = format!("/api/v2/groups/{}", uuid::Uuid::new_v4());
    let group_request = json!({"operationId":shared_operation,"expectedRevision":0,"input":{"action":"create","name":"owner-scoped-operation","description":"","criteria":null}});
    let (status, group_receipt) = settled_write(
        &mut publisher,
        &router,
        &shared_group,
        group_request.clone(),
    )
    .await?;
    ensure!(status.is_success(), "planning identity: {group_receipt}");
    let shared_saved = format!("/api/v2/saved-queries/{}", uuid::Uuid::new_v4());
    let saved_request = json!({"operationId":shared_operation,"expectedRevision":0,"input":{"action":"put","definition":{"name":"owner-scoped-operation","query":{}}}});
    let (status, saved_receipt) = publisher
        .call(
            &router,
            Method::PUT,
            &shared_saved,
            Some(saved_request.clone()),
        )
        .await?;
    ensure!(status.is_success(), "assets identity: {saved_receipt}");
    let variants=[("x86_64","x64"),("aarch64","arm64")].iter().map(|(arch,key)|json!({"platform":"windows","architecture":arch,"key":"msi.machine.no-id","declaration":{"kind":"software","definition":crate::publication_support::software_definition(&server.logical,"Acme.App","1",rss_mdm_resource::Platform::Windows,key)}})).collect::<Vec<_>>();
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
                "SELECT count(*) FROM mdm_publication.operations WHERE id='{blocked}'"
            ))?
            .trim()
                == "0"
        );
    }
    publisher.csrf = original_csrf;
    let bad_operation = uuid::Uuid::new_v4();
    let (bad_status,_)=publisher.call(&router,Method::POST,&path,Some(json!({"operationId":bad_operation,"expectedRevision":0,"input":{"action":"candidate","resource":"missing","version":"v1","expectedResourceRevision":1,"submission":server.winget_submission()}}))).await?;
    ensure!(bad_status.is_client_error());
    ensure!(
        audit_count(|r| r.source() == "mdm.business"
            && r.operation() == Some(bad_operation.to_string().as_str())
            && r.result() == "success")?
        .to_string()
            == "0",
        "failed publication intent claimed success"
    );
    ensure!(
        audit_count(
            |r| r.operation() == Some(bad_operation.to_string().as_str())
                && r.result() == "unknown"
                && r.status() == 202
                && r.payload["software"]["stage"] == "management_admission"
        )?
        .to_string()
            == "1"
    );
    let candidate_request = json!({"operationId":shared_operation,"expectedRevision":0,"input":{"action":"candidate","resource":resource,"version":"v1","expectedResourceRevision":2,"submission":server.winget_submission()}});
    let (status, candidate) =
        settled_write(&mut publisher, &router, &path, candidate_request.clone()).await?;
    ensure!(status.is_success(), "publication identity: {candidate}");
    ensure!(pg(&format!("SELECT (SELECT count(*) FROM mdm_resource_catalog.operations WHERE id='{shared_operation}')+(SELECT count(*) FROM mdm_assets.group_operations WHERE id='{shared_operation}')+(SELECT count(*) FROM mdm_assets.operations WHERE id='{shared_operation}')+(SELECT count(*) FROM mdm_publication.operations WHERE id='{shared_operation}')"))?.trim()=="4");
    let event_count = audit_count(|r| {
        r.source() == "mdm.business"
            && matches!(r.action(), "management_write" | "software_preflight")
            && r.operation() == Some(shared_operation.to_string().as_str())
    })?;
    ensure!(
        event_count >= 4,
        "each owner must retain an independent business event; found {event_count}"
    );
    for (method, route, request, expected) in [
        (
            Method::POST,
            &resource_path,
            resource_request,
            &resource_receipt,
        ),
        (
            Method::POST,
            &shared_group,
            group_request.clone(),
            &group_receipt,
        ),
        (Method::PUT, &shared_saved, saved_request, &saved_receipt),
        (Method::POST, &path, candidate_request, &candidate),
    ] {
        let replay = publisher
            .call(&router, method, route, Some(request))
            .await?;
        ensure!(
            replay.0.is_success() && &replay.1 == expected,
            "owner replay {route}: {replay:?}"
        );
    }
    ensure!(
        audit_count(|r| r.source() == "mdm.business"
            && matches!(r.action(), "management_write" | "software_preflight")
            && r.operation() == Some(shared_operation.to_string().as_str()))?
            == event_count
    );
    let mut conflict = group_request;
    conflict["input"]["name"] = json!("different-request");
    let rejected = publisher
        .call(&router, Method::POST, &shared_group, Some(conflict))
        .await?;
    ensure!(
        rejected.0 == StatusCode::CONFLICT,
        "same-owner identity conflict: {rejected:?}"
    );
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
    // Let revocation own Audit before publication starts. Hold its authorization
    // lock until publication is visibly waiting on Audit, then release in lock order.
    use sqlx::Connection;
    let mut holder =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let authorization_key = format!("{TENANT}:{INSTANCE}", TENANT = case_tenant());
    sqlx::query("SELECT pg_advisory_lock(hashtextextended($1,2363))")
        .bind(&authorization_key)
        .execute(&mut holder)
        .await?;
    let posts_before = server.state.lock().unwrap().posts;
    let mut delayed = publisher.clone();
    let begin_publication = tokio::sync::Notify::new();
    let release = async {
        for (phase, query) in [
            (
                "revocation authorization lock",
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='mdm_access' AND wait_event_type='Lock' AND query LIKE '%2363%')",
            ),
            (
                "publication Audit lock",
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='mdm_flow_runtime' AND wait_event_type='Lock' AND query LIKE '%rss_audit.reserve%')",
            ),
        ] {
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if sqlx::query_scalar::<_, bool>(query)
                        .fetch_one(&mut holder)
                        .await?
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Ok::<_, sqlx::Error>(())
            })
            .await
            .with_context(|| format!("missing barrier: {phase}"))??;
            begin_publication.notify_one();
        }
        sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1,2363))")
            .bind(&authorization_key)
            .execute(&mut holder)
            .await?;
        anyhow::Ok(())
    };
    let (delayed, revoked, released) = tokio::join!(
        async {
            begin_publication.notified().await;
            delayed
                .call(&router, Method::POST, &path, Some(request.clone()))
                .await
        },
        set_management_grants(&member, json!([])),
        release,
    );
    released?;
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
    ensure!(
        audit_count(|r| r.operation() == Some(operation.to_string().as_str())
            && r.action() == "management_write"
            && r.result() == "unknown")?
        .to_string()
            == "1"
    );
    let (status, published) = publisher
        .call(&router, Method::POST, &path, Some(request.clone()))
        .await?;
    ensure!(
        status == StatusCode::OK && published["rings"][0]["publication"]["outcome"] == "published",
        "publish: {status} {published}"
    );
    let publication_operation = request["operationId"].as_str().unwrap().to_owned();
    ensure!(
        audit_count(
            |r| r.operation() == Some(publication_operation.to_string().as_str())
                && r.action() == "management_write"
                && r.result() == "success"
        )?
        .to_string()
            == "1",
        "first publication mislabeled as replay"
    );
    ensure!(
        publisher
            .call(&router, Method::POST, &path, Some(request))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        audit_count(|r| r.source() == "mdm.request"
            && r.operation() == Some(publication_operation.to_string().as_str())
            && r.action() == "management_write"
            && r.result() == "replay")?
        .to_string()
            == "1",
        "terminal retry was not audited as replay"
    );
    ensure!(
        server.state.lock().unwrap().posts == 1,
        "HTTP replay republished content"
    );
    ensure!(
        audit_count(|r| r.action() == "software_approve"
            && r.actor() == subject.as_str()
            && r.payload["instance"] == INSTANCE)?
        .to_string()
            == "1",
        "approval lost real actor"
    );
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
    ensure!(
        audit_count(|r| r.operation() == Some(operation.to_string().as_str())
            && r.action() == "management_write"
            && r.result() == "success")?
        .to_string()
            == "1",
        "unpublished withdrawal replay was marked as performed"
    );
    ensure!(
        audit_count(|r| r.source() == "mdm.request"
            && r.operation() == Some(operation.to_string().as_str())
            && r.action() == "management_write"
            && r.result() == "replay")?
        .to_string()
            == "1"
    );
    let fresh = json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":withdrawn["revision"],"input":{"action":"withdraw","ring":"pilot"}});
    ensure!(
        publisher
            .call(&router, Method::POST, &path, Some(fresh.clone()))
            .await?
            .0
            == StatusCode::OK
    );
    let operation = fresh["operationId"].as_str().unwrap();
    ensure!(
        audit_count(|r| r.operation() == Some(operation.to_string().as_str())
            && r.action() == "management_write"
            && r.result() == "success")?
        .to_string()
            == "1"
    );
    reader.close().await;
    Ok(())
}
