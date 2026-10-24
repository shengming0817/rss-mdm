#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios retain distinct authorization, failure and recovery assertions"
)]
use super::*;
use crate::audit_test_support::audit_count;
async fn history_boundaries(
    b: &mut Browser,
    router: &Router,
    base: &Value,
    token: &str,
    rule_path: &str,
    task: &str,
    subject: &str,
) -> Result<()> {
    let history = "/api/v1/devices/compliance-a/compliance/history";
    for filter in ["from=0", "until=9999999999"] {
        ensure!(
            b.call(
                router,
                Method::GET,
                &format!("{history}?cursor={token}&{filter}"),
                None
            )
            .await?
            .0 == StatusCode::BAD_REQUEST
        );
    }
    let mut other = Browser::default();
    ensure!(other.login(router, "other").await? == StatusCode::OK);
    let other_subject = browser_subject(&other, router).await?;
    crate::test_support::identity::seed_grants(
        case_tenant(),
        &other_subject,
        crate::test_support::identity::device_grants(None, &["compliance_read"])?,
    )
    .await?;
    ensure!(other.call(router, Method::GET, history, None).await?.0 == StatusCode::OK);
    ensure!(
        other
            .call(
                router,
                Method::GET,
                &format!("{history}?cursor={token}"),
                None
            )
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    for device in [None, Some("compliance-a")] {
        let mut limited = vec![crate::authorization::Grant {
            operation: crate::authorization::Permission::ComplianceRuleRead,
            scope: crate::authorization::Scope::Tenant,
        }];
        if let Some(device) = device {
            limited.extend(crate::test_support::identity::device_grants(
                Some(device),
                &["compliance_read"],
            )?);
        }
        crate::test_support::identity::change_grants(case_tenant(), subject, limited).await?;
        ensure!(b.call(router, Method::GET, rule_path, None).await?.0 == StatusCode::OK);
        ensure!(
            b.call(
                router,
                Method::GET,
                &format!("{rule_path}/tasks/{task}"),
                None
            )
            .await?
            .0 == StatusCode::FORBIDDEN
        );
    }
    grants(subject, None).await?;
    let tenant = case::peer();
    let config = crate::test_support::identity::config(tenant)?;
    let access = database(base).await?;
    let audit = access.audit_store_fixture(&config.audit).await?;
    let (other_router, _, _, _, resources) = crate::api::application_fixture(
        config,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        access,
        None,
        audit,
    )
    .await?;
    resources
        .finish(async {
            let other_router = other_router.layer(axum::Extension(
                rss_identity_http_axum::ClientAddress("127.0.0.1".parse()?),
            ));
            pg_tenant(
                tenant,
                &format!("INSERT INTO mdm_access.devices VALUES('{tenant}','compliance-a')"),
            )?;
            crate::test_support::identity::seed_grants(
                tenant,
                case::context().admin_for(tenant),
                crate::test_support::identity::device_grants(None, &["compliance_read"])?,
            )
            .await?;
            let mut cross = Browser::default();
            ensure!(
                cross
                    .call(
                        &other_router,
                        Method::POST,
                        &format!("/api/v1/identity/tenants/{tenant}/login"),
                        Some(json!({"login":case::login("admin"),"password":PASSWORD}))
                    )
                    .await?
                    .0
                    == StatusCode::OK
            );
            ensure!(
                cross
                    .call(&other_router, Method::GET, history, None)
                    .await?
                    .0
                    == StatusCode::OK
            );
            ensure!(
                cross
                    .call(
                        &other_router,
                        Method::GET,
                        &format!("{history}?cursor={token}"),
                        None
                    )
                    .await?
                    .0
                    == StatusCode::BAD_REQUEST
            );
            Ok(())
        })
        .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.http: real HTTP and durable worker contract"]
async fn http_history_cursors_authorization_and_disable() -> Result<()> {
    let fixture = Fixture::open().await?;
    let router = &fixture.router;
    let base = &fixture.base;
    let mut browser = fixture.browser.clone();
    let subject = &fixture.subject;
    let initial = status(&mut browser, router, "compliance-a", "unknown").await?;
    ensure!(initial["reason"] == "no_rules");
    let (_, path, written) = fixture.rule().await?;
    let (s, _) = browser
        .call(
            router,
            Method::PUT,
            &path,
            Some(request(0, definition(json!({"kind":"all"})))),
        )
        .await?;
    ensure!(s == StatusCode::CONFLICT);
    ensure!(
        status(&mut browser, router, "compliance-a", "pending").await?["rules"][0]["current"]
            .is_null()
    );
    let queued = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{path}/tasks/{}", written["task"].as_str().unwrap()),
        None,
    )
    .await?;
    ensure!(queued["phase"] == "queued" && queued["processed"] == 0);
    let list = ok(
        &mut browser,
        router,
        Method::GET,
        "/api/v1/compliance-rules",
        None,
    )
    .await?;
    ensure!(list.get("nextCursor").is_some() && list["items"][0].get("currentRun").is_none());
    let automation = start_automation(base).await?;
    status(&mut browser, router, "compliance-a", "unknown").await?;
    assign(&mut browser, router, "compliance-a", 0, false).await?;
    let old =
        status(&mut browser, router, "compliance-a", "compliant").await?["rules"][0]["current"]
            .clone();
    assign(&mut browser, router, "compliance-a", 1, true).await?;
    status(&mut browser, router, "compliance-a", "non_compliant").await?;
    let history = ok(
        &mut browser,
        router,
        Method::GET,
        "/api/v1/devices/compliance-a/compliance/history",
        None,
    )
    .await?;
    ensure!(
        history["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["status"] == "compliant" && v["factWatermark"] == old["factWatermark"]),
        "history was rewritten"
    );
    let original = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{path}/versions/1"),
        None,
    )
    .await?;
    ensure!(original["definition"]["target"]["kind"] == "all");
    let first = ok(
        &mut browser,
        router,
        Method::GET,
        "/api/v1/devices/compliance-a/compliance/history?limit=1",
        None,
    )
    .await?;
    let next = first["nextCursor"].as_str().unwrap();
    let second = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("/api/v1/devices/compliance-a/compliance/history?limit=1&cursor={next}"),
        None,
    )
    .await?;
    for page in [&first, &second] {
        ensure!(page["items"].as_array().unwrap().len() == 1);
        Uuid::parse_str(page["items"][0]["task"].as_str().unwrap())?;
    }
    ensure!(first["items"][0]["task"] != second["items"][0]["task"]);
    let (s, _) = browser
        .call(
            router,
            Method::GET,
            &format!("/api/v1/devices/compliance-b/compliance/history?cursor={next}"),
            None,
        )
        .await?;
    ensure!(
        s == StatusCode::BAD_REQUEST,
        "history cursor was reused for a different device"
    );
    history_boundaries(
        &mut browser,
        router,
        base,
        next,
        &path,
        written["task"].as_str().unwrap(),
        subject,
    )
    .await?;
    // Device-scoped authorization applies equally to history and current results.
    grants(subject, Some("compliance-a")).await?;
    for suffix in ["compliance", "compliance/history"] {
        let (s, _) = browser
            .call(
                router,
                Method::GET,
                &format!("/api/v1/devices/compliance-b/{suffix}"),
                None,
            )
            .await?;
        ensure!(s == StatusCode::FORBIDDEN);
    }
    let (s, _) = browser.call(router, Method::GET, &path, None).await?;
    ensure!(s == StatusCode::FORBIDDEN);
    let (s, _) = browser
        .call(
            router,
            Method::POST,
            &format!("{path}/recompute"),
            Some(request(2, json!({}))),
        )
        .await?;
    ensure!(s == StatusCode::FORBIDDEN);
    let (s, _) = browser
        .call(
            router,
            Method::GET,
            &format!("{path}/tasks/{}", written["task"].as_str().unwrap()),
            None,
        )
        .await?;
    ensure!(s == StatusCode::FORBIDDEN);
    grants(subject, None).await?;
    // Disabling removes the rule from the aggregate but preserves all previous evidence.
    let mut def = definition(json!({"kind":"all"}));
    def["enabled"] = json!(false);
    ok(
        &mut browser,
        router,
        Method::PUT,
        &path,
        Some(request(1, def)),
    )
    .await?;
    ensure!(status(&mut browser, router, "compliance-a", "unknown").await?["reason"] == "no_rules");
    let retained = ok(
        &mut browser,
        router,
        Method::GET,
        "/api/v1/devices/compliance-a/compliance/history",
        None,
    )
    .await?;
    let tasks: std::collections::BTreeSet<_> = retained["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["task"].as_str().unwrap())
        .collect();
    ensure!(
        history["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| tasks.contains(v["task"].as_str().unwrap()))
    );

    let another = Uuid::new_v4();
    let another_path = format!("/api/v1/compliance-rules/{another}");
    let mut disabled = definition(json!({"kind":"all"}));
    disabled["enabled"] = json!(false);
    ok(
        &mut browser,
        router,
        Method::PUT,
        &another_path,
        Some(request(0, disabled)),
    )
    .await?;
    let base = "/api/v1/compliance-rules?filter=enabled==false;severity==high&sort=revision&fields=id,revision&limit=1";
    let page = ok(&mut browser, router, Method::GET, base, None).await?;
    ensure!(page["items"] == json!([{"id":another,"revision":1}]));
    let cursor = page["nextCursor"].as_str().unwrap();
    let last = ok(
        &mut browser,
        router,
        Method::GET,
        &format!("{base}&cursor={cursor}"),
        None,
    )
    .await?;
    ensure!(last["items"][0]["revision"] == 2 && last["nextCursor"].is_null());
    let deletion = request(2, json!({}));
    let receipt = ok(
        &mut browser,
        router,
        Method::DELETE,
        &path,
        Some(deletion.clone()),
    )
    .await?;
    ensure!(receipt["deleted"] == true && receipt["revision"] == 3);
    ensure!(ok(&mut browser, router, Method::DELETE, &path, Some(deletion)).await? == receipt);
    ensure!(browser.call(router, Method::GET, &path, None).await?.0 == StatusCode::NOT_FOUND);
    ensure!(
        browser
            .call(
                router,
                Method::PUT,
                &path,
                Some(request(3, definition(json!({"kind":"all"}))))
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    ensure!(
        ok(
            &mut browser,
            router,
            Method::GET,
            &format!("{path}/versions/1"),
            None
        )
        .await?["definition"]["enabled"]
            == true
    );
    let removed = ok(
        &mut browser,
        router,
        Method::GET,
        "/api/v1/compliance-rules?filter=deleted==true",
        None,
    )
    .await?;
    ensure!(
        removed["items"].as_array().unwrap().len() == 1 && removed["items"][0]["enabled"] == false
    );
    ensure!(
        ok(
            &mut browser,
            router,
            Method::GET,
            "/api/v1/devices/compliance-a/compliance/history",
            None
        )
        .await?["items"]
            == retained["items"]
    );
    ensure!(audit_count(|r| r.action() == "compliance_read").await? > 0);
    crate::test_support::runtime::stop_worker(automation).await?;
    fixture.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=compliance.http: queued Delete must recheck authorization before writes"]
async fn queued_delete_observes_permission_revocation() -> Result<()> {
    use sqlx::Connection;
    let fixture = Fixture::open().await?;
    let (id, path, _) = fixture.rule().await?;
    let mut browser = fixture.browser.clone();
    let mut observer =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let mut hold = observer.begin().await?;
    crate::Database::configure_transaction(&mut hold, case_tenant()).await?;
    rss_mdm_inventory_postgres::lock_watermark_in(
        &mut hold,
        rss_request_context::TenantId::parse(case_tenant())?,
    )
    .await?;
    let release = async {
        tokio::time::timeout(Duration::from_secs(3),async{
            loop{
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='mdm_flow_runtime' AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) AND query LIKE '%mdm.lock_asset_watermark%')").fetch_one(&mut *hold).await?;
                if waiting{break;}
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *hold).await?;
                tokio::task::yield_now().await;
            }
            Ok::<_,anyhow::Error>(())
        }).await??;
        // Authentication and its original snapshot completed before the write reached the barrier.
        grants(&fixture.subject, Some("compliance-a")).await?;
        hold.commit().await?;
        Ok::<_, anyhow::Error>(())
    };
    let (response, released) = tokio::join!(
        browser.call(
            &fixture.router,
            Method::DELETE,
            &path,
            Some(request(1, json!({})))
        ),
        release
    );
    released?;
    observer.close().await?;
    ensure!(
        response?.0 == StatusCode::FORBIDDEN,
        "queued delete ignored revoked write permission"
    );
    let deleted: bool = serde_json::from_str(&pg(&format!(
        "SELECT deleted::text FROM mdm_compliance.rules WHERE tenant_id='{}' AND id='{id}'",
        case_tenant()
    ))?)?;
    ensure!(!deleted);

    crate::test_support::identity::change_grants(
        case_tenant(),
        &fixture.subject,
        vec![crate::authorization::Grant {
            operation: crate::authorization::Permission::ComplianceWrite,
            scope: crate::authorization::Scope::Tenant,
        }],
    )
    .await?;
    let attempted = browser
        .call(
            &fixture.router,
            Method::PUT,
            &path,
            Some(request(1, definition(json!({"kind":"all"})))),
        )
        .await?;
    ensure!(
        attempted.0 == StatusCode::FORBIDDEN,
        "ComplianceWrite without InventoryRead changed an asset rule"
    );
    grants(&fixture.subject, None).await?;
    ensure!(ok(&mut browser, &fixture.router, Method::GET, &path, None).await?["revision"] == 1);
    fixture.close().await;
    Ok(())
}
