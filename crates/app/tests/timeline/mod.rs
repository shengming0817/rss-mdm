//! Real administrator HTTP, PostgreSQL audit facts and the production projection task.
#![allow(
    clippy::cognitive_complexity,
    reason = "integration scenarios keep assertions together"
)]
use crate::test_support::*;
use rss_mdm_timeline_service::Timeline;
use rss_request_context::TenantId;
use uuid::Uuid;
struct Fixture {
    authority: authority::Authority,
    router: Router,
    admin: Browser,
    timeline: Arc<Timeline>,
}
impl Fixture {
    async fn open() -> Result<Self> {
        let authority = authority::Authority::open().await?;
        let config: Config = serde_json::from_value(authority.base.clone())?;
        let (router, _, runtime) = crate::api::application_fixture(
            config,
            Arc::new(crate::clock::SystemClock),
            monotonic(),
            authority.access.clone(),
            None,
            authority.audit.clone(),
        )
        .await?;
        let tenant = TenantId::parse(case_tenant())?;
        let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant).await?;
        let timeline = authority
            .access
            .timeline(authority.audit.clone(), tenant, &key)?;
        timeline.initialize().await?;
        let admin = authority.browser("admin")?;
        let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse()?,
        )));
        Ok(Self {
            authority,
            router,
            admin,
            timeline,
        })
    }
    async fn catch_up(&self) -> Result<()> {
        for _ in 0..100 {
            if self.timeline.catch_up().await? == 0 {
                return Ok(());
            }
        }
        anyhow::bail!("projection did not drain bounded fixture")
    }
    async fn get(&mut self, path: &str) -> Result<Value> {
        let (status, value) = self
            .admin
            .call(&self.router, Method::GET, path, None)
            .await?;
        ensure!(
            status == StatusCode::OK,
            "timeline {path}: {status} {value}"
        );
        Ok(value)
    }
}
#[tokio::test]
#[ignore = "make t2 MODULE=timeline.http"]
async fn existing_business_facts_are_queryable_over_real_http() -> Result<()> {
    let mut f = Fixture::open().await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let router = f.router.clone();
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let _server = crate::test_support::planning_http::Server(server);
    f.admin.network = Some((
        Client::builder().no_proxy().build()?,
        format!("http://{address}"),
    ));
    let device = case::name("timeline-device");
    let subject = browser_subject(&f.admin, &f.router).await?;
    let mut grants = identity::device_grants(
        Some(device),
        &[
            "enrollment",
            "credentials",
            "inventory_read",
            "inventory_assign",
        ],
    )?;
    grants.extend(
        [
            crate::authorization::Permission::AuthorizationRead,
            crate::authorization::Permission::AuthorizationWrite,
        ]
        .map(|operation| crate::authorization::Grant {
            operation,
            scope: crate::authorization::Scope::Tenant,
        }),
    );
    identity::set_grants(case_tenant(), &subject, grants).await?;
    let operation = Uuid::new_v4();
    f.admin.operation = Some(operation);
    let (status,issued)=f.admin.call(&f.router,Method::POST,"/api/v3/enrollments",Some(json!({"deviceId":device,"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows"}))).await?;
    ensure!(status == StatusCode::OK);
    let enrollment = issued["enrollmentId"].as_str().unwrap();
    ensure!(
        f.admin
            .call(
                &f.router,
                Method::GET,
                &format!("/api/v3/enrollments/{enrollment}"),
                None
            )
            .await?
            .0
            == StatusCode::OK
    );
    f.admin.operation = Some(Uuid::new_v4());
    ensure!(
        f.admin
            .call(
                &f.router,
                Method::POST,
                &format!("/api/v3/enrollments/{enrollment}/resume"),
                Some(json!({"password":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"}))
            )
            .await?
            .0
            == StatusCode::OK
    );
    f.admin.operation = Some(Uuid::new_v4());
    ensure!(
        f.admin
            .call(
                &f.router,
                Method::POST,
                &format!("/api/v3/enrollments/{enrollment}/cancel"),
                Some(json!({}))
            )
            .await?
            .0
            == StatusCode::OK
    );
    let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
    let service = crate::device::DeviceService::new(
        f.authority.access.registration(),
        case_tenant().into(),
        f.authority.audit.clone(),
    );
    let channel =
        crate::device::test_support::proof(case_tenant(), rss_mdm_inventory::Channel::Mdm, 93);
    let (_, registration) =
        crate::device::test_support::bind(&service, &proof, &channel, device, 0).await?;
    f.admin.operation = Some(Uuid::new_v4());
    let (status, value) = f
        .admin
        .call(
            &f.router,
            Method::POST,
            &format!(
                "/api/v3/devices/{device}/registrations/{}/revoke",
                registration.registration
            ),
            Some(json!({})),
        )
        .await?;
    ensure!(status == StatusCode::OK, "revoke: {status} {value}");
    let manual = Uuid::new_v4();
    let (status,value)=f.admin.call(&f.router,Method::PUT,&format!("/api/v2/devices/{device}/manual-fields/custom.office_floor"),Some(json!({"operationId":manual,"expectedRevision":0,"input":{"action":"set","value":{"kind":"integer","value":9}}}))).await?;
    ensure!(status == StatusCode::OK, "manual: {status} {value}");
    // Replay and denied manual writes retain a source-owned device coordinate.
    let (replay_status,_)=f.admin.call(&f.router,Method::PUT,&format!("/api/v2/devices/{device}/manual-fields/custom.office_floor"),Some(json!({"operationId":manual,"expectedRevision":0,"input":{"action":"set","value":{"kind":"integer","value":9}}}))).await?;
    ensure!(replay_status == StatusCode::OK);
    let other = f.authority.browser("other")?;
    let denied_subject = browser_subject(&other, &f.router).await?;
    identity::set_grants(
        case_tenant(),
        &denied_subject,
        identity::device_grants(Some(device), &["inventory_read"])?,
    )
    .await?;
    let mut other = other;
    let denied = Uuid::new_v4();
    let (denied_status,_)=other.call(&f.router,Method::PUT,&format!("/api/v2/devices/{device}/manual-fields/custom.office_floor"),Some(json!({"operationId":denied,"expectedRevision":1,"input":{"action":"set","value":{"kind":"integer","value":10}}}))).await?;
    ensure!(denied_status == StatusCode::FORBIDDEN);
    // Actual management API denial is a persisted fact, never a fabricated execution success.
    let management = Uuid::new_v4();
    let (status, _) = f
        .admin
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v3/devices/{device}/operations/{management}"),
            None,
        )
        .await?;
    ensure!(status == StatusCode::FORBIDDEN);
    f.catch_up().await?;
    let page = f.get(&format!("/api/v3/devices/{device}/timeline")).await?;
    let items = page["items"].as_array().unwrap();
    for action in [
        "enrollment_create",
        "enrollment_read",
        "enrollment_resume",
        "enrollment_cancel",
        "registration_bind",
        "credential_revoke",
        "management_write",
        "command_read",
    ] {
        ensure!(
            items.iter().any(|v| v["action"] == action),
            "missing {action}: {items:?}"
        );
    }
    ensure!(items.iter().any(|v| v["source"] == "mdm.request"
        && v["operationId"] == manual.to_string()
        && v["deviceId"] == device));
    ensure!(items.iter().any(|v| v["source"] == "mdm.request"
        && v["operationId"] == denied.to_string()
        && v["auditOutcome"] == "denied"
        && v["deviceId"] == device));
    let stored = audit_records()?;
    for item in items {
        ensure!(
            stored
                .iter()
                .any(|r| r.decoded.event().identity().event_id().as_str()
                    == item["eventId"].as_str().unwrap())
        );
        ensure!(item["effect"] == "unknown");
    }
    let filtered = f
        .get(&format!("/api/v3/audit-events?operationId={manual}"))
        .await?;
    ensure!(!filtered["items"].as_array().unwrap().is_empty());
    ensure!(
        filtered["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["operationId"] == manual.to_string())
    );
    ensure!(!serde_json::to_string(&page)?.contains("AAAAAAAAAAAA"));
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=timeline.http"]
async fn fixed_watermark_pagination_survives_new_events_and_rebuild_rejects_old_cursor()
-> Result<()> {
    let mut f = Fixture::open().await?;
    for _ in 0..6 {
        f.get("/api/v3/audit-events").await?;
    }
    f.catch_up().await?;
    let all = f.get("/api/v3/audit-events").await?;
    let expected = all["items"].as_array().unwrap();
    let first = f.get("/api/v3/audit-events?limit=2").await?;
    let mut items = first["items"].as_array().unwrap().clone();
    let mut cursor = first["nextCursor"].as_str().map(str::to_owned);
    f.get("/api/v3/audit-events").await?;
    f.catch_up().await?;
    let stale = cursor.clone().unwrap();
    for _ in 0..50 {
        let Some(token) = cursor.take() else { break };
        let page = f
            .get(&format!("/api/v3/audit-events?limit=2&cursor={token}"))
            .await?;
        items.extend(page["items"].as_array().unwrap().clone());
        cursor = page["nextCursor"].as_str().map(str::to_owned);
    }
    ensure!(cursor.is_none());
    ensure!(&items == expected, "fixed window changed");
    ensure!(
        items
            .windows(2)
            .all(|w| (w[0]["recordedAt"].as_i64(), w[0]["position"].as_u64())
                > (w[1]["recordedAt"].as_i64(), w[1]["position"].as_u64()))
    );
    for path in [
        format!("/api/v3/audit-events?action=inventory_read&cursor={stale}"),
        format!("/api/v3/devices/absent/timeline?cursor={stale}"),
        "/api/v3/audit-events?cursor=invalid".into(),
        "/api/v3/audit-events?limit=201".into(),
    ] {
        let status = f.admin.call(&f.router, Method::GET, &path, None).await?.0;
        ensure!(
            status == StatusCode::CONFLICT || status == StatusCode::BAD_REQUEST,
            "cursor/input silently accepted: {status}"
        );
    }
    pg(&format!(
        "DELETE FROM mdm_timeline.facts WHERE tenant_id='{tenant}';UPDATE mdm_timeline.checkpoints SET generation='{generation}',position=-1,source_through=-1 WHERE tenant_id='{tenant}'",
        tenant = case_tenant(),
        generation = Uuid::new_v4()
    ))?;
    f.catch_up().await?;
    ensure!(
        f.admin
            .call(
                &f.router,
                Method::GET,
                &format!("/api/v3/audit-events?cursor={stale}"),
                None
            )
            .await?
            .0
            == StatusCode::CONFLICT
    );
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=timeline.http"]
async fn administrators_use_existing_access_and_tenant_isolation_is_preserved() -> Result<()> {
    let mut f = Fixture::open().await?;
    f.catch_up().await?;
    let page = f.get("/api/v3/audit-events").await?;
    ensure!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["actor"] != case::context().admin_for(case::peer()))
    );
    f.get("/api/v3/devices/unknown-device/timeline").await?;
    let mut anonymous = Browser::default();
    ensure!(
        anonymous
            .call(&f.router, Method::GET, "/api/v3/audit-events", None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    let mut other = f.authority.browser("other")?;
    ensure!(
        other
            .call(&f.router, Method::GET, "/api/v3/audit-events", None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    let subject = browser_subject(&other, &f.router).await?;
    identity::set_grants(
        case_tenant(),
        &subject,
        vec![crate::authorization::Grant {
            operation: crate::authorization::Permission::AuthorizationRead,
            scope: crate::authorization::Scope::Tenant,
        }],
    )
    .await?;
    ensure!(
        other
            .call(
                &f.router,
                Method::GET,
                "/api/v3/devices/unknown-device/timeline",
                None
            )
            .await?
            .0
            == StatusCode::OK
    );
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=timeline.http"]
async fn projection_commit_is_atomic_concurrent_and_corruption_is_visible() -> Result<()> {
    let mut f = Fixture::open().await?;
    f.get("/api/v3/audit-events").await?;
    let before = pg(&format!(
        "SELECT position FROM mdm_timeline.checkpoints WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    // A failed batch must not advance the checkpoint or leave partial rows.
    pg(
        "CREATE FUNCTION mdm_timeline.fail_fixture() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'fixture';END$$; CREATE TRIGGER fail_fixture BEFORE INSERT ON mdm_timeline.facts FOR EACH ROW EXECUTE FUNCTION mdm_timeline.fail_fixture()",
    )?;
    ensure!(f.timeline.catch_up().await.is_err());
    ensure!(
        before
            == pg(&format!(
                "SELECT position FROM mdm_timeline.checkpoints WHERE tenant_id='{}'",
                case_tenant()
            ))?
    );
    pg(
        "DROP TRIGGER fail_fixture ON mdm_timeline.facts;DROP FUNCTION mdm_timeline.fail_fixture()",
    )?;
    let (a, b) = tokio::join!(f.timeline.catch_up(), f.timeline.catch_up());
    a?;
    b?;
    f.catch_up().await?;
    let count = pg(&format!(
        "SELECT count(*)=count(DISTINCT position) FROM mdm_timeline.facts WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    ensure!(count.trim() == "t");
    pg(&format!(
        "UPDATE mdm_timeline.facts SET digest=decode(repeat('00',32),'hex') WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    ensure!(
        f.admin
            .call(&f.router, Method::GET, "/api/v3/audit-events", None)
            .await?
            .0
            .is_server_error()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=timeline.http"]
async fn source_recording_time_orders_facts_and_unknown_execution_remains_unknown() -> Result<()> {
    use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
    let mut f = Fixture::open().await?;
    let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
    let operation = Uuid::new_v4();
    for (index, recorded, observed) in [(0, 200, 300), (1, 100, 400), (2, 200, 50)] {
        let audit = RequestAudit::new(case_tenant().into(), "command_reconcile");
        proof.bind_audit(&audit)?;
        audit.operation(operation, "command_reconcile");
        let fact = Fact::business(
            &audit,
            &format!("time-fixture:{operation}:{index}"),
            b"input",
            200,
            "success",
            None,
        )?
        .with_details(
            json!({"after":{"execution":"unknown"},"privateKey":"private-fixture-secret"}),
        )?;
        let event = fact.event(rss_contract::Timepoint::try_from(observed as i64)?)?;
        let prepared =
            rss_audit_core::prepare(event, rss_contract::Timepoint::try_from(recorded as i64)?)?;
        let budget = AuditBudget::new(Duration::from_secs(3));
        let control = budget.control();
        let attempt = f
            .authority
            .audit
            .write(
                TenantId::parse(case_tenant())?,
                &control,
                prepared,
                |prepared, tx| {
                    Box::pin(async move {
                        tx.append(prepared)
                            .await
                            .map_err(rss_mdm_audit_integration::Error::from)
                            .map(|_| ())
                    })
                },
            )
            .await;
        ensure!(attempt.fold(
            |_| true,
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| false
        ));
        audit.finalize(None);
    }
    f.catch_up().await?;
    let page = f
        .get(&format!(
            "/api/v3/audit-events?operationId={operation}&limit=2"
        ))
        .await?;
    let items = page["items"].as_array().unwrap();
    ensure!(
        items.len() == 2
            && items.iter().all(|v| v["recordedAt"] == 200
                && v["phase"] == "unknown"
                && v["executionState"] == "unknown"
                && v["effect"] == "unknown")
    );
    ensure!(items[0]["position"].as_u64() > items[1]["position"].as_u64());
    let next = f
        .get(&format!(
            "/api/v3/audit-events?operationId={operation}&cursor={}",
            page["nextCursor"].as_str().unwrap()
        ))
        .await?;
    ensure!(next["items"][0]["recordedAt"] == 100 && next["nextCursor"].is_null());
    let filtered = f
        .get(&format!(
            "/api/v3/audit-events?operationId={operation}&from=150&until=201"
        ))
        .await?;
    ensure!(filtered["items"].as_array().unwrap().len() == 2);
    ensure!(!serde_json::to_string(&filtered)?.contains("private-fixture-secret"));
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=timeline.http"]
async fn managed_projection_restarts_without_duplicate_facts_and_drains_on_shutdown() -> Result<()>
{
    let mut f = Fixture::open().await?;
    f.get("/api/v3/audit-events").await?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(15))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    launch.stage_deferred_task_with_token(f.timeline.clone().registration().critical());
    launch.finish();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let page = f.get("/api/v3/audit-events?action=audit_search").await?;
            if !page["items"].as_array().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    crate::test_support::stop_worker(Some(stack)).await?;
    f.catch_up().await?;
    let count = pg(&format!(
        "SELECT count(*) FROM mdm_timeline.facts WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    f.timeline.initialize().await?;
    ensure!(f.timeline.catch_up().await? == 0);
    ensure!(
        count
            == pg(&format!(
                "SELECT count(*) FROM mdm_timeline.facts WHERE tenant_id='{}'",
                case_tenant()
            ))?
    );
    Ok(())
}
