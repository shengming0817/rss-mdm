//! Real administrator HTTP, PostgreSQL audit facts and request-driven projection.
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
    key: Vec<u8>,
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
            key,
        })
    }
    async fn append(
        &self,
        proof: &crate::authorization::context::AuthorizedPrincipal,
        operation: Uuid,
        index: usize,
        recorded: i64,
        observed: i64,
    ) -> Result<()> {
        use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
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
        let attempt = self
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
        Ok(())
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
    let (status,issued)=f.admin.call(&f.router,Method::POST,"/api/v1/enrollments",Some(json!({"deviceId":device,"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","source":"mdm.windows","windowsProfile":"Device"}))).await?;
    ensure!(status == StatusCode::OK);
    let enrollment = issued["enrollmentId"].as_str().unwrap();
    ensure!(
        f.admin
            .call(
                &f.router,
                Method::GET,
                &format!("/api/v1/enrollments/{enrollment}"),
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
                &format!("/api/v1/enrollments/{enrollment}/resume"),
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
                &format!("/api/v1/enrollments/{enrollment}/cancel"),
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
                "/api/v1/devices/{device}/registrations/{}/revoke",
                registration.registration
            ),
            Some(json!({})),
        )
        .await?;
    ensure!(status == StatusCode::OK, "revoke: {status} {value}");
    let manual = Uuid::new_v4();
    let (status,value)=f.admin.call(&f.router,Method::PUT,&format!("/api/v1/devices/{device}/manual-fields/custom.office_floor"),Some(json!({"operationId":manual,"expectedRevision":0,"input":{"action":"set","value":{"kind":"integer","value":9}}}))).await?;
    ensure!(status == StatusCode::OK, "manual: {status} {value}");
    // Replay and denied manual writes retain a source-owned device coordinate.
    let (replay_status,_)=f.admin.call(&f.router,Method::PUT,&format!("/api/v1/devices/{device}/manual-fields/custom.office_floor"),Some(json!({"operationId":manual,"expectedRevision":0,"input":{"action":"set","value":{"kind":"integer","value":9}}}))).await?;
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
    let (denied_status,_)=other.call(&f.router,Method::PUT,&format!("/api/v1/devices/{device}/manual-fields/custom.office_floor"),Some(json!({"operationId":denied,"expectedRevision":1,"input":{"action":"set","value":{"kind":"integer","value":10}}}))).await?;
    ensure!(denied_status == StatusCode::FORBIDDEN);
    // Actual management API denial is a persisted fact, never a fabricated execution success.
    let management = Uuid::new_v4();
    let (status, _) = f
        .admin
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/devices/{device}/operations/{management}"),
            None,
        )
        .await?;
    ensure!(status == StatusCode::FORBIDDEN);
    let page = f.get(&format!("/api/v1/devices/{device}/timeline")).await?;
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
        .get(&format!("/api/v1/audit-events?operationId={manual}"))
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
        f.get("/api/v1/audit-events").await?;
    }
    let first = f.get("/api/v1/audit-events?limit=2").await?;
    let through = first["coverage"]["indexedThrough"].as_u64().unwrap();
    let all = f.get("/api/v1/audit-events?limit=200").await?;
    let expected: Vec<_> = all["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["position"].as_u64().unwrap() <= through)
        .cloned()
        .collect();
    let mut items = first["items"].as_array().unwrap().clone();
    let mut cursor = first["nextCursor"].as_str().map(str::to_owned);
    f.get("/api/v1/audit-events").await?;
    let stale = cursor.clone().unwrap();
    for _ in 0..50 {
        let Some(token) = cursor.take() else { break };
        let page = f
            .get(&format!("/api/v1/audit-events?limit=2&cursor={token}"))
            .await?;
        items.extend(page["items"].as_array().unwrap().clone());
        cursor = page["nextCursor"].as_str().map(str::to_owned);
    }
    ensure!(cursor.is_none());
    ensure!(items == expected, "fixed window changed");
    ensure!(
        items
            .windows(2)
            .all(|w| (w[0]["recordedAt"].as_i64(), w[0]["position"].as_u64())
                > (w[1]["recordedAt"].as_i64(), w[1]["position"].as_u64()))
    );
    for path in [
        format!("/api/v1/audit-events?action=inventory_read&cursor={stale}"),
        format!("/api/v1/devices/absent/timeline?cursor={stale}"),
        "/api/v1/audit-events?cursor=invalid".into(),
        "/api/v1/audit-events?limit=201".into(),
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
    ensure!(
        f.admin
            .call(
                &f.router,
                Method::GET,
                &format!("/api/v1/audit-events?cursor={stale}"),
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
    let page = f.get("/api/v1/audit-events").await?;
    ensure!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["actor"] != case::context().admin_for(case::peer()))
    );
    f.get("/api/v1/devices/unknown-device/timeline").await?;
    let before = pg(&format!(
        "SELECT position FROM mdm_timeline.checkpoints WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    let mut anonymous = Browser::default();
    ensure!(
        anonymous
            .call(&f.router, Method::GET, "/api/v1/audit-events", None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    let mut other = f.authority.browser("other")?;
    ensure!(
        other
            .call(&f.router, Method::GET, "/api/v1/audit-events", None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(
        f.admin
            .call(
                &f.router,
                Method::GET,
                "/api/v1/audit-events?limit=201",
                None
            )
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    ensure!(
        before
            == pg(&format!(
                "SELECT position FROM mdm_timeline.checkpoints WHERE tenant_id='{}'",
                case_tenant()
            ))?
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
                "/api/v1/devices/unknown-device/timeline",
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
    f.get("/api/v1/audit-events").await?;
    let before = pg(&format!(
        "SELECT position FROM mdm_timeline.checkpoints WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    // A failed batch must not advance the checkpoint or leave partial rows.
    pg(
        "CREATE FUNCTION mdm_timeline.fail_fixture() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'fixture';END$$; CREATE TRIGGER fail_fixture BEFORE INSERT ON mdm_timeline.facts FOR EACH ROW EXECUTE FUNCTION mdm_timeline.fail_fixture()",
    )?;
    ensure!(
        f.admin
            .call(&f.router, Method::GET, "/api/v1/audit-events", None)
            .await?
            .0
            == StatusCode::SERVICE_UNAVAILABLE
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_timeline.facts WHERE tenant_id='{}' AND position>{before}",
            case_tenant()
        ))?
        .trim()
            == "0"
    );
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
    f.get("/api/v1/audit-events").await?; // The same service recovers without a health reset.
    let mut other = f.admin.clone();
    let (a, b) = tokio::join!(
        f.admin
            .call(&f.router, Method::GET, "/api/v1/audit-events", None),
        other.call(&f.router, Method::GET, "/api/v1/audit-events", None)
    );
    ensure!(a?.0 == StatusCode::OK && b?.0 == StatusCode::OK);
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
            .call(&f.router, Method::GET, "/api/v1/audit-events", None)
            .await?
            .0
            .is_server_error()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=timeline.http"]
async fn source_recording_time_orders_facts_and_unknown_execution_remains_unknown() -> Result<()> {
    let mut f = Fixture::open().await?;
    let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
    let operation = Uuid::new_v4();
    for (index, recorded, observed) in [(0, 200, 300), (1, 100, 400), (2, 200, 50)] {
        f.append(&proof, operation, index, recorded, observed)
            .await?;
    }
    let page = f
        .get(&format!(
            "/api/v1/audit-events?operationId={operation}&limit=2"
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
            "/api/v1/audit-events?operationId={operation}&cursor={}",
            page["nextCursor"].as_str().unwrap()
        ))
        .await?;
    ensure!(next["items"][0]["recordedAt"] == 100 && next["nextCursor"].is_null());
    let filtered = f
        .get(&format!(
            "/api/v1/audit-events?operationId={operation}&from=150&until=201"
        ))
        .await?;
    ensure!(filtered["items"].as_array().unwrap().len() == 2);
    ensure!(!serde_json::to_string(&filtered)?.contains("private-fixture-secret"));
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=timeline.http"]
async fn on_demand_projection_is_bounded_idle_and_resumes_from_durable_checkpoint() -> Result<()> {
    let mut f = Fixture::open().await?;
    let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
    let operation = Uuid::new_v4();
    let before = pg(&format!(
        "SELECT position FROM mdm_timeline.checkpoints WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    for index in 0..130 {
        f.append(&proof, operation, index, 200, 200).await?;
    }
    // Persistent facts alone do not advance the query index.
    ensure!(
        before
            == pg(&format!(
                "SELECT position FROM mdm_timeline.checkpoints WHERE tenant_id='{}'",
                case_tenant()
            ))?
    );
    let first = f
        .get(&format!(
            "/api/v1/audit-events?operationId={operation}&limit=200"
        ))
        .await?;
    ensure!(first["coverage"]["complete"] == false);
    ensure!(
        !first["items"].as_array().unwrap().is_empty()
            && first["items"].as_array().unwrap().len() <= 64
    );
    let mut indexed = first["coverage"]["indexedThrough"].as_u64().unwrap();
    let mut complete = false;
    for _ in 0..8 {
        let page = f
            .get(&format!(
                "/api/v1/audit-events?operationId={operation}&limit=200"
            ))
            .await?;
        let next = page["coverage"]["indexedThrough"].as_u64().unwrap();
        ensure!(next >= indexed && next - indexed <= 64);
        indexed = next;
        if page["coverage"]["complete"] == true {
            ensure!(page["items"].as_array().unwrap().len() == 130);
            complete = true;
            break;
        }
    }
    ensure!(complete, "small bounded backlog did not converge");
    let restarted = f.authority.access.timeline(
        f.authority.audit.clone(),
        TenantId::parse(case_tenant())?,
        &f.key,
    )?;
    restarted.initialize().await?;
    let query = rss_mdm_timeline_service::Query {
        operation_id: Some(operation),
        limit: Some(200),
        ..Default::default()
    };
    let page = restarted.query(&proof, "audit", &query).await?;
    ensure!(page.items.len() == 130 && page.coverage.indexed_through.unwrap() >= indexed);
    ensure!(
        pg(&format!(
            "SELECT count(*)=count(DISTINCT position) FROM mdm_timeline.facts WHERE tenant_id='{}'",
            case_tenant()
        ))?
        .trim()
            == "t"
    );
    Ok(())
}

async fn lock_checkpoint() -> Result<sqlx::PgConnection> {
    use sqlx::Connection;
    let mut owner = sqlx::PgConnection::connect(&std::env::var("MDM_ADMIN_URL")?).await?;
    sqlx::raw_sql("BEGIN").execute(&mut owner).await?;
    sqlx::query(
        "SELECT position FROM mdm_timeline.checkpoints WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(case_tenant())
    .fetch_one(&mut owner)
    .await?;
    Ok(owner)
}
async fn wait_for_projection_lock(owner: &mut sqlx::PgConnection) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5),async{
        loop {
            // Each poll must observe fresh activity while the checkpoint lock transaction stays open.
            sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *owner).await?;
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%mdm_timeline.checkpoints%')").fetch_one(&mut *owner).await?;
            if waiting {return Ok::<_,anyhow::Error>(())}
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await??;
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=timeline.http"]
async fn query_budget_returns_partial_after_acknowledged_rollback_and_next_query_recovers()
-> Result<()> {
    let mut f = Fixture::open().await?;
    let mut owner = lock_checkpoint().await?;
    let browser = f.admin.clone();
    let router = f.router.clone();
    let query = tokio::spawn(async move {
        let mut browser = browser;
        browser
            .call(&router, Method::GET, "/api/v1/audit-events", None)
            .await
    });
    wait_for_projection_lock(&mut owner).await?;
    let (status, page) = query.await??;
    ensure!(
        status == StatusCode::OK
            && page["coverage"]["complete"] == false
            && page["coverage"]["indexedThrough"].is_null()
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_timeline.facts WHERE tenant_id='{}'",
            case_tenant()
        ))?
        .trim()
            == "0"
    );
    sqlx::raw_sql("ROLLBACK").execute(&mut owner).await?;
    let recovered = f.get("/api/v1/audit-events").await?;
    ensure!(!recovered["items"].as_array().unwrap().is_empty());
    Ok(())
}
#[tokio::test]
#[ignore = "make t2 MODULE=timeline.http"]
async fn prepared_batch_cannot_cross_a_rebuilt_generation_at_the_same_position() -> Result<()> {
    let mut f = Fixture::open().await?;
    let mut owner = lock_checkpoint().await?;
    let timeline = f.timeline.clone();
    let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
    let query =
        tokio::spawn(async move { timeline.query(&proof, "audit", &Default::default()).await });
    wait_for_projection_lock(&mut owner).await?;
    sqlx::query("UPDATE mdm_timeline.checkpoints SET generation=$2 WHERE tenant_id=$1::uuid")
        .bind(case_tenant())
        .bind(Uuid::new_v4())
        .execute(&mut owner)
        .await?;
    sqlx::raw_sql("COMMIT").execute(&mut owner).await?;
    let page = query.await??;
    ensure!(
        page.items.is_empty() && !page.coverage.complete && page.coverage.indexed_through.is_none()
    );
    ensure!(
        pg(&format!(
            "SELECT position FROM mdm_timeline.checkpoints WHERE tenant_id='{}'",
            case_tenant()
        ))?
        .trim()
            == "-1"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_timeline.facts WHERE tenant_id='{}'",
            case_tenant()
        ))?
        .trim()
            == "0"
    );
    ensure!(
        !f.get("/api/v1/audit-events").await?["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "make t2 MODULE=timeline.http"]
async fn corrupt_source_is_rejected_without_advancing_the_index() -> Result<()> {
    let mut f = Fixture::open().await?;
    let before = pg(&format!(
        "SELECT position FROM mdm_timeline.checkpoints WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    pg(&format!(
        "UPDATE rss_audit.records SET canonical=decode('00','hex') WHERE tenant_id='{}' AND position=(SELECT min(position) FROM rss_audit.records WHERE tenant_id='{}')",
        case_tenant(),
        case_tenant()
    ))?;
    let (status, error) = f
        .admin
        .call(&f.router, Method::GET, "/api/v1/audit-events", None)
        .await?;
    ensure!(
        status == StatusCode::INTERNAL_SERVER_ERROR && error["code"] == "audit_integrity_error"
    );
    ensure!(
        before
            == pg(&format!(
                "SELECT position FROM mdm_timeline.checkpoints WHERE tenant_id='{}'",
                case_tenant()
            ))?
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_timeline.facts WHERE tenant_id='{}'",
            case_tenant()
        ))?
        .trim()
            == "0"
    );
    Ok(())
}
