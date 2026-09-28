#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios preserve distinct recovery assertions"
)]
use crate::test_support::*;
#[tokio::test]
#[ignore = "MODULE=agent.reports: durable intake, projection, capacity, retention and ACK recovery"]
async fn durable_reports_and_projection() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let owned_router = crate::test_support::agent::router(&fixture).await?;
    let router = &owned_router;
    let audit_store = fixture.audit.as_ref();
    let mut session = fixture.browser("other")?;
    let browser = &mut session;
    set_device_grants(
        browser,
        router,
        "device-1",
        &["inventory_read", "enrollment"],
    )
    .await?;
    let agent = crate::test_support::agent::register(router, browser).await?;
    let credential = agent.credential;
    let registration = agent.registration;
    let password = agent.password;
    let config = &fixture.base;
    let (status, error) = agent_call(
        router,
        Method::GET,
        "/api/agent/v3/reports/not-a-uuid",
        Some(credential),
        None,
    )
    .await?;
    ensure!(
        status == StatusCode::BAD_REQUEST && error["code"] == "malformed_request",
        "invalid report path escaped the wire error contract: {status} {error}"
    );
    let (status, error) = agent_call(
        router,
        Method::POST,
        "/api/agent/v3/reports",
        Some(credential),
        Some(json!({"oversized":"x".repeat(17_000)})),
    )
    .await?;
    ensure!(
        status == StatusCode::BAD_REQUEST && error["code"] == "malformed_request",
        "oversized body escaped the wire error contract: {status} {error}"
    );
    let (status, error) = agent_call(
        router,
        Method::POST,
        "/api/agent/v3/reports",
        Some(credential),
        Some(json!({"oversized":"x".repeat(2 * 1024 * 1024 + 1)})),
    )
    .await?;
    ensure!(
        status == StatusCode::BAD_REQUEST && error["code"] == "malformed_request",
        ">2 MiB body escaped the Agent wire boundary: {status} {error}"
    );
    let missing = uuid::Uuid::new_v4();
    ensure!(
        agent_call(
            router,
            Method::GET,
            &format!("/api/agent/v3/reports/{missing}"),
            Some(credential),
            None
        )
        .await?
            == (StatusCode::NOT_FOUND, json!({"code":"report_not_found"}))
    );
    ensure!(
        agent_call(
            router,
            Method::GET,
            &format!("/api/agent/v3/reports/{missing}"),
            Some(password),
            None
        )
        .await?
            == (StatusCode::UNAUTHORIZED, json!({"code":"invalid_identity"}))
    );
    let report_id = uuid::Uuid::new_v4();
    let report = json!({
        "wireVersion":3,
        "reportId":report_id,
        "sequence":0,
        "observedAt":1,
        "body":{"kind":"snapshot","values":[
            {"field":"device.model","value":{"kind":"known","value":"Agent Model"}},
            {"field":"device.os.version","value":{"kind":"known","value":"1.0"}}
        ]}
    });
    let (status, ack) = agent_call(
        router,
        Method::POST,
        "/api/agent/v3/reports",
        Some(credential),
        Some(report.clone()),
    )
    .await?;
    ensure!(
        status == StatusCode::ACCEPTED && ack["intake"] == "durable",
        "Agent report failed: {status} {ack}"
    );
    ensure!(
        agent_call(
            router,
            Method::POST,
            "/api/agent/v3/reports",
            Some(credential),
            Some(report.clone())
        )
        .await?
        .1 == ack,
        "report replay changed acknowledgement"
    );
    let concurrent_id = uuid::Uuid::new_v4();
    let concurrent = json!({"wireVersion":3,"reportId":concurrent_id,"sequence":0,"observedAt":1,"body":{"kind":"failed","code":"temporarilyUnavailable"}});
    let mut same_id = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let router = router.clone();
        let body = concurrent.clone();
        same_id.spawn(async move {
            agent_call(
                &router,
                Method::POST,
                "/api/agent/v3/reports",
                Some(credential),
                Some(body),
            )
            .await
        });
    }
    let mut concurrent_ack = None;
    while let Some(result) = same_id.join_next().await {
        let result = result??;
        ensure!(result.0 == StatusCode::ACCEPTED);
        if let Some(expected) = &concurrent_ack {
            ensure!(
                &result.1 == expected,
                "concurrent replay changed acknowledgement"
            );
        } else {
            concurrent_ack = Some(result.1);
        }
    }
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND id='{concurrent_id}'"))?.trim() == "1", "concurrent replay duplicated durable intake");
    pg(&format!(
        "UPDATE mdm_access.collection_runs SET delivery_pending=false WHERE tenant_id='{TENANT}' AND id='{concurrent_id}'"
    ))?;
    let mut changed = report;
    changed["sequence"] = json!(1);
    ensure!(
        agent_call(
            router,
            Method::POST,
            "/api/agent/v3/reports",
            Some(credential),
            Some(changed)
        )
        .await?
        .0 == StatusCode::CONFLICT,
        "changed report identity was accepted"
    );
    let (status, current) = agent_call(
        router,
        Method::GET,
        &format!("/api/agent/v3/reports/{report_id}"),
        Some(credential),
        None,
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && current["observation"] == "pending"
            && current["projection"] == "pending",
        "unexpected pre-worker status: {status} {current}"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND source='agent.builtin' AND id='{report_id}' AND delivery_pending"))?.trim() == "1");
    let runtime = agent_runtime(config).await?;
    let owner = crate::inventory_runtime::test_support::start(runtime.clone()).await?;
    wait_agent_status(router, credential, report_id, "snapshot", "applied").await?;
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND source='agent.builtin' AND id='{report_id}' AND NOT delivery_pending"))?.trim() == "1");
    ensure!(pg(&format!("SELECT string_agg(field||'='||coalesce(value,''),',' ORDER BY field) FROM mdm.inventory WHERE tenant_id='{TENANT}' AND batch_id='{report_id}'"))?.trim() == "device.model=Agent Model,device.os.version=1.0");
    ensure!(owner.shutdown().join().await?.is_clean());
    runtime.close_fixture().await?;

    pg(&format!(
        "INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,session_id,request_message,first_command,request,started_at,attempts,result,reason,batch,digest,sealed_at,delivery_pending) SELECT tenant_id,gen_random_uuid(),registration,source,epoch,scope,g,NULL,NULL,NULL,NULL,started_at-g,attempts,result,reason,batch,digest,sealed_at-g,false FROM mdm_access.collection_runs CROSS JOIN generate_series(1,230) g WHERE tenant_id='{TENANT}' AND id='{report_id}'"
    ))?;
    let partial_id = uuid::Uuid::new_v4();
    let failed_id = uuid::Uuid::new_v4();
    for body in [
        json!({"wireVersion":3,"reportId":partial_id,"sequence":1,"observedAt":2,"body":{"kind":"partial","values":[{"field":"device.model","value":{"kind":"known","value":"Unconfirmed"}}]}}),
        json!({"wireVersion":3,"reportId":failed_id,"sequence":2,"observedAt":3,"body":{"kind":"failed","code":"collectionFailed"}}),
    ] {
        ensure!(
            agent_call(
                router,
                Method::POST,
                "/api/agent/v3/reports",
                Some(credential),
                Some(body)
            )
            .await?
            .0 == StatusCode::ACCEPTED
        );
    }
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND registration='{}' AND source='agent.builtin' AND NOT delivery_pending", registration["registrationId"].as_str().unwrap()))?.trim().parse::<i64>()? <= 224, "delivered Agent retention was not enforced");
    pg(&format!(
        "INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,session_id,request_message,first_command,request,started_at,attempts,result,reason,batch,digest,sealed_at,delivery_pending) SELECT tenant_id,gen_random_uuid(),registration,source,epoch,scope,1000+g,NULL,NULL,NULL,NULL,started_at,attempts,result,reason,batch,digest,sealed_at,true FROM mdm_access.collection_runs CROSS JOIN generate_series(1,29) g WHERE tenant_id='{TENANT}' AND id='{partial_id}'"
    ))?;
    let mut capacity = tokio::task::JoinSet::new();
    for sequence in [3, 4] {
        let router = router.clone();
        let body = json!({"wireVersion":3,"reportId":uuid::Uuid::new_v4(),"sequence":sequence,"observedAt":4,"body":{"kind":"failed","code":"temporarilyUnavailable"}});
        capacity.spawn(async move {
            agent_call(
                &router,
                Method::POST,
                "/api/agent/v3/reports",
                Some(credential),
                Some(body),
            )
            .await
        });
    }
    let mut capacity_statuses = Vec::new();
    while let Some(result) = capacity.join_next().await {
        capacity_statuses.push(result??);
    }
    ensure!(
        capacity_statuses
            .iter()
            .filter(|result| result.0 == StatusCode::ACCEPTED)
            .count()
            == 1
    );
    ensure!(
        capacity_statuses
            .iter()
            .filter(|result| result.0 == StatusCode::SERVICE_UNAVAILABLE
                && result.1["code"] == "service_unavailable")
            .count()
            == 1,
        "concurrent capacity boundary was not linearized: {capacity_statuses:?}"
    );
    pg(&format!(
        "DELETE FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND registration='{}' AND source='agent.builtin' AND sequence>=1000",
        registration["registrationId"].as_str().unwrap()
    ))?;
    let runtime = agent_runtime(config).await?;
    let owner = crate::inventory_runtime::test_support::start(runtime.clone()).await?;
    wait_agent_status(
        router,
        credential,
        partial_id,
        "needSnapshotPartial",
        "notApplicable",
    )
    .await?;
    wait_agent_status(
        router,
        credential,
        failed_id,
        "needSnapshotCollectionFailed",
        "notApplicable",
    )
    .await?;
    ensure!(pg(&format!("SELECT count(*) FROM mdm.inventory WHERE tenant_id='{TENANT}' AND batch_id IN ('{partial_id}','{failed_id}')"))?.trim() == "0");
    ensure!(owner.shutdown().join().await?.is_clean());
    runtime.close_fixture().await?;
    for (number, fault, committed) in [
        (1, rss_audit_postgres::PgFault::BeforeCommitPending, false),
        (2, rss_audit_postgres::PgFault::CommitUnknownAfterAck, true),
    ] {
        let expected = "operation_unknown";
        let fault_report = uuid::Uuid::new_v4();
        let body = json!({"wireVersion":3,"reportId":fault_report,"sequence":100+number,"observedAt":100+number,"body":{"kind":"failed","code":"temporarilyUnavailable"}});
        audit_store.inject_next_fault(fault);
        let failed = agent_call(
            router,
            Method::POST,
            "/api/agent/v3/reports",
            Some(credential),
            Some(body.clone()),
        )
        .await?;
        ensure!(failed.0 == StatusCode::SERVICE_UNAVAILABLE && failed.1["code"] == expected);
        let persisted = pg(&format!(
            "SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND id='{fault_report}'"
        ))?;
        ensure!(persisted.trim() == if committed { "1" } else { "0" });
        let retry = agent_call(
            router,
            Method::POST,
            "/api/agent/v3/reports",
            Some(credential),
            Some(body.clone()),
        )
        .await?;
        ensure!(retry.0 == StatusCode::ACCEPTED && retry.1["reportId"] == fault_report.to_string());
        ensure!(
            agent_call(
                router,
                Method::POST,
                "/api/agent/v3/reports",
                Some(credential),
                Some(body)
            )
            .await?
                == retry
        );
        ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{TENANT}' AND id='{fault_report}'"))?.trim() == "1", "report recovery duplicated durable intake");
    }
    Ok(())
}
