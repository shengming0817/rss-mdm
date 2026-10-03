#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios preserve distinct recovery assertions"
)]
use crate::test_support::*;
#[tokio::test]
#[ignore = "MODULE=agent.registration: capability binding, re-registration and commit recovery"]
async fn registration_binding_and_replay() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let owned_router = app_with_access(&fixture.base, fixture.access.clone())
        .await?
        .0;
    let router = &owned_router;
    let mut session = fixture.browser("other")?;
    let browser = &mut session;
    set_device_grants(
        browser,
        router,
        crate::test_support::case::name("device-1"),
        &["inventory_read", "enrollment"],
    )
    .await?;
    let agent = crate::test_support::agent::register(router, browser).await?;
    let credential = agent.credential;
    let registration = agent.registration;
    let registration_request = agent.request;
    ensure!(
        browser
            .call(router, Method::POST, "/api/v1/enrollments", Some(json!({})))
            .await?
            .0
            == StatusCode::NOT_FOUND
    );
    for path in [
        "/api/agent/v3/registrations",
        "/api/agent/v3/reports",
        "/api/agent/v3/tasks/claim",
        "/api/agent/v4/registrations",
        "/api/agent/v4/reports",
        "/api/agent/v4/tasks/claim",
        "/api/agent/v5/registrations",
        "/api/agent/v5/reports",
        "/api/agent/v5/tasks/claim",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header("host", "mdm.example.test")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {credential}"))
                    .body(Body::from(r#"{"wireVersion":3}"#))?,
            )
            .await?;
        ensure!(
            response.status() == StatusCode::NOT_FOUND,
            "retired Agent route survived: {path}"
        );
    }
    let mut unsupported_wire = registration_request.clone();
    unsupported_wire["wireVersion"] = json!(5);
    let response = agent_call(
        router,
        Method::POST,
        "/api/agent/v6/registrations",
        None,
        Some(unsupported_wire),
    )
    .await?;
    ensure!(response == (StatusCode::BAD_REQUEST, json!({"code":"unsupported_wire"})));
    let mut unsupported_capability = registration_request.clone();
    unsupported_capability["capabilities"] = json!(["future"]);
    let response = agent_call(
        router,
        Method::POST,
        "/api/agent/v6/registrations",
        None,
        Some(unsupported_capability),
    )
    .await?;
    ensure!(
        response
            == (
                StatusCode::BAD_REQUEST,
                json!({"code":"unsupported_capability"})
            )
    );
    ensure!(
        agent_call(
            router,
            Method::POST,
            "/api/agent/v6/registrations",
            None,
            Some(registration_request)
        )
        .await?
        .0 == StatusCode::OK,
        "registration replay was not recovered"
    );
    let report_id = uuid::Uuid::new_v4();
    let prior = json!({"wireVersion":6,"collection":registration["collections"][0],"reportId":report_id,"sequence":0,"observedAt":1,"body":{"kind":"failed","code":"collectionFailed"}});
    ensure!(
        agent_call(
            router,
            Method::POST,
            "/api/agent/v6/reports",
            Some(credential),
            Some(prior)
        )
        .await?
        .0 == StatusCode::ACCEPTED
    );
    ensure!(!pg(&format!("SELECT locator FROM mdm_access.credentials WHERE tenant_id='{TENANT}' AND registration='{}'", registration["registrationId"].as_str().unwrap(), TENANT = case_tenant()))?.contains(credential), "raw Agent credential persisted");
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=agent.registration: tenant audit-head fault and credential recovery"]
async fn registration_recovery_preserves_credential_rotation() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let owned_router = crate::test_support::agent::router(&fixture).await?;
    let router = &owned_router;
    let audit_store = fixture.audit.as_ref();
    let mut session = fixture.browser("other")?;
    let browser = &mut session;
    set_device_grants(
        browser,
        router,
        case::name("device-1"),
        &["inventory_read", "enrollment"],
    )
    .await?;
    let agent = crate::test_support::agent::register(router, browser).await?;
    let credential = agent.credential;
    let registration = agent.registration;
    let report_id = uuid::Uuid::new_v4();
    ensure!(agent_call(router, Method::POST, "/api/agent/v6/reports", Some(credential),
        Some(json!({"wireVersion":6,"collection":registration["collections"][0],"reportId":report_id,"sequence":0,"observedAt":1,"body":{"kind":"failed","code":"collectionFailed"}}))).await?.0 == StatusCode::ACCEPTED);
    let next_password = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
    let next_credential = &crate::test_support::credential("replacement");
    browser.operation = Some(uuid::Uuid::new_v4());
    let (status, next_enrollment) = browser
        .call(
            router,
            Method::POST,
            "/api/v3/enrollments",
            Some(json!({"deviceId":crate::test_support::case::name("device-1"),"password":next_password,"source":"agent.builtin"})),
        )
        .await?;
    ensure!(status == StatusCode::OK);
    let next_operation = uuid::Uuid::new_v4();
    let next_registration = json!({"wireVersion":6,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"operationId":next_operation,"enrollmentId":next_enrollment["enrollmentId"],"password":next_password,"credential":next_credential,"platform":"macos","architecture":"aarch64","capabilities":["inventory.collect.v6"]});
    audit_store.inject_next_fault(rss_audit_postgres::PgFault::BeforeCommitPending);
    let rolled_back = agent_call(
        router,
        Method::POST,
        "/api/agent/v6/registrations",
        None,
        Some(next_registration.clone()),
    )
    .await?;
    ensure!(
        rolled_back.0 == StatusCode::SERVICE_UNAVAILABLE
            && rolled_back.1["code"] == "operation_unknown"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_agent.operations WHERE tenant_id='{TENANT}' AND operation_id='{next_operation}'", TENANT = case_tenant()))?.trim() == "0", "rolled-back registration persisted");
    audit_store.inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    let unknown = agent_call(
        router,
        Method::POST,
        "/api/agent/v6/registrations",
        None,
        Some(next_registration.clone()),
    )
    .await?;
    ensure!(
        unknown.0 == StatusCode::SERVICE_UNAVAILABLE && unknown.1["code"] == "operation_unknown"
    );
    let recovered = agent_call(
        router,
        Method::POST,
        "/api/agent/v6/registrations",
        None,
        Some(next_registration),
    )
    .await?;
    ensure!(recovered.0 == StatusCode::OK);
    let stored_receipt: Value = serde_json::from_str(&pg(&format!(
        "SELECT result FROM mdm_agent.operations WHERE tenant_id='{TENANT}' AND operation_id='{next_operation}'",
        TENANT = case_tenant()
    ))?)?;
    ensure!(
        recovered.1 == stored_receipt,
        "registration ACK-loss retry did not recover the committed receipt"
    );
    ensure!(agent_call(router, Method::POST, "/api/agent/v6/reports", Some(credential), Some(json!({"wireVersion":6,"collection":registration["collections"][0],"reportId":uuid::Uuid::new_v4(),"sequence":2,"observedAt":2,"body":{"kind":"failed","code":"collectionFailed"}}))).await?.0 == StatusCode::UNAUTHORIZED);
    ensure!(
        agent_call(
            router,
            Method::GET,
            &format!("/api/agent/v6/reports/{report_id}"),
            Some(credential),
            None
        )
        .await?
        .0 == StatusCode::UNAUTHORIZED
    );
    Ok(())
}
