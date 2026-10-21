//! Device loss diagnostics persist independently of sample delivery and policy leases.
use super::*;

const UPLOAD: &str = "/api/v1/agent/runtime/telemetry/gaps";
const QUERY: &str = "/api/v1/telemetry/gaps/query";

pub(super) struct Evidence {
    body: Value,
    receipt: Value,
    query: Value,
}

pub(super) async fn receive(
    f: &mut Fixture,
    configuration: &wire::TelemetryConfiguration,
    secondary: &str,
) -> Result<Evidence> {
    let now = f.planning.clock.unix_seconds()? * 1_000_000;
    let body = json!({"reportId":Uuid::new_v4(),"registrationId":configuration.registration_id,
        "generation":configuration.generation,"createdAt":now,
        "gaps":[{"reason":"capacity","count":3,"first":now-2_000_000,"last":now-1_000_000}]});
    let batches = pg(&format!(
        "SELECT count(*) FROM mdm_telemetry.batches WHERE tenant_id='{}'",
        case_tenant()
    ))?;
    let (status, receipt) = agent_call(
        &f.router,
        Method::POST,
        UPLOAD,
        Some(case_credential()),
        Some(body.clone()),
    )
    .await?;
    ensure!(
        status == StatusCode::ACCEPTED
            && receipt["reportId"] == body["reportId"]
            && receipt["replayed"] == false,
        "initial gap report: {status} {receipt}"
    );
    ensure!(receipt["receivedAt"].as_i64().is_some_and(|at| at >= now));
    let evidence = Evidence {
        query: json!({"device":case_device_id(),"receivedFrom":now-1_000_000,
            "receivedUntil":now+86_400_000_000,"limit":1,"after":null}),
        body,
        receipt,
    };
    replay(&f.router, &evidence).await?;
    let mut changed = evidence.body.clone();
    changed["gaps"][0]["count"] = json!(4);
    ensure!(
        agent_call(
            &f.router,
            Method::POST,
            UPLOAD,
            Some(case_credential()),
            Some(changed)
        )
        .await?
        .0 == StatusCode::CONFLICT
    );
    for credential in [None, Some(secondary)] {
        let (status, _) = agent_call(
            &f.router,
            Method::POST,
            UPLOAD,
            credential,
            Some(evidence.body.clone()),
        )
        .await?;
        ensure!(
            matches!(
                status,
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::CONFLICT
            ),
            "foreign gap upload: {status}"
        );
        let (status, _) = agent_call(
            &f.router,
            Method::GET,
            &receipt_path(&evidence),
            credential,
            None,
        )
        .await?;
        ensure!(
            matches!(
                status,
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
            ),
            "foreign gap receipt: {status}"
        );
    }
    for (key, value) in [
        ("registrationId", json!(Uuid::new_v4())),
        ("generation", json!(configuration.generation + 1)),
    ] {
        let mut forged = evidence.body.clone();
        forged["reportId"] = json!(Uuid::new_v4());
        forged[key] = value;
        let (status, _) = agent_call(
            &f.router,
            Method::POST,
            UPLOAD,
            Some(case_credential()),
            Some(forged),
        )
        .await?;
        ensure!(
            matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
            "registration fence: {status}"
        );
    }
    for (key, value) in [
        ("tenantId", json!(case::peer())),
        ("source", json!("agent.native")),
    ] {
        let mut forged = evidence.body.clone();
        forged["reportId"] = json!(Uuid::new_v4());
        forged[key] = value;
        ensure!(
            agent_call(
                &f.router,
                Method::POST,
                UPLOAD,
                Some(case_credential()),
                Some(forged)
            )
            .await?
            .0 == StatusCode::BAD_REQUEST
        );
    }
    for created in [now - 8 * 86400 * 1_000_000, now + 600 * 1_000_000] {
        let mut invalid = evidence.body.clone();
        invalid["reportId"] = json!(Uuid::new_v4());
        invalid["createdAt"] = json!(created);
        invalid["gaps"][0]["first"] = json!(created - 2_000_000);
        invalid["gaps"][0]["last"] = json!(created - 1_000_000);
        ensure!(
            agent_call(
                &f.router,
                Method::POST,
                UPLOAD,
                Some(case_credential()),
                Some(invalid)
            )
            .await?
            .0 == StatusCode::BAD_REQUEST
        );
    }
    for (key, value) in [
        ("count", json!(0)),
        ("reason", json!("unrecognized")),
        ("first", json!(now)),
    ] {
        let mut invalid = evidence.body.clone();
        invalid["reportId"] = json!(Uuid::new_v4());
        invalid["gaps"][0][key] = value;
        ensure!(
            agent_call(
                &f.router,
                Method::POST,
                UPLOAD,
                Some(case_credential()),
                Some(invalid)
            )
            .await?
            .0 == StatusCode::BAD_REQUEST
        );
    }
    let mut oversized = evidence.body.clone();
    oversized["reportId"] = json!(Uuid::new_v4());
    oversized["gaps"] = Value::Array(vec![evidence.body["gaps"][0].clone(); 128]);
    ensure!(serde_json::to_vec(&oversized)?.len() > 4096);
    let (status, _) = agent_call(
        &f.router,
        Method::POST,
        UPLOAD,
        Some(case_credential()),
        Some(oversized),
    )
    .await?;
    ensure!(
        matches!(
            status,
            StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE
        ),
        "oversized gap report: {status}"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_telemetry.batches WHERE tenant_id='{}'",
            case_tenant()
        ))? == batches,
        "gap diagnostics created sample batches"
    );
    let report = post(&mut f.author, &f.router, QUERY, evidence.query.clone()).await?;
    assert_report(&report, &evidence)?;
    Ok(evidence)
}

fn receipt_path(evidence: &Evidence) -> String {
    format!("{UPLOAD}/{}", evidence.body["reportId"].as_str().unwrap())
}

async fn replay(router: &Router, evidence: &Evidence) -> Result<()> {
    let (status, receipt) = agent_call(
        router,
        Method::GET,
        &receipt_path(evidence),
        Some(case_credential()),
        None,
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && receipt["reportId"] == evidence.body["reportId"]
            && receipt["receivedAt"] == evidence.receipt["receivedAt"],
        "persisted gap receipt: {status} {receipt}"
    );
    let (status, receipt) = agent_call(
        router,
        Method::POST,
        UPLOAD,
        Some(case_credential()),
        Some(evidence.body.clone()),
    )
    .await?;
    ensure!(
        status == StatusCode::ACCEPTED
            && receipt["replayed"] == true
            && receipt["receivedAt"] == evidence.receipt["receivedAt"],
        "gap replay: {status} {receipt}"
    );
    Ok(())
}

fn assert_report(result: &Value, evidence: &Evidence) -> Result<()> {
    let reports = result["reports"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing gap reports: {result}"))?;
    ensure!(
        reports.len() == 1
            && reports[0]["report"] == evidence.body
            && reports[0]["receivedAt"] == evidence.receipt["receivedAt"],
        "gap diagnostic changed: {result}"
    );
    Ok(())
}

pub(super) async fn reopened(f: &mut Fixture, router: &Router, evidence: &Evidence) -> Result<()> {
    replay(router, evidence).await?;
    let result = post(&mut f.author, router, QUERY, evidence.query.clone()).await?;
    assert_report(&result, evidence)?;
    // A second durable report proves the continuation returns a real distinct row.
    let mut second = evidence.body.clone();
    second["reportId"] = json!(Uuid::new_v4());
    let (status, receipt) = agent_call(
        router,
        Method::POST,
        UPLOAD,
        Some(case_credential()),
        Some(second.clone()),
    )
    .await?;
    ensure!(status == StatusCode::ACCEPTED && receipt["replayed"] == false);
    let first = post(&mut f.author, router, QUERY, evidence.query.clone()).await?;
    ensure!(
        first["reports"].as_array().is_some_and(|v| v.len() == 1) && first["next"].is_object(),
        "gap page missing cursor: {first}"
    );
    let mut next = evidence.query.clone();
    next["after"] = first["next"].clone();
    identity::set_grants(case_tenant(), &f.author_id, vec![]).await?;
    ensure!(
        f.author
            .call(router, Method::POST, QUERY, Some(next.clone()))
            .await?
            .0
            == StatusCode::FORBIDDEN,
        "gap cursor bypassed current permission"
    );
    identity::set_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
    let last = post(&mut f.author, router, QUERY, next).await?;
    ensure!(
        last["reports"].as_array().is_some_and(|v| v.len() == 1) && last["next"].is_null(),
        "unexpected last gap page: {last}"
    );
    let ids = [
        first["reports"][0]["report"]["reportId"].clone(),
        last["reports"][0]["report"]["reportId"].clone(),
    ];
    ensure!(
        ids[0] != ids[1]
            && ids.contains(&evidence.body["reportId"])
            && ids.contains(&second["reportId"]),
        "gap pagination lost or repeated a report"
    );
    for limit in [0, 257] {
        let mut invalid = evidence.query.clone();
        invalid["limit"] = json!(limit);
        ensure!(
            f.author
                .call(router, Method::POST, QUERY, Some(invalid))
                .await?
                .0
                == StatusCode::BAD_REQUEST
        );
    }
    Ok(())
}

pub(super) async fn withdrawn(
    f: &mut Fixture,
    router: &Router,
    evidence: &Evidence,
    policy: &Value,
) -> Result<()> {
    identity::set_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
    post(
        &mut f.author,
        router,
        &format!("/api/v1/policies/{}", policy.as_str().unwrap()),
        json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"disable"}}),
    )
    .await?;
    let mut body = evidence.body.clone();
    body["reportId"] = json!(Uuid::new_v4());
    body["gaps"][0]["reason"] = json!("configuration");
    let (status, result) = agent_call(
        router,
        Method::POST,
        UPLOAD,
        Some(case_credential()),
        Some(body),
    )
    .await?;
    ensure!(
        status == StatusCode::ACCEPTED && result["replayed"] == false,
        "withdrawal blocked device diagnostics: {status} {result}"
    );
    Ok(())
}

pub(super) async fn revoked(router: &Router, evidence: &Evidence) -> Result<()> {
    for (method, path, body) in [
        (Method::GET, receipt_path(evidence), None),
        (Method::POST, UPLOAD.into(), Some(evidence.body.clone())),
    ] {
        let (status, _) = agent_call(router, method, &path, Some(case_credential()), body).await?;
        ensure!(
            matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
            "revoked registration accessed gap diagnostics: {status}"
        );
    }
    Ok(())
}
