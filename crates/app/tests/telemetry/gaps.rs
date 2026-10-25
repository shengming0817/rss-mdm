//! Device loss diagnostics persist independently of sample delivery and policy leases.
use super::*;

const UPLOAD: &str = "/api/v1/agent/runtime/telemetry/gaps";
const QUERY: &str = "/api/v1/telemetry/gaps/query";

pub(super) struct Evidence {
    body: Value,
    receipt: Value,
    query: Value,
    peer: wire::BindingProfile,
    peer_credential: String,
}

pub(super) async fn receive(
    f: &mut Fixture,
    configuration: &wire::TelemetryConfiguration,
    secondary: &(String, String, wire::BindingProfile),
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
        peer: secondary.2.clone(),
        peer_credential: secondary.0.clone(),
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
    for credential in [None, Some(secondary.0.as_str())] {
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
    invalid_reports(&f.router, &evidence, now).await?;
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

async fn invalid_reports(router: &Router, evidence: &Evidence, now: i64) -> Result<()> {
    for (key, value) in [
        ("tenantId", json!(case::peer())),
        ("source", json!("agent.native")),
    ] {
        let mut forged = evidence.body.clone();
        forged["reportId"] = json!(Uuid::new_v4());
        forged[key] = value;
        ensure!(
            agent_call(
                router,
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
                router,
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
                router,
                Method::POST,
                UPLOAD,
                Some(case_credential()),
                Some(invalid)
            )
            .await?
            .0 == StatusCode::BAD_REQUEST
        );
    }
    oversized_report(router, evidence).await?;
    Ok(())
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
    identity::change_grants(case_tenant(), &f.author_id, vec![]).await?;
    ensure!(
        f.author
            .call(router, Method::POST, QUERY, Some(next.clone()))
            .await?
            .0
            == StatusCode::FORBIDDEN,
        "gap cursor bypassed current permission"
    );
    identity::change_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
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
    device_scoped_queries(f, router, evidence).await?;
    Ok(())
}

pub(super) async fn withdrawn(
    f: &mut Fixture,
    router: &Router,
    evidence: &Evidence,
    policy: &Value,
) -> Result<()> {
    identity::change_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
    let path = format!("/api/v1/policies/{}", policy.as_str().unwrap());
    let (status, current) = f.author.call(router, Method::GET, &path, None).await?;
    ensure!(status == StatusCode::OK);
    post(
        &mut f.author,
        router,
        &format!("/api/v1/policies/{}", policy.as_str().unwrap()),
        json!({"operationId":Uuid::new_v4(),"expectedRevision":current["revision"],"input":{"action":"disable"}}),
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
    bounded_store(f, router, evidence).await?;
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

// SQL prepares capacity states only; all admission, rollback, expiry reads and pruning
// below use the running product and its real PostgreSQL transactions.
async fn bounded_store(f: &Fixture, router: &Router, evidence: &Evidence) -> Result<()> {
    let tenant = case_tenant();
    let registration = evidence.body["registrationId"].as_str().unwrap();
    let generation = evidence.body["generation"].as_u64().unwrap();
    let mut expiring = evidence.body.clone();
    let expires = database_now()? + 20_000_000;
    let created = expires - 7 * 86400 * 1_000_000;
    expiring["reportId"] = json!(Uuid::new_v4());
    expiring["createdAt"] = json!(created);
    expiring["gaps"][0]["first"] = json!(created - 2_000_000);
    expiring["gaps"][0]["last"] = json!(created - 1_000_000);
    let (status, _) = agent_call(
        router,
        Method::POST,
        UPLOAD,
        Some(case_credential()),
        Some(expiring.clone()),
    )
    .await?;
    ensure!(
        status == StatusCode::ACCEPTED,
        "near-expiry legitimate gap report: {status}"
    );
    let expiring_id = expiring["reportId"].as_str().unwrap();
    let mut candidate = evidence.body.clone();
    candidate["reportId"] = json!(Uuid::new_v4());
    let candidate_id = candidate["reportId"].as_str().unwrap().to_owned();
    // A different registration must not count toward this registration's 4096 limit.
    let registration_seed = Uuid::new_v4();
    let registered: i64 = pg(&format!("SELECT count(*) FROM mdm_telemetry.gap_reports WHERE tenant_id='{tenant}' AND registration='{registration}'"))?.trim().parse()?;
    seed_reports(
        registration_seed,
        4096 - registered,
        registration,
        generation,
        false,
        &evidence.body,
    )?;
    denied_without_writes(router, &candidate).await?;
    let (status, _) = agent_call(
        router,
        Method::GET,
        &format!("{UPLOAD}/{expiring_id}"),
        Some(case_credential()),
        None,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "expiry fixture must first be readable"
    );
    let remaining = expires.saturating_sub(database_now()?).max(0) as u64;
    tokio::time::sleep(Duration::from_micros(remaining + 100_000)).await;
    ensure!(
        agent_call(
            router,
            Method::GET,
            &format!("{UPLOAD}/{expiring_id}"),
            Some(case_credential()),
            None
        )
        .await?
        .0 == StatusCode::NOT_FOUND,
        "expired receipt remained readable"
    );
    tokio::time::timeout(Duration::from_secs(45),async {
        loop {
            if pg(&format!("SELECT count(*) FROM mdm_telemetry.gap_reports WHERE tenant_id='{tenant}' AND id='{expiring_id}'"))?.trim()=="0" {break;}
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Ok::<_,anyhow::Error>(())
    }).await??;
    ensure!(pg(&format!("SELECT count(*) FROM mdm_telemetry.gap_reports WHERE tenant_id='{tenant}' AND registration='{registration}'"))?.trim()=="4095","prune removed valid capacity rows");
    replay(router, evidence).await?;
    let (status, _) = agent_call(
        router,
        Method::POST,
        UPLOAD,
        Some(case_credential()),
        Some(candidate.clone()),
    )
    .await?;
    ensure!(
        status == StatusCode::ACCEPTED,
        "prune failed to release registration capacity: {status}"
    );
    clear_seed(registration_seed, 4096 - registered)?;
    pg(&format!(
        "DELETE FROM mdm_telemetry.gap_reports WHERE tenant_id='{tenant}' AND id='{candidate_id}'"
    ))?;

    // Keep every synthetic registration below 4096 so only the tenant bound can reject.
    let tenant_seed = Uuid::new_v4();
    let count: i64 = pg(&format!(
        "SELECT count(*) FROM mdm_telemetry.gap_reports WHERE tenant_id='{tenant}'"
    ))?
    .trim()
    .parse()?;
    seed_reports(
        tenant_seed,
        100_000 - count,
        registration,
        generation,
        true,
        &evidence.body,
    )?;
    ensure!(pg(&format!("SELECT max(n) FROM (SELECT count(*) n FROM mdm_telemetry.gap_reports WHERE tenant_id='{tenant}' GROUP BY registration) x"))?.trim().parse::<i64>()?<4096);
    denied_without_writes(router, &candidate).await?;
    clear_seed(tenant_seed, 100_000 - count)?;

    // Avoid straddling a minute: no mocked clock or rate transaction is involved.
    let remainder = database_now()? % 60_000_000;
    if remainder > 45_000_000 {
        tokio::time::sleep(Duration::from_micros(
            (60_000_000 - remainder + 100_000) as u64,
        ))
        .await;
    }
    let saved = pg(&format!(
        "SELECT row_to_json(r)::text FROM mdm_telemetry.rate_windows r WHERE tenant_id='{tenant}'"
    ))?;
    let saved: Value = serde_json::from_str(saved.trim())?;
    let minute = database_now()? / 60_000_000;
    let limit = f.base["telemetry"]["ingress"]["batchesPerMinute"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing ingress limit"))?;
    pg(&format!(
        "UPDATE mdm_telemetry.rate_windows SET minute={minute},batches={limit},bytes=1 WHERE tenant_id='{tenant}'"
    ))?;
    denied_without_writes(router, &candidate).await?;
    ensure!(
        database_now()? / 60_000_000 == minute,
        "rate check crossed its minute window"
    );
    pg(&format!(
        "UPDATE mdm_telemetry.rate_windows SET minute={},batches={},bytes={} WHERE tenant_id='{tenant}'",
        saved["minute"].as_i64().unwrap(),
        saved["batches"].as_i64().unwrap(),
        saved["bytes"].as_i64().unwrap()
    ))?;
    let (status, _) = agent_call(
        router,
        Method::POST,
        UPLOAD,
        Some(case_credential()),
        Some(candidate),
    )
    .await?;
    ensure!(
        status == StatusCode::ACCEPTED,
        "rate rejection left a partial report or admission state: {status}"
    );
    pg(&format!(
        "DELETE FROM mdm_telemetry.gap_reports WHERE tenant_id='{tenant}' AND id='{candidate_id}'"
    ))?;
    Ok(())
}

fn database_now() -> Result<i64> {
    Ok(
        pg("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")?
            .trim()
            .parse()?,
    )
}

async fn denied_without_writes(router: &Router, body: &Value) -> Result<()> {
    let tenant = case_tenant();
    let state = || {
        pg(&format!(
            "SELECT (SELECT count(*) FROM mdm_telemetry.gap_reports WHERE tenant_id='{tenant}')::text||':'||(SELECT row_to_json(r)::text FROM mdm_telemetry.rate_windows r WHERE tenant_id='{tenant}')"
        ))
    };
    let before = state()?;
    let (status, result) = agent_call(
        router,
        Method::POST,
        UPLOAD,
        Some(case_credential()),
        Some(body.clone()),
    )
    .await?;
    ensure!(
        status == StatusCode::SERVICE_UNAVAILABLE,
        "capacity/rate admission: {status} {result}"
    );
    ensure!(
        state()? == before,
        "rejected gap changed rows or shared rate accounting"
    );
    let id = body["reportId"].as_str().unwrap();
    ensure!(pg(&format!("SELECT count(*) FROM mdm_telemetry.gap_reports WHERE tenant_id='{tenant}' AND id='{id}'"))?.trim()=="0","rejected report persisted");
    Ok(())
}

fn seed_reports(
    seed: Uuid,
    count: i64,
    registration: &str,
    generation: u64,
    spread: bool,
    template: &Value,
) -> Result<()> {
    ensure!(count > 0);
    let now = database_now()?;
    let registration_sql = if spread {
        format!("md5('{seed}:registration:'||(n/1000)::text)::uuid")
    } else {
        format!("'{registration}'::uuid")
    };
    // Preserve canonical wire member order when calculating each report's exact digest.
    let typed: wire::TelemetryGapReport = serde_json::from_value(template.clone())?;
    let gaps = serde_json::to_string(&typed.gaps)?;
    let device = case_device_id().replace('\'', "''");
    pg(&format!(
        "WITH identities AS (SELECT md5('{seed}:'||n::text)::uuid id,{registration_sql} registration FROM generate_series(1,{count}) n), documents AS (SELECT *,format('{{\"reportId\":\"%s\",\"registrationId\":\"%s\",\"generation\":{generation},\"createdAt\":{now},\"gaps\":{gaps}}}',id,registration) body FROM identities) INSERT INTO mdm_telemetry.gap_reports SELECT '{}'::uuid,id,'{device}',registration,{generation},sha256(convert_to(body,'UTF8')),body::jsonb,{now},{now}+604800000000 FROM documents",
        case_tenant()
    ))?;
    Ok(())
}

fn clear_seed(seed: Uuid, count: i64) -> Result<()> {
    pg(&format!(
        "DELETE FROM mdm_telemetry.gap_reports WHERE tenant_id='{}' AND id IN (SELECT md5('{seed}:'||n::text)::uuid FROM generate_series(1,{count}) n)",
        case_tenant()
    ))?;
    Ok(())
}

async fn oversized_report(router: &Router, evidence: &Evidence) -> Result<()> {
    let mut report: wire::TelemetryGapReport = serde_json::from_value(evidence.body.clone())?;
    report.report_id = Uuid::new_v4();
    report.validate()?;
    let mut bytes = serde_json::to_vec(&report)?;
    ensure!(bytes.len() <= wire::TELEMETRY_GAP_MAX_BYTES);
    bytes.resize(wire::TELEMETRY_GAP_MAX_BYTES + 1, b' ');
    // JSON whitespace is semantically inert: only the actual transport size differs.
    ensure!(serde_json::from_slice::<wire::TelemetryGapReport>(&bytes)? == report);
    let peer = agent::evidence(case_credential())
        .ok_or_else(|| anyhow::anyhow!("missing authenticated gap peer"))?;
    let request = Request::builder()
        .method(Method::POST)
        .uri(UPLOAD)
        .header("host", "mdm.example.test:9445")
        .header("content-type", "application/json")
        .extension(peer)
        .body(Body::from(bytes))?;
    let response = tokio::spawn(router.clone().oneshot(request)).await??;
    ensure!(
        matches!(
            response.status(),
            StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE
        ),
        "oversized valid gap accepted: {}",
        response.status()
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_telemetry.gap_reports WHERE tenant_id='{}' AND id='{}'",
            case_tenant(),
            report.report_id
        ))?
        .trim()
            == "0",
        "oversized report reached durable storage"
    );
    let (status, receipt) = agent_call(
        router,
        Method::POST,
        UPLOAD,
        Some(case_credential()),
        Some(serde_json::to_value(&report)?),
    )
    .await?;
    ensure!(
        status == StatusCode::ACCEPTED
            && receipt["reportId"] == report.report_id.to_string()
            && receipt["replayed"] == false,
        "compact control report rejected: {status} {receipt}"
    );
    pg(&format!(
        "DELETE FROM mdm_telemetry.gap_reports WHERE tenant_id='{}' AND id='{}'",
        case_tenant(),
        report.report_id
    ))?;
    Ok(())
}

async fn device_scoped_queries(
    f: &mut Fixture,
    router: &Router,
    evidence: &Evidence,
) -> Result<()> {
    let mut report: wire::TelemetryGapReport = serde_json::from_value(evidence.body.clone())?;
    report.registration_id = evidence.peer.registration_id;
    report.generation = evidence.peer.generation;
    let mut expected = Vec::new();
    for _ in 0..2 {
        report.report_id = Uuid::new_v4();
        let (status, receipt) = agent_call(
            router,
            Method::POST,
            UPLOAD,
            Some(&evidence.peer_credential),
            Some(serde_json::to_value(&report)?),
        )
        .await?;
        ensure!(
            status == StatusCode::ACCEPTED && receipt["replayed"] == false,
            "second-device gap report: {status} {receipt}"
        );
        expected.push(json!(report.report_id));
    }
    let mut query = evidence.query.clone();
    query["device"] = json!(evidence.peer.device_id);
    let first = post(&mut f.author, router, QUERY, query.clone()).await?;
    ensure!(
        first["reports"]
            .as_array()
            .is_some_and(|rows| rows.len() == 1)
            && first["next"].is_object(),
        "second-device first page: {first}"
    );
    let mut continuation = query.clone();
    continuation["after"] = first["next"].clone();
    let last = post(&mut f.author, router, QUERY, continuation.clone()).await?;
    ensure!(
        last["reports"]
            .as_array()
            .is_some_and(|rows| rows.len() == 1)
            && last["next"].is_null(),
        "second-device last page: {last}"
    );
    let first_id = &first["reports"][0]["report"]["reportId"];
    let last_id = &last["reports"][0]["report"]["reportId"];
    ensure!(
        first_id != last_id && expected.contains(first_id) && expected.contains(last_id),
        "second-device pagination did not return both real reports"
    );
    restricted_queries(f, router, evidence, query, continuation).await
}

async fn restricted_queries(
    f: &mut Fixture,
    router: &Router,
    evidence: &Evidence,
    query: Value,
    continuation: Value,
) -> Result<()> {
    identity::change_grants(
        case_tenant(),
        &f.author_id,
        identity::device_grants(Some(case_device_id()), &["inventory_read"])?,
    )
    .await?;
    for denied in [query, continuation] {
        ensure!(
            f.author
                .call(router, Method::POST, QUERY, Some(denied))
                .await?
                .0
                == StatusCode::FORBIDDEN,
            "device-scoped grant allowed another device's gap query"
        );
    }
    let permitted = post(&mut f.author, router, QUERY, evidence.query.clone()).await?;
    let rows = permitted["reports"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing permitted device reports"))?;
    ensure!(
        rows.len() == 1 && rows[0]["report"]["registrationId"] == evidence.body["registrationId"],
        "device-scoped grant did not retain own-device access: {permitted}"
    );
    identity::change_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
    Ok(())
}
