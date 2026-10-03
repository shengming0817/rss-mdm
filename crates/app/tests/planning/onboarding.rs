//! Real HTTP/PG source evidence and durable Policy authority; no OS success is inferred.
use crate::test_support::agent_execution::*;
use crate::test_support::*;
async fn fixture() -> Result<Fixture> {
    let mut base: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    base["enrollment_entries"] =
        json!({"windows":"https://enroll.example.test","macos":"https://enroll.example.test/"});
    let mut f = Fixture::from_config(base).await?;
    f.grants
        .extend(identity::device_grants(None, &["enrollment"])?);
    identity::set_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
    f.register_profile(json!(["inventory.collect.v6", "mdm.enrollment.v6"]))
        .await?;
    let setup = start_automation(&f.base).await?;
    let group = Uuid::new_v4();
    planning_http::call(&mut f.author,&f.router,&format!("/api/v2/groups/{group}"),0,json!({"action":"create","name":"MDM missing","description":"","criteria":{"kind":"predicate","field":"channel.mdm.enrollment","op":"eq","value":{"kind":"string","value":"unenrolled"}}})).await?;
    stop_worker(setup).await?;
    f.scope(case_task_scope(), json!([{"kind":"group","id":group}]))
        .await?;
    Ok(f)
}
async fn publish(f: &mut Fixture) -> Result<Uuid> {
    let id = Uuid::new_v4();
    post(&mut f.author,&f.router,&format!("/api/v3/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":case_task_scope(),"action":{"kind":"request_mdm_enrollment","organization":case_tenant(),"runLifetimeSeconds":300}}}})).await?;
    Ok(id)
}
async fn report(f: &Fixture, sequence: u64, state: &str) -> Result<()> {
    let id = Uuid::new_v4();
    let collection = f
        .builtin_collections
        .iter()
        .find(|definition| {
            definition["fields"].as_array().is_some_and(|fields| {
                fields
                    .iter()
                    .any(|field| field["key"] == "channel.mdm.enrollment")
            })
        })
        .ok_or_else(|| anyhow::anyhow!("server did not publish enrollment collection"))?;
    let input = json!({"wireVersion":6,"collection":collection,"reportId":id,"sequence":sequence,"observedAt":1,"body":{"kind":"snapshot","values":[{"field":"channel.mdm.enrollment","value":{"kind":"value","value":{"kind":"string","value":state}}}]}});
    let response = agent_call(
        &f.router,
        Method::POST,
        "/api/agent/v6/reports",
        Some(case_credential()),
        Some(input.clone()),
    )
    .await?;
    ensure!(response.0 == StatusCode::ACCEPTED, "{response:?}");
    ensure!(
        response
            == agent_call(
                &f.router,
                Method::POST,
                "/api/agent/v6/reports",
                Some(case_credential()),
                Some(input)
            )
            .await?
    );
    wait_agent_status(&f.router, case_credential(), id, "snapshot", "applied").await?;
    planning_http::await_ingress().await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.onboarding"]
async fn explicit_source_absence_drives_one_standard_entry_without_creating_mdm_identity()
-> Result<()> {
    let mut f = fixture().await?;
    let id = publish(&mut f).await?;
    let overlapping = publish(&mut f).await?;
    let automation = start_automation(&f.base).await?;
    let workers = worker(&f.base).await?;
    for (sequence, state) in ["unknown", "other_organization", "this_organization"]
        .into_iter()
        .enumerate()
    {
        report(&f, sequence as u64, state).await?;
        let response = claim_request(&f.router, Uuid::new_v4()).await?;
        ensure!(
            response.0 == StatusCode::OK && response.1["task"].is_null(),
            "{response:?}"
        );
        ensure!(run_count(id)?.trim() == "0");
    }
    // An old observation time is legitimate current source evidence; no arbitrary freshness TTL.
    report(&f, 3, "unenrolled").await?;
    let state =
        channel_onboarding::diagnosis(&mut f.author, &f.router, id, case_device_id()).await?;
    ensure!(state["taskAdmission"]["state"] == "eligible", "{state}");
    let task = claim(&f.router).await?;
    ensure!(task["payload"]["entry"]["kind"] == "macos");
    ensure!(task["payload"].get("resourceDigest").is_none());
    task_event(&f.router, &task, json!({"kind":"received"})).await?;
    task_event(&f.router, &task, json!({"kind":"start"})).await?;
    task_event(
        &f.router,
        &task,
        json!({"kind":"enrollment_result","outcome":"opened"}),
    )
    .await?;
    for _ in 0..3 {
        ensure!(claim_request(&f.router, Uuid::new_v4()).await?.1["task"].is_null());
    }
    ensure!(
        run_count(id)?.trim().parse::<u64>()? + run_count(overlapping)?.trim().parse::<u64>()? == 1
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_access.registrations WHERE tenant_id='{}' AND channel='mdm'",
            case_tenant()
        ))?
        .trim()
            == "0"
    );
    stop_worker(workers).await?;
    stop_worker(automation).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.onboarding"]
async fn scope_wide_grant_is_rechecked_before_opening_enrollment() -> Result<()> {
    let mut f = fixture().await?;
    publish(&mut f).await?;
    let automation = start_automation(&f.base).await?;
    let workers = worker(&f.base).await?;
    report(&f, 0, "unenrolled").await?;
    let task = claim(&f.router).await?;
    let grants = f
        .grants
        .iter()
        .filter(|g| g.operation != crate::authorization::Permission::Enrollment)
        .cloned()
        .collect();
    identity::set_grants(case_tenant(), &f.author_id, grants).await?;
    let response = task_event_request(
        &f.router,
        &task,
        Uuid::new_v4(),
        &mut json!({"kind":"start"}),
    )
    .await?;
    ensure!(response.0 == StatusCode::FORBIDDEN, "{response:?}");
    stop_worker(workers).await?;
    stop_worker(automation).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.onboarding"]
async fn uncertain_entry_survives_application_restart_and_policy_disable() -> Result<()> {
    let mut f = fixture().await?;
    let id = publish(&mut f).await?;
    let automation = start_automation(&f.base).await?;
    let workers = worker(&f.base).await?;
    report(&f, 0, "unenrolled").await?;
    let task = claim(&f.router).await?;
    task_event(&f.router, &task, json!({"kind":"received"})).await?;
    task_event(&f.router, &task, json!({"kind":"start"})).await?;
    task_event(
        &f.router,
        &task,
        json!({"kind":"enrollment_result","outcome":"unknown"}),
    )
    .await?;
    stop_worker(workers).await?;
    let access = database(&f.base).await?;
    let (router, execution, _) = crate::api::application_fixture(
        serde_json::from_value(f.base.clone())?,
        Arc::new(crate::clock::SystemClock),
        monotonic(),
        access.clone(),
        None,
        access
            .audit_store(&crate::config::AuditConfig::Plain)
            .await?,
    )
    .await?;
    let execution = execution.service;
    let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
        "127.0.0.1".parse()?,
    )));
    execution.recover_action_fixture(id).await?;
    ensure!(claim_request(&router, Uuid::new_v4()).await?.1["task"].is_null());
    ensure!(run_count(id)?.trim() == "1");
    post(
        &mut f.author,
        &router,
        &format!("/api/v3/policies/{id}"),
        json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"disable"}}),
    )
    .await?;
    execution.recover_action_fixture(id).await?;
    let state = pg(&format!(
        "SELECT state FROM mdm_commands.action_runs WHERE id='{}'",
        task["payload"]["taskId"].as_str().unwrap()
    ))?;
    let state: Value = serde_json::from_str(state.trim())?;
    ensure!(
        state["execution"] == "unknown" && state["cancellation"] == "requested",
        "{state}"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_access.registrations WHERE tenant_id='{}' AND channel='mdm'",
            case_tenant()
        ))?
        .trim()
            == "0"
    );
    stop_worker(automation).await?;
    Ok(())
}
