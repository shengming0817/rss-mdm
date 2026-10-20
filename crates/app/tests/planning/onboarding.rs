//! Real HTTP/PG source evidence and durable Policy authority; no OS success is inferred.
use crate::test_support::agent_execution::*;
use crate::test_support::*;
use anyhow::Context;
async fn fixture() -> Result<Fixture> {
    let mut base: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    base["enrollment_entries"] =
        json!({"windows":"https://enroll.example.test","macos":"https://enroll.example.test/"});
    let (resources, mut f) = Resources::build(move |resources| {
        Box::pin(async move {
    let mut f = Fixture::from_config(base).await?;
    resources.extend(std::mem::take(&mut f.resources));
    f.grants
        .extend(identity::device_grants(None, &["enrollment"])?);
    identity::set_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
    f.register_profile(json!(["inventory.collect.v1", "mdm.enrollment.v1"]))
        .await?;
    let setup = start_automation(&f.base).await?;
    let group = Uuid::new_v4();
    planning_http::call(&mut f.author,&f.router,&format!("/api/v1/groups/{group}"),0,json!({"action":"create","assetContext":"endpoint","presentation":{"name":"MDM missing","description":""},"criteria":{"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"channel.mdm.enrollment","op":"eq","value":{"kind":"string","value":"unenrolled"}}}})).await?;
    stop_worker(setup).await?;
    f.scope(case_task_scope(), json!([{"kind":"group","id":group}]))
        .await?;
    Ok(f)
    })
    }).await?;
    f.resources = resources;
    Ok(f)
}
async fn publish(f: &mut Fixture) -> Result<Uuid> {
    let id = Uuid::new_v4();
    post(&mut f.author,&f.router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":case_task_scope(),"action":{"kind":"request_mdm_enrollment","organization":case_tenant(),"runLifetimeSeconds":300}}}})).await?;
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
    let input = json!({"wireVersion":1,"collection":collection,"reportId":id,"sequence":sequence,"observedAt":1,"body":{"kind":"snapshot","values":[{"field":"channel.mdm.enrollment","value":{"kind":"value","value":{"kind":"string","value":state}}}]}});
    let response = agent_call(
        &f.router,
        Method::POST,
        "/api/v1/agent/runtime/reports",
        Some(case_credential()),
        Some(input.clone()),
    )
    .await?;
    ensure!(response.0 == StatusCode::ACCEPTED, "{response:?}");
    wait_agent_status(&f.router, case_credential(), id, "snapshot", "applied").await?;
    planning_http::await_ingress().await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.onboarding"]
async fn explicit_source_absence_drives_one_standard_entry_without_creating_mdm_identity()
-> Result<()> {
    let mut f = fixture().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
    let id = publish(&mut f).await?;
    let overlapping = publish(&mut f).await?;
    let automation = start_automation(&f.base).await?;
    let workers = worker(&f.base).await?;
    report(&f, 0, "unknown").await?;
    let response = claim_request(&f.router, Uuid::new_v4()).await?;
    ensure!(response.0 == StatusCode::OK && response.1["task"].is_null(), "{response:?}");
    ensure!(run_count(id)?.trim() == "0" && run_count(overlapping)?.trim() == "0");
    // An old observation time is legitimate current source evidence; no arbitrary freshness TTL.
    report(&f, 1, "unenrolled").await?;
    let state =
        channel_onboarding::diagnosis(&mut f.author, &f.router, id, case_device_id()).await?;
    ensure!(state["taskAdmission"]["state"] == "eligible", "{state}");
    let task = claim(&f.router).await?;
    ensure!(task["payload"]["task"]["entry"]["kind"] == "macos");
    ensure!(task["payload"].get("resourceDigest").is_none());
    let handoff_path=format!("/api/v1/agent/runtime/tasks/{}/enrollment",task["payload"]["task"]["taskId"].as_str().unwrap());
    let handoff=json!({"operationId":Uuid::new_v4(),"attemptId":task["payload"]["task"]["attemptId"],"password":credential("native-handoff")});
    let denied=agent_call(&f.router,Method::POST,&handoff_path,Some(case_credential()),Some(handoff.clone())).await?;
    ensure!(denied.0==StatusCode::FORBIDDEN,"handoff requires Start: {denied:?}");
    task_event(&f.router, &task, json!({"kind":"received"})).await?;
    task_event(&f.router, &task, json!({"kind":"start"})).await?;
    let accepted=agent_call(&f.router,Method::POST,&handoff_path,Some(case_credential()),Some(handoff.clone())).await?;
    ensure!(accepted.0==StatusCode::OK,"native handoff: {accepted:?}");
    ensure!(accepted.1["entry"]["kind"]=="macos" && accepted.1["username"].is_null());
    let again=agent_call(&f.router,Method::POST,&handoff_path,Some(case_credential()),Some(handoff.clone())).await?;
    ensure!(again==accepted,"same-operation retry must preserve request and expiry");
    let mut changed=handoff.clone();changed["password"]=json!(credential("changed-handoff"));
    let conflict=agent_call(&f.router,Method::POST,&handoff_path,Some(case_credential()),Some(changed)).await?;
    ensure!(conflict.0==StatusCode::CONFLICT,"changed handoff: {conflict:?}");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.agent_native_enrollments WHERE tenant_id='{}' AND task='{}'",case_tenant(),task["payload"]["task"]["taskId"].as_str().unwrap()))?.trim()=="1");

    task_event(
        &f.router,
        &task,
        json!({"kind":"enrollment_result","outcome":"opened"}),
    )
    .await?;
    let replay_after_open=agent_call(&f.router,Method::POST,&handoff_path,Some(case_credential()),Some(handoff.clone())).await?;
    ensure!(replay_after_open==accepted,"task UI result cannot lose an existing handoff receipt");
    let empty = claim_request(&f.router, Uuid::new_v4()).await?;
    ensure!(empty.0 == StatusCode::OK && empty.1["task"].is_null());
    ensure!(
        run_count(id)?.trim().parse::<u64>()? + run_count(overlapping)?.trim().parse::<u64>()? == 1
    );
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let rerun = Uuid::new_v4();
    let path = format!("/api/v1/policies/{id}/reruns");
    let request = json!({"operationId":rerun,"expectedRevision":1,"input":{"deadline":now+600}});
    let accepted = post(&mut f.author, &f.router, &path, request.clone()).await?;
    ensure!(post(&mut f.author, &f.router, &path, request).await? == accepted);
    let explicit = claim(&f.router).await?;
    ensure!(explicit["payload"]["task"]["taskId"] != task["payload"]["task"]["taskId"]);
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{}' AND occurrence='explicit:{rerun}'", case_tenant()))?.trim() == "1");
    task_event(&f.router, &explicit, json!({"kind":"received"})).await?;
    task_event(&f.router, &explicit, json!({"kind":"start"})).await?;
    task_event(
        &f.router,
        &explicit,
        json!({"kind":"enrollment_result","outcome":"opened"}),
    )
    .await?;
    let empty = claim_request(&f.router, Uuid::new_v4()).await?;
    ensure!(empty.0 == StatusCode::OK && empty.1["task"].is_null());
    ensure!(
        pg(&format!(
            "SELECT revision FROM mdm_policy.policies WHERE tenant_id='{}' AND id='{id}'",
            case_tenant()
        ))?
        .trim()
            == "1"
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
    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.onboarding"]
async fn scope_wide_grant_is_rechecked_before_opening_enrollment() -> Result<()> {
    let mut f = fixture().await?;
    let resources = std::mem::take(&mut f.resources);
    resources
        .finish(async {
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
            ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_attempts WHERE run='{}' AND permit IS NOT NULL", task["payload"]["task"]["taskId"].as_str().unwrap()))?.trim() == "0");
            let state: Value = serde_json::from_str(&pg(&format!("SELECT state FROM mdm_commands.action_runs WHERE id='{}'", task["payload"]["task"]["taskId"].as_str().unwrap()))?)?;
            ensure!(state["execution"] != "running" && state["execution"] != "unknown");
            stop_worker(workers).await?;
            stop_worker(automation).await?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.onboarding"]
async fn uncertain_entry_survives_application_restart_and_policy_disable() -> Result<()> {
    let mut f = fixture().await?;
    let resources = std::mem::take(&mut f.resources);
    resources
        .finish(async {
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
            let (router, execution, _, _, resources) = crate::api::application_fixture(
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
            resources
                .finish(async {
                    let execution = execution.service;
                    let router = router.layer(axum::Extension(
                        rss_identity_http_axum::ClientAddress("127.0.0.1".parse()?),
                    ));
                    execution.recover_action_fixture(id).await?;
                    let empty = claim_request(&router, Uuid::new_v4()).await?;
                    ensure!(empty.0 == StatusCode::OK && empty.1["task"].is_null());
                    ensure!(run_count(id)?.trim() == "1");
                    post(
        &mut f.author,
        &router,
        &format!("/api/v1/policies/{id}"),
        json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"disable"}}),
    )
    .await?;
                    execution.recover_action_fixture(id).await?;
                    let state = pg(&format!(
                        "SELECT state FROM mdm_commands.action_runs WHERE id='{}'",
                        task["payload"]["task"]["taskId"].as_str().unwrap()
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
                })
                .await
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.onboarding"]
async fn employee_enrollment_is_opt_in_idempotent_and_rechecks_publication() -> Result<()> {
    use rss_mdm_registration_service::enrollment::native::{AgentPolicyAuthority, Coordinates};
    use sqlx::Connection;
    let mut f = fixture().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let automation = start_automation(&f.base).await?;
        let workers = worker(&f.base).await?;
        report(&f, 0, "unenrolled").await?;
        let directory = "/api/v1/agent/runtime/self-service?source=human";
        let invoke = "/api/v1/agent/runtime/self-service/invocations";
        ensure!(claim_request(&f.router, Uuid::new_v4()).await?.1["task"].is_null());
        ensure!(agent_call(&f.router, Method::GET, directory, Some(case_credential()), None).await?.1["items"] == json!([]));
        let id = Uuid::new_v4();
        let mut definition = json!({"scope":case_task_scope(),"action":{
            "kind":"request_mdm_enrollment","organization":case_tenant(),"runLifetimeSeconds":300,
            "schedule":{"trigger":{"kind":"manual"},"misfire":{"kind":"coalesce_one"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null}},
            "selfService":{"access":{"kind":"device"},"published":false,"allowAi":false,
            "presentation":{"displayName":"Register MDM","description":"Join the organization","prerequisites":"OS confirmation",
            "sideEffects":"Device management","category":"Device","keywords":[]}}});
        let path = format!("/api/v1/policies/{id}");
        post(&mut f.author, &f.router, &path, json!({"operationId":Uuid::new_v4(),"expectedRevision":0,
            "input":{"action":"put","enabled":true,"definition":definition}})).await?;
        ensure!(agent_call(&f.router, Method::GET, directory, Some(case_credential()), None).await?.1["items"] == json!([]));
        definition["selfService"]["published"] = json!(true);
        let policy = post(&mut f.author, &f.router, &path, json!({"operationId":Uuid::new_v4(),"expectedRevision":1,
            "input":{"action":"put","enabled":true,"definition":definition}})).await?;
        let available = agent_call(&f.router, Method::GET, directory, Some(case_credential()), None).await?;
        ensure!(available.0 == StatusCode::OK && available.1["items"][0]["task"]["kind"] == "enrollment", "{available:?}");
        ensure!(run_count(id)?.trim() == "0", "directory cannot initiate enrollment");
        let input = json!({"operationId":Uuid::new_v4(),"policyId":id,"policyRevision":policy["revision"],
            "policyVersion":policy["versionId"],"source":"human","confirmed":true,"parameters":{}});
        let accepted = agent_call(&f.router, Method::POST, invoke, Some(case_credential()), Some(input.clone())).await?;
        ensure!(accepted.0 == StatusCode::ACCEPTED, "{accepted:?}");
        ensure!(agent_call(&f.router, Method::POST, invoke, Some(case_credential()), Some(input.clone())).await? == accepted);
        let mut duplicate = input.clone(); duplicate["operationId"] = json!(Uuid::new_v4());
        ensure!(agent_call(&f.router, Method::POST, invoke, Some(case_credential()), Some(duplicate)).await?.0 == StatusCode::CONFLICT);
        let task = claim(&f.router).await?;
        ensure!(task["payload"]["task"]["taskId"] == accepted.1["runId"]);
        ensure!(task["payload"]["task"]["authorization"]["requestId"] == input["operationId"]);
        task_event(&f.router, &task, json!({"kind":"received"})).await?;
        task_event(&f.router, &task, json!({"kind":"start"})).await?;
        let handoff = json!({"operationId":Uuid::new_v4(),"attemptId":task["payload"]["task"]["attemptId"],"password":credential("employee-mdm")});
        let handoff_path = format!("/api/v1/agent/runtime/tasks/{}/enrollment", task["payload"]["task"]["taskId"].as_str().unwrap());
        let native = agent_call(&f.router, Method::POST, &handoff_path, Some(case_credential()), Some(handoff)).await?;
        ensure!(native.0 == StatusCode::OK, "{native:?}");
        task_event(&f.router, &task, json!({"kind":"enrollment_result","outcome":"opened"})).await?;
        let status = agent_call(&f.router, Method::GET, &format!("{invoke}/{}", input["operationId"].as_str().unwrap()), Some(case_credential()), None).await?;
        ensure!(status.0 == StatusCode::OK && status.1["result"] == json!({"kind":"enrollment","outcome":"opened"}), "{status:?}");
        ensure!(pg(&format!("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id='{}' AND channel='mdm'",case_tenant()))?.trim() == "0");
        let coordinates = Coordinates { tenant: case_tenant().into(), id: Uuid::parse_str(native.1["enrollmentId"].as_str().unwrap())?,
            device: String::new(), actor: String::new(), instance: String::new(), version: 1, expected_generation: 0,
            operation: Uuid::new_v4(), source: rss_mdm_inventory::ReportSource::MdmApple };
        let mut connection = sqlx::PgConnection::connect_with(&crate::device::test_support::options("mdm_command_runtime")?.password("runtime-fixture")).await?;
        let mut tx = connection.begin().await?;
        crate::Database::configure_transaction(&mut tx, case_tenant()).await?;
        f.execution.current(&mut tx, &coordinates).await?;
        tx.rollback().await?;
        let access = crate::Database::connect(crate::device::test_support::options("mdm_access")?).await?;
        let admission = rss_mdm_registration_service::enrollment::native::agent_policy(
            &access.registration(), case_tenant(), coordinates.id, Some(&credential("employee-mdm")), f.execution.clone(),
        ).await?;
        // Hold the execution watermark first. Native authentication must wait there,
        // without holding the registration lock needed by an in-flight handoff.
        let mut blocker = sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        let mut observer = sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        let mut blocked = blocker.begin().await?;
        crate::Database::configure_transaction(&mut blocked, case_tenant()).await?;
        let tenant = rss_request_context::TenantId::parse(case_tenant())?;
        rss_mdm_inventory_postgres::lock_watermark_in(&mut blocked, tenant).await?;
        let mut native_connection = sqlx::PgConnection::connect_with(&crate::device::test_support::options("mdm_access")?).await?;
        let mut native_tx = native_connection.begin().await?;
        crate::Database::configure_transaction(&mut native_tx, case_tenant()).await?;
        let native_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *native_tx).await?;
        let release = async {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let waiting: bool = sqlx::query_scalar("SELECT coalesce(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1")
                        .bind(native_pid).fetch_one(&mut observer).await?;
                    if waiting { break; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,2670))")
                    .bind(case_tenant()).fetch_one(&mut *blocked).await?;
                ensure!(free, "native waiter must not hold registration admission before watermark");
                Ok::<_,anyhow::Error>(())
            }).await??;
            blocked.rollback().await?;
            Ok::<_,anyhow::Error>(())
        };
        let (authenticated, released) = tokio::join!(admission.current_request(&mut native_tx), release);
        released?; authenticated?;
        native_tx.rollback().await?;
        blocker.close().await?; observer.close().await?; access.close().await;

        definition["selfService"]["published"] = json!(false);
        post(&mut f.author, &f.router, &path, json!({"operationId":Uuid::new_v4(),"expectedRevision":policy["revision"],
            "input":{"action":"put","enabled":true,"definition":definition}})).await?;
        let mut tx = connection.begin().await?;
        crate::Database::configure_transaction(&mut tx, case_tenant()).await?;
        ensure!(matches!(f.execution.current(&mut tx, &coordinates).await, Err(rss_mdm_registration_service::Error::Forbidden)));
        tx.rollback().await?;
        connection.close().await?;
        stop_worker(workers).await?;
        stop_worker(automation).await?;
        Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.onboarding"]
async fn native_continuation_rejects_independent_source_read_revocation_after_opened() -> Result<()>
{
    use crate::authorization::{OperationAuthority, Permission};
    use sqlx::{Connection, Row};
    let mut f = fixture().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let management = f.grants.iter().filter(|g| g.operation != Permission::InventoryRead).cloned().collect();
        identity::independent_source_read(case_tenant(), &f.author_id, management).await?;
        let automation = start_automation(&f.base).await?;
        let workers = worker(&f.base).await?;
        report(&f, 0, "unenrolled").await?;
        let id = Uuid::new_v4();
        let policy = post(&mut f.author, &f.router, &format!("/api/v1/policies/{id}"), json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{
            "scope":case_task_scope(),"action":{"kind":"request_mdm_enrollment","organization":case_tenant(),"runLifetimeSeconds":300,"schedule":{"trigger":{"kind":"manual"},"misfire":{"kind":"coalesce_one"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null}},
            "selfService":{"access":{"kind":"device"},"published":true,"allowAi":false,"presentation":{"displayName":"Register MDM","description":"Join","prerequisites":"OS confirmation","sideEffects":"Device management","category":"Device","keywords":[]}}}}})).await?;
        let invoke = json!({"operationId":Uuid::new_v4(),"policyId":id,"policyRevision":policy["revision"],"policyVersion":policy["versionId"],"source":"human","confirmed":true,"parameters":{}});
        let accepted = agent_call(&f.router, Method::POST, "/api/v1/agent/runtime/self-service/invocations", Some(case_credential()), Some(invoke)).await?;
        ensure!(accepted.0 == StatusCode::ACCEPTED, "{accepted:?}");
        let task = claim(&f.router).await?;
        task_event(&f.router, &task, json!({"kind":"received"})).await?;
        task_event(&f.router, &task, json!({"kind":"start"})).await?;
        let native = agent_call(&f.router, Method::POST, &format!("/api/v1/agent/runtime/tasks/{}/enrollment", task["payload"]["task"]["taskId"].as_str().unwrap()), Some(case_credential()), Some(json!({"operationId":Uuid::new_v4(),"attemptId":task["payload"]["task"]["attemptId"],"password":credential("source-read-continuation")}))).await?;
        ensure!(native.0 == StatusCode::OK, "{native:?}");
        task_event(&f.router, &task, json!({"kind":"enrollment_result","outcome":"opened"})).await?;
        let request = Uuid::parse_str(native.1["enrollmentId"].as_str().unwrap())?;
        let access = crate::Database::connect(crate::device::test_support::options("mdm_access")?).await?;
        let admission = rss_mdm_registration_service::enrollment::native::agent_policy(&access.registration(), case_tenant(), request, Some(&credential("source-read-continuation")), f.execution.clone()).await?;
        let mut admin = Browser::default();
        ensure!(admin.login(&f.router, "admin").await? == StatusCode::OK);
        let mut c = sqlx::PgConnection::connect_with(&crate::device::test_support::options("mdm_access")?).await?;
        let mut tx = c.begin().await?;
        crate::Database::configure_transaction(&mut tx, case_tenant()).await?;
        let rule = sqlx::query("SELECT id,revision FROM mdm_access.authorization_rules WHERE tenant_id=$1::uuid AND document->'subject'->'user'->>'principalId'=$2 AND jsonb_array_length(document->'grants')=1 AND document->'grants'->0->>'operation'='inventory_read'")
            .bind(case_tenant()).bind(&f.author_id).fetch_one(&mut *tx).await?;
        let grant: Value = sqlx::query_scalar("SELECT authority FROM mdm_access.agent_native_enrollments WHERE tenant_id=$1::uuid AND request=$2").bind(case_tenant()).bind(request).fetch_one(&mut *tx).await?;
        let grant: OperationAuthority = serde_json::from_value(grant)?;
        tx.rollback().await?;
        let removed = admin.call(&f.router, Method::PUT, &format!("/api/v1/authorization/rules/{}",rule.try_get::<Uuid,_>("id")?), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":rule.try_get::<i64,_>("revision")?,"value":null}))).await?;
        ensure!(removed.0 == StatusCode::OK, "{removed:?}");
        let mut tx = c.begin().await?;
        crate::Database::configure_transaction(&mut tx, case_tenant()).await?;
        admission.lock_authority_in(&mut tx).await?;
        ensure!(grant.valid(&mut tx, Permission::Enrollment, crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?).await?, "Enrollment grant must remain independently valid");
        ensure!(matches!(admission.current_request(&mut tx).await, Err(rss_mdm_registration_service::Error::Forbidden)), "revoked source read must stop native continuation");
        tx.rollback().await?;
        ensure!(pg(&format!("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id='{}' AND channel='mdm'",case_tenant()))?.trim() == "0");
        c.close().await?;
        access.close().await;
        stop_worker(workers).await?;
        stop_worker(automation).await?;
        Ok(())
    }).await
}

/// Retirement must use ordinary publication and explicit Policy execution, survive
/// later policy changes, and keep an unconfirmed device effect visible.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.onboarding"]
async fn unmanage_policy_requires_authority_and_preserves_accepted_exit() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        f.register_profile(json!(["inventory.collect.v1", "task.execute.v1", "device.unmanage.v1"])).await?;
        f.scope(case_task_scope(), json!([{"kind":"device","id":case_device_id()}])).await?;
        let policy = Uuid::new_v4();
        let path = format!("/api/v1/policies/{policy}");
        let definition = json!({"scope":case_task_scope(),"action":{"kind":"unmanage_device","runLifetimeSeconds":300}});
        let input = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":definition}});
        // PolicyWrite alone must not grant retirement authority.
        let denied = f.author.call(&f.router,Method::POST,&path,Some(input.clone())).await?;
        ensure!(denied.0==StatusCode::FORBIDDEN,"{denied:?}");
        f.grants.extend(identity::device_grants(None,&["device_unmanage","inventory_assign"])?);
        identity::set_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
        post(&mut f.author,&f.router,&path,input).await?;
        let automation = start_automation(&f.base).await?;
        let workers = worker(&f.base).await?;
        let empty = claim_request(&f.router,Uuid::new_v4()).await?;
        ensure!(empty.0==StatusCode::OK && empty.1["task"].is_null(),"manual policy ran automatically: {empty:?}");
        ensure!(pg(&format!("SELECT count(*) FROM mdm_devices.retirements WHERE tenant_id='{}' AND policy='{policy}'",case_tenant()))?.trim()=="0");
        let (resource,_,_)=f.resource().await?;
        crate::test_support::agent_execution::publish(&mut f.author,&f.router,resource).await?;
        let ordinary=claim(&f.router).await?;
        task_event(&f.router,&ordinary,json!({"kind":"received"})).await?;
        let now=crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
        let rerun=json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"deadline":now+300}});
        post(&mut f.author,&f.router,&format!("{path}/reruns"),rerun.clone()).await?;
        post(&mut f.author,&f.router,&format!("{path}/reruns"),rerun).await?;
        let task=claim(&f.router).await?;
        ensure!(task["payload"]["kind"]=="unmanage","{task}");
        let retirement=task["payload"]["task"]["retirementId"].as_str().context("retirement ID")?;
        ensure!(pg(&format!("SELECT retirement FROM mdm_access.devices WHERE tenant_id='{}' AND id='{}'",case_tenant(),case_device_id()))?.trim()==retirement);
        let mut start=json!({"kind":"start"});
        let rejected=task_event_request(&f.router,&ordinary,Uuid::new_v4(),&mut start).await?;
        ensure!(rejected.0==StatusCode::FORBIDDEN || rejected.0==StatusCode::CONFLICT,"ordinary work started after accepted exit: {rejected:?}");
        post(&mut f.author,&f.router,&path,json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"put","enabled":false,"definition":definition}})).await?;
        task_event(&f.router,&task,json!({"kind":"received"})).await?;
        task_event(&f.router,&task,json!({"kind":"start"})).await?;
        task_event(&f.router,&task,json!({"kind":"unmanage_result","outcome":"unknown"})).await?;
        tokio::time::timeout(Duration::from_secs(30),async {
            loop {
                let (status,record)=f.author.call(&f.router,Method::GET,&format!("/api/v1/device-retirements/{retirement}"),None).await?;
                ensure!(status==StatusCode::OK,"{record}");
                let channel=&record["channels"][0];
                if channel["stage"]=="unenroll" && channel["effect"]=="unknown" && channel["reason"]=="agent_uninstall_unconfirmed" {
                    ensure!(channel["execution"]==task["payload"]["task"]["taskId"]);
                    break Ok::<_,anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        }).await??;
        ensure!(pg(&format!("SELECT state FROM mdm_access.registrations WHERE tenant_id='{}' AND id='{}'",case_tenant(),task["payload"]["task"]["registrationId"].as_str().context("registration ID")?))?.trim()=="active");
        ensure!(pg(&format!("SELECT count(*) FROM mdm_devices.retirements WHERE tenant_id='{}' AND policy='{policy}'",case_tenant()))?.trim()=="1");
        let forced=json!({"operationId":Uuid::new_v4(),"reason":"device effect unavailable"});
        let force_path=format!("/api/v1/device-retirements/{retirement}/force-revoke");
        let receipt=post(&mut f.author,&f.router,&force_path,forced.clone()).await?;
        ensure!(post(&mut f.author,&f.router,&force_path,forced).await?==receipt);
        let access=database(&f.base).await?;
        let owner=rss_mdm_device_service::Associations::new(access.audit_store(&crate::config::AuditConfig::Plain).await?,rss_request_context::TenantId::parse(case_tenant())?,&[7;32])?;
        ensure!(owner.finalize_retirements(&crate::registration_lifecycle::Bridge).await?==1);
        let (status,record)=f.author.call(&f.router,Method::GET,&format!("/api/v1/device-retirements/{retirement}"),None).await?;
        ensure!(status==StatusCode::OK && record["channels"][0]["stage"]=="complete" && record["channels"][0]["effect"]=="unknown","{record}");
        let asset_path=format!("/api/v1/device-views/endpoint/{}/asset-state",case_device_id());
        for state in ["archived","deleted","active"] {
            post(&mut f.author,&f.router,&asset_path,json!({"operationId":Uuid::new_v4(),"state":state})).await?;
        }
        let peer=claim_request(&f.router,Uuid::new_v4()).await?;
        ensure!(peer.0==StatusCode::UNAUTHORIZED || peer.0==StatusCode::FORBIDDEN,"restoring asset revived its credential: {peer:?}");
        stop_worker(workers).await?;
        stop_worker(automation).await?;
        Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.onboarding"]
async fn unmanage_start_without_receipt_expires_through_existing_recovery() -> Result<()> {
    retirement_delivery_deadline(true).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.onboarding"]
async fn unmanage_without_start_expires_as_blocked_without_redelivery() -> Result<()> {
    retirement_delivery_deadline(false).await
}
async fn retirement_delivery_deadline(started: bool) -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        f.register_profile(json!(["inventory.collect.v1","device.unmanage.v1"])).await?;
        f.grants.extend(identity::device_grants(None,&["device_unmanage"])?);
        identity::set_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
        f.scope(case_task_scope(),json!([{"kind":"device","id":case_device_id()}])).await?;
        let policy=Uuid::new_v4();
        let now=crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
        post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":case_task_scope(),"action":{"kind":"unmanage_device","runLifetimeSeconds":300}}}})).await?;
        let automation=start_automation(&f.base).await?;
        let workers=worker(&f.base).await?;
        post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}/reruns"),json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"deadline":now+300}})).await?;
        let task=claim(&f.router).await?;
        task_event(&f.router,&task,json!({"kind":"received"})).await?;
        if started { task_event(&f.router,&task,json!({"kind":"start"})).await?; }
        let execution=task["payload"]["task"]["taskId"].as_str().context("task ID")?;
        let retirement=task["payload"]["task"]["retirementId"].as_str().context("retirement ID")?;
        // Move the persisted execution budget across its deadline; no further device
        // sign-in, Policy change or explicit recovery call may be needed.
        pg(&format!("UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{{deadline}}',to_jsonb(floor(extract(epoch FROM clock_timestamp()))::bigint-1)) WHERE tenant_id='{}' AND id='{execution}'",case_tenant()))?;
        tokio::time::timeout(Duration::from_secs(30),async {
            loop {
                let state=pg(&format!("SELECT effect||':'||reason FROM mdm_devices.retirement_channels WHERE tenant_id='{}' AND operation='{retirement}'",case_tenant()))?;
                if state.trim()==if started {"unknown:agent_uninstall_unconfirmed"}else{"blocked:agent_uninstall_not_started"} {break Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await??;
        ensure!(pg(&format!("SELECT state->>'execution' FROM mdm_commands.action_runs WHERE tenant_id='{}' AND id='{execution}'",case_tenant()))?.trim()==if started {"unknown"} else {"not_started"});
        if !started {
            let (_, tasks)=claim_request(&f.router,Uuid::new_v4()).await?;
            ensure!(tasks["task"].is_null(),"expired uninstall was redelivered: {tasks}");
            ensure!(pg(&format!("SELECT execution::text FROM mdm_devices.retirement_channels WHERE tenant_id='{}' AND operation='{retirement}'",case_tenant()))?.trim()==execution);
        }
        stop_worker(workers).await?;stop_worker(automation).await?;
        Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.onboarding"]
async fn delayed_explicit_retirement_and_overlapping_policy_history_remain_durable() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        f.register_profile(json!(["inventory.collect.v1","device.unmanage.v1"])).await?;
        f.grants.extend(identity::device_grants(None,&["device_unmanage"])?);
        identity::set_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
        f.scope(case_task_scope(),json!([{"kind":"device","id":case_device_id()}])).await?;
        f.scope(case_empty_scope(),json!([])).await?;
        let a=Uuid::new_v4();let b=Uuid::new_v4();
        let action=json!({"kind":"unmanage_device","runLifetimeSeconds":300,"schedule":{"trigger":{"kind":"manual"},"notBefore":0,"until":null,"jitterSeconds":60,"window":null}});
        for policy in [a,b] {
            post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":case_task_scope(),"action":action}}})).await?;
        }
        let automation=start_automation(&f.base).await?;
        let workers=worker(&f.base).await?;
        // First drain publication jobs without any trigger. The following persisted
        // trigger has no accompanying job, as after an early delayed reconciliation.
        tokio::time::timeout(Duration::from_secs(30),async {
            loop {
                if pg(&format!("SELECT count(*) FROM mdm_automation.automation_jobs WHERE tenant_id='{}' AND kind='policy_reconcile' AND target IN('{a}','{b}') AND NOT completed",case_tenant()))?.trim()=="0" {break Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        }).await??;
        let now=crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
        let trigger=Uuid::new_v4();
        pg(&format!("INSERT INTO mdm_policy.triggers(tenant_id,id,version,created_at,deadline) SELECT tenant_id,'{trigger}',current_version,{},{} FROM mdm_policy.policies WHERE tenant_id='{}' AND id='{b}'",now-120,now+600,case_tenant()))?;
        f.planning.forward_lifecycle_schedules().await?;
        let task=claim(&f.router).await?;
        let retirement=task["payload"]["task"]["retirementId"].as_str().context("retirement ID")?;
        let trigger_a=Uuid::new_v4();
        post(&mut f.author,&f.router,&format!("/api/v1/policies/{a}/reruns"),json!({"operationId":trigger_a,"expectedRevision":1,"input":{"deadline":now+600}})).await?;
        pg(&format!("UPDATE mdm_policy.triggers SET created_at={} WHERE tenant_id='{}' AND id='{trigger_a}'",now-120,case_tenant()))?;
        f.planning.forward_lifecycle_schedules().await?;
        tokio::time::timeout(Duration::from_secs(30),async {
            loop {
                if pg(&format!("SELECT count(*) FROM mdm_devices.retirement_policies WHERE tenant_id='{}' AND operation='{retirement}'",case_tenant()))?.trim()=="2" {break Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        }).await??;
        ensure!(pg(&format!("SELECT count(*) FROM mdm_devices.retirement_policies p JOIN rss_audit.records r ON r.tenant_id=p.tenant_id AND r.source_id='mdm.business' AND r.event_id='e-'||encode(sha256(convert_to('retirement:'||p.operation::text||':policy:'||p.policy::text||':'||p.version::text||':accepted','UTF8')),'hex') WHERE p.tenant_id='{}' AND p.operation='{retirement}'",case_tenant()))?.trim()=="2","each new Policy reference needs its own audited fact");
        post(&mut f.author,&f.router,&format!("/api/v1/policies/{a}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"put","enabled":false,"definition":{"scope":case_empty_scope(),"action":action}}})).await?;
        let (status,page)=f.author.call(&f.router,Method::GET,&format!("/api/v1/policies/{a}/assignments"),None).await?;
        ensure!(status==StatusCode::OK,"{page}");
        ensure!(page["items"].as_array().context("assignments")?.iter().any(|item|item["operationIds"].as_array().is_some_and(|ids|ids.contains(&json!(retirement)))),"Scope exit lost the shared retirement reference: {page}");
        stop_worker(workers).await?;stop_worker(automation).await?;
        Ok(())
    }).await
}
