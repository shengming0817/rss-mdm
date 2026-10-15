use crate::test_support::agent_execution::*;
use crate::test_support::*;
async fn call(
    f: &Fixture,
    method: Method,
    path: &str,
    value: Option<Value>,
    device: bool,
    user: bool,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mdm.example.test:9445");
    if device {
        request =
            request.extension(crate::test_support::agent::evidence(case_credential()).unwrap());
    }
    if user {
        request = request.header(
            "x-rss-user-session",
            f.author.cookies.get("__Host-identity-session").unwrap(),
        );
    }
    let body = if let Some(value) = value {
        request = request.header("content-type", "application/json");
        Body::from(serde_json::to_vec(&value)?)
    } else {
        Body::empty()
    };
    let response = f.router.clone().oneshot(request.body(body)?).await?;
    let status = response.status();
    let value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    Ok((status, value))
}
fn definition(resource: Uuid, inputs: bool) -> Value {
    let mut value = policy_definition(resource, case_task_scope());
    value["action"]["schedule"] = json!({"trigger":{"kind":"manual"},"misfire":{"kind":"coalesce_one"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null});
    if inputs {
        value["action"]["parameters"] =
            json!({"name":{"kind":"input"},"path":{"kind":"fixed","value":"/Applications"}});
    }
    value["selfService"] = json!({"access":{"kind":"authenticated_user"},"published":true,"displayName":"Repair","description":"Repair the application","prerequisites":"Signed-in employee","sideEffects":"May restart the application","category":"Support","keywords":["repair"]});
    value
}
async fn publish_definition(f: &mut Fixture, value: Value) -> Result<(Uuid, Value)> {
    publish_definition_as(&mut f.author, &f.router, value).await
}
async fn publish_definition_as(
    author: &mut Browser,
    router: &Router,
    value: Value,
) -> Result<(Uuid, Value)> {
    let id = Uuid::new_v4();
    let policy=post(author,router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":value}})).await?;
    Ok((id, policy))
}
fn request(id: Uuid, policy: &Value, parameters: Value) -> Value {
    json!({"operationId":Uuid::new_v4(),"policyId":id,"policyRevision":policy["revision"],"policyVersion":policy["versionId"],"source":"ai","confirmed":true,"parameters":parameters})
}
const INVOKE: &str = "/api/v1/agent/runtime/self-service/invocations";
const DIRECTORY: &str = "/api/v1/agent/runtime/self-service?source=ai";
async fn claim_with_context(router: &Router, context: &Value) -> Result<(StatusCode, Value)> {
    agent_call(router, Method::POST, "/api/v1/agent/runtime/tasks/claim", Some(case_credential()), Some(json!({"wireVersion":1,"executionContext":context,"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh"],"operationId":Uuid::new_v4()}))).await
}
async fn event_with_context(
    router: &Router,
    task: &Value,
    context: &Value,
    event: Value,
) -> Result<(StatusCode, Value)> {
    agent_call(router, Method::POST, &format!("/api/v1/agent/runtime/tasks/{}/events", task["payload"]["task"]["taskId"].as_str().unwrap()), Some(case_credential()), Some(json!({"wireVersion":1,"executionContext":context,"operationId":Uuid::new_v4(),"attemptId":task["payload"]["task"]["attemptId"],"event":event}))).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.self_service"]
async fn targeted_invocation_binds_parameters_identity_frequency_and_result() -> Result<()> {
    let mut f = Fixture::new().await?;
    f.register().await?;
    ensure!(claim_request(&f.router, Uuid::new_v4()).await?.0 == StatusCode::OK);
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    let (resource, _, _) = f.script_resource(4096, true).await?;
    let (id, policy) = publish_definition(&mut f, definition(resource, true)).await?;
    let reads = audit_count(|record| record.action() == "command_read")?;
    let directory = call(&f, Method::GET, DIRECTORY, None, true, true).await?;
    ensure!(
        audit_count(|record| record.action() == "command_read")? == reads + 1,
        "directory must retain its task read audit action"
    );
    ensure!(
        directory.0 == StatusCode::OK && directory.1["items"].as_array().unwrap().len() == 1,
        "directory: {directory:?}"
    );
    ensure!(
        directory.1["items"][0]["selfService"]["allowAi"] == true
            && directory.1["items"][0]["selfService"]["riskLevel"] == 2
    );
    let reads = audit_count(|record| record.action() == "command_read")?;
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, false, true).await?.0 == StatusCode::UNAUTHORIZED
    );
    ensure!(
        audit_count(|record| record.action() == "command_read")? == reads + 1,
        "unauthenticated directory rejection must retain its task read audit action"
    );
    let accepts = audit_count(|record| record.action() == "command_accept")?;
    ensure!(
        call(
            &f,
            Method::POST,
            INVOKE,
            Some(json!({"unknown":true})),
            true,
            true
        )
        .await?
        .0 == StatusCode::BAD_REQUEST
    );
    ensure!(
        audit_count(|record| record.action() == "command_accept")? == accepts + 1,
        "JSON rejection before invocation service must retain its task accept audit action"
    );
    ensure!(call(&f, Method::GET, DIRECTORY, None, true, false).await?.1["items"] == json!([]));
    let input = request(id, &policy, json!({"name":"Acme"}));
    let mut invalid = input.clone();
    invalid["confirmed"] = json!(false);
    ensure!(
        call(&f, Method::POST, INVOKE, Some(invalid), true, true)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    for parameters in [
        json!({}),
        json!({"name":"Acme","path":"/Library"}),
        json!({"name":"x".repeat(33)}),
        json!({"name":true}),
    ] {
        let mut invalid = input.clone();
        invalid["parameters"] = parameters;
        ensure!(
            call(&f, Method::POST, INVOKE, Some(invalid), true, true)
                .await?
                .0
                == StatusCode::BAD_REQUEST
        );
    }
    ensure!(run_count(id)?.trim() == "0");
    let accepted = call(&f, Method::POST, INVOKE, Some(input.clone()), true, true).await?;
    ensure!(accepted.0 == StatusCode::ACCEPTED, "invoke: {accepted:?}");
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, true, true).await?.1["items"] == json!([]),
        "pending call remained in directory"
    );
    ensure!(
        call(&f, Method::POST, INVOKE, Some(input.clone()), true, true)
            .await?
            .1
            == accepted.1
    );
    let mut conflict = input.clone();
    conflict["parameters"]["name"] = json!("Other");
    ensure!(
        call(&f, Method::POST, INVOKE, Some(conflict), true, true)
            .await?
            .0
            == StatusCode::CONFLICT
    );
    ensure!(
        call(
            &f,
            Method::POST,
            INVOKE,
            Some(request(id, &policy, json!({"name":"Other"}))),
            true,
            true
        )
        .await?
        .0 == StatusCode::CONFLICT
    );
    let stack = worker(&f.base).await?;
    let task = claim(&f.router).await?;
    ensure!(task["payload"]["task"]["taskId"] == accepted.1["runId"]);
    ensure!(task["payload"]["task"]["parameters"] == json!({"name":"Acme","path":"/Applications"}));
    ensure!(task["payload"]["task"]["arguments"] == json!(["Acme"]));
    ensure!(task["payload"]["task"]["environment"]["RSS_PARAM_PATH"] == "/Applications");
    ensure!(
        task["payload"]["task"]["authorization"]["requestId"] == input["operationId"]
            && task["payload"]["task"]["authorization"]["subject"]["user"]["principalId"]
                == f.author_id
            && task["payload"]["task"]["authorization"]["source"] == "ai"
    );
    complete(&f.router, &task).await?;
    let status = call(
        &f,
        Method::GET,
        &format!("{INVOKE}/{}", input["operationId"].as_str().unwrap()),
        None,
        true,
        true,
    )
    .await?;
    ensure!(
        status.0 == StatusCode::OK
            && status.1["runId"] == accepted.1["runId"]
            && status.1["attemptId"] == task["payload"]["task"]["attemptId"]
    );
    ensure!(
        status.1["result"]["evidence"]["quality"] == "complete"
            && status.1["result"]["evidence"]["collectedAt"] == 2
            && status.1["result"]["evidence"]["receivedAt"]
                .as_i64()
                .unwrap()
                > 2
    );
    ensure!(
        call(
            &f,
            Method::POST,
            INVOKE,
            Some(request(id, &policy, json!({"name":"Again"}))),
            true,
            true
        )
        .await?
        .0 == StatusCode::CONFLICT,
        "self-service must consume once-per-version"
    );
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, true, true).await?.1["items"] == json!([]),
        "consumed once-per-version remained in directory"
    );
    ensure!(run_count(id)?.trim() == "1");
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.self_service"]
async fn self_service_rechecks_config_and_capability_before_start() -> Result<()> {
    let mut f = Fixture::new().await?;
    f.register().await?;
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    let (resource, _, _) = f.resource().await?;
    let mut value = definition(resource, false);
    value["action"]["frequency"] = json!("every_trigger");
    let (id, policy) = publish_definition(&mut f, value.clone()).await?;
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, true, true).await?.1["items"] == json!([]),
        "missing profile facts are Unknown"
    );
    ensure!(
        call(
            &f,
            Method::POST,
            INVOKE,
            Some(request(id, &policy, json!({}))),
            true,
            true
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    ensure!(run_count(id)?.trim() == "0");
    claim_request(&f.router, Uuid::new_v4()).await?;
    value["selfService"]["allowAi"] = json!(false);
    let updated=post(&mut f.author,&f.router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"put","enabled":true,"definition":value.clone()}})).await?;
    ensure!(updated["version"] == policy["version"] && updated["revision"] == 2);
    ensure!(call(&f, Method::GET, DIRECTORY, None, true, true).await?.1["items"] == json!([]));
    ensure!(
        call(
            &f,
            Method::GET,
            &DIRECTORY.replace("source=ai", "source=human"),
            None,
            true,
            true
        )
        .await?
        .1["items"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    let mut human = request(id, &updated, json!({}));
    human["source"] = json!("human");
    human["confirmed"] = json!(false);
    ensure!(
        call(&f, Method::POST, INVOKE, Some(human), true, true)
            .await?
            .0
            == StatusCode::ACCEPTED
    );
    let stack = worker(&f.base).await?;
    let task = claim(&f.router).await?;
    value["selfService"]["published"] = json!(false);
    post(&mut f.author,&f.router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":2,"input":{"action":"put","enabled":true,"definition":value}})).await?;
    let mut start = json!({"kind":"start"});
    ensure!(
        task_event_request(&f.router, &task, Uuid::new_v4(), &mut start)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_attempts WHERE run='{}' AND permit IS NOT NULL",task["payload"]["task"]["taskId"].as_str().unwrap()))?.trim()=="0");
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.self_service"]
async fn grants_and_scope_are_rechecked_and_ai_switch_does_not_change_automation() -> Result<()> {
    let mut f = Fixture::new().await?;
    f.register().await?;
    crate::test_support::identity::independent_source_read(
        case_tenant(),
        &f.author_id,
        f.grants.clone(),
    )
    .await?;
    claim_request(&f.router, Uuid::new_v4()).await?;
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    let (resource, _, _) = f.resource().await?;
    let mut value = definition(resource, false);
    value["selfService"]["riskLevel"] = json!(1);
    let (id, policy) = publish_definition(&mut f, value.clone()).await?;
    let mut input = request(id, &policy, json!({}));
    input["confirmed"] = json!(false);
    ensure!(
        call(&f, Method::POST, INVOKE, Some(input), true, true)
            .await?
            .0
            == StatusCode::ACCEPTED
    );
    let stack = worker(&f.base).await?;
    let task = claim(&f.router).await?;
    task_event(&f.router, &task, json!({"kind":"received"})).await?;
    let revoked = f
        .grants
        .iter()
        .filter(|g| g.operation != crate::authorization::Permission::ScriptExecute)
        .cloned()
        .collect();
    crate::test_support::identity::set_management_grants(case_tenant(), &f.author_id, revoked)
        .await?;
    let mut start = json!({"kind":"start"});
    ensure!(
        task_event_request(&f.router, &task, Uuid::new_v4(), &mut start)
            .await?
            .0
            == StatusCode::OK,
        "employee qualification must not depend on management ScriptExecute"
    );
    ensure!(call(&f, Method::GET, DIRECTORY, None, true, true).await?.0 == StatusCode::OK);
    task_event(&f.router, &task, json!({"kind":"result","exitCode":0,"quality":"complete","output":{"ok":true},"diagnostics":{"stdout":"","stderr":"","durationMs":1,"executedAt":1,"failure":null}})).await?;
    crate::test_support::identity::set_management_grants(
        case_tenant(),
        &f.author_id,
        f.grants.clone(),
    )
    .await?;
    let (second, second_policy) = publish_definition(&mut f, value.clone()).await?;
    ensure!(
        call(
            &f,
            Method::POST,
            INVOKE,
            Some(request(second, &second_policy, json!({}))),
            true,
            true
        )
        .await?
        .0 == StatusCode::ACCEPTED
    );
    let second_task = claim(&f.router).await?;
    let result=post(&mut f.author,&f.router,&format!("/api/v1/scopes/{}",case_task_scope()),json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"put","definition":{"targets":[],"limitations":null,"exclusions":[]}}})).await?;
    let automation = start_automation(&f.base).await?;
    await_task(
        &mut f.author,
        &f.router,
        &format!(
            "/api/v1/scopes/{}/tasks/{}",
            case_task_scope(),
            result["task"].as_str().unwrap()
        ),
    )
    .await?;
    ensure!(
        task_event_request(&f.router, &second_task, Uuid::new_v4(), &mut start)
            .await?
            .0
            == StatusCode::FORBIDDEN,
        "Scope exit must withdraw execution"
    );
    let restored=post(&mut f.author,&f.router,&format!("/api/v1/scopes/{}",case_task_scope()),json!({"operationId":Uuid::new_v4(),"expectedRevision":2,"input":{"action":"put","definition":{"targets":[{"kind":"device","id":case_device_id()}],"limitations":null,"exclusions":[]}}})).await?;
    await_task(
        &mut f.author,
        &f.router,
        &format!(
            "/api/v1/scopes/{}/tasks/{}",
            case_task_scope(),
            restored["task"].as_str().unwrap()
        ),
    )
    .await?;
    crate::test_support::stop_worker(automation).await?;
    value["selfService"]["allowAi"] = json!(false);
    value["selfService"]["access"] = json!({"kind":"users","selectors":[{"kind":"user","instanceId":crate::test_support::identity::INSTANCE,"tenantId":case_tenant(),"principalId":Uuid::new_v4()}]});
    value["action"]["schedule"]=policy_definition(resource,case_task_scope())["action"].get("schedule").cloned().unwrap_or_else(||json!({"trigger":{"kind":"check_in","minimumSeconds":60},"misfire":{"kind":"coalesce_one"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null}));
    let (automatic, published) = publish_definition(&mut f, value.clone()).await?;
    let normal = claim(&f.router).await?;
    ensure!(
        normal["payload"]["task"]["authorization"]["kind"] == "policy"
            && normal["payload"]["task"]["authorization"]["policyId"] == automatic.to_string(),
        "allowAi and nonmatching employee access must not disable automation"
    );
    value["selfService"]["published"] = json!(false);
    let withdrawn = post(&mut f.author, &f.router, &format!("/api/v1/policies/{automatic}"), json!({"operationId":Uuid::new_v4(),"expectedRevision":published["revision"],"input":{"action":"put","enabled":true,"definition":value}})).await?;
    ensure!(withdrawn["versionId"] == published["versionId"]);
    let revoked = f
        .grants
        .iter()
        .filter(|g| g.operation != crate::authorization::Permission::ScriptExecute)
        .cloned()
        .collect();
    crate::test_support::identity::set_management_grants(case_tenant(), &f.author_id, revoked)
        .await?;
    let identity = crate::test_support::identity::identity(case_tenant()).await?;
    let proof = identity
        .authority
        .inspect_session(
            identity.tenant,
            rss_identity_core::session::SessionSecret::parse(
                f.author.cookies["__Host-identity-session"].clone(),
            )?,
            crate::identity::deadline(),
        )
        .await?;
    identity
        .authority
        .revoke_current_session(proof, crate::identity::deadline())
        .await?;
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, true, true).await?.0 == StatusCode::UNAUTHORIZED
    );
    complete(&f.router, &normal).await?;
    ensure!(pg(&format!("SELECT state->>'execution' FROM mdm_commands.action_runs WHERE tenant_id='{}' AND id='{}'", case_tenant(), normal["payload"]["task"]["taskId"].as_str().unwrap()))?.trim() == "succeeded", "self-service withdrawal, management grant removal and enterprise logout must not withdraw ordinary Policy execution");
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.self_service"]
async fn device_access_logged_in_user_requires_exact_os_session_and_helper_without_system_fallback()
-> Result<()> {
    use sha2::{Digest, Sha256};
    let mut f = Fixture::new().await?;
    f.register().await?;
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    let (_, bytes, mut script) = f.resource().await?;
    script["runAs"] = json!("logged_in_user");
    script["purpose"] = json!({"kind":"action"});
    let resource_id = Uuid::new_v4();
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    resource(
        &mut f.author,
        &f.router,
        resource_id,
        0,
        json!({"action":"create","kind":"script"}),
    )
    .await?;
    resource(&mut f.author, &f.router, resource_id, 1, json!({"action":"version","version":"v1","kind":"script","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"script","artifact":{"reference":"logged-in-user-script","length":bytes.len(),"sha256":digest},"definition":script}}]})).await?;
    ensure!(upload(&f.author, &f.router, resource_id, bytes).await? == StatusCode::CREATED);
    resource(
        &mut f.author,
        &f.router,
        resource_id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let mut value = definition(resource_id, false);
    value["selfService"]["access"] = json!({"kind":"device"});
    let (id, policy) = publish_definition(&mut f, value.clone()).await?;
    let os_session = Uuid::new_v4();
    let mut local = crate::test_support::software_execution::context(
        crate::test_support::software_execution::Platform::MacOs,
    );
    local["interactiveUser"] =
        json!({"identity":"501","sessionId":os_session,"administrator":false});
    // Enterprise authentication cannot create an OS user or supply a missing user helper.
    for (revision, helper, user) in [
        (2, false, local["interactiveUser"].clone()),
        (3, true, Value::Null),
    ] {
        let mut missing = local.clone();
        missing["revision"] = json!(revision);
        missing["userHelper"] = json!(helper);
        missing["interactiveUser"] = user;
        let poll = claim_with_context(&f.router, &missing).await?;
        ensure!(poll.0 == StatusCode::OK && poll.1["task"].is_null());
        for enterprise_user in [false, true] {
            let directory = call(&f, Method::GET, DIRECTORY, None, true, enterprise_user).await?;
            ensure!(directory.0 == StatusCode::OK && directory.1["items"] == json!([]));
            ensure!(
                call(
                    &f,
                    Method::POST,
                    INVOKE,
                    Some(request(id, &policy, json!({}))),
                    true,
                    enterprise_user
                )
                .await?
                .0 == StatusCode::FORBIDDEN
            );
        }
    }
    ensure!(run_count(id)?.trim() == "0");
    local["revision"] = json!(4);
    ensure!(claim_with_context(&f.router, &local).await?.0 == StatusCode::OK);
    let directory = call(&f, Method::GET, DIRECTORY, None, true, false).await?;
    ensure!(directory.0 == StatusCode::OK && directory.1["items"].as_array().unwrap().len() == 1);
    ensure!(directory.1["items"][0]["task"]["runAs"] == "logged_in_user");
    let accepted = call(
        &f,
        Method::POST,
        INVOKE,
        Some(request(id, &policy, json!({}))),
        true,
        false,
    )
    .await?;
    ensure!(
        accepted.0 == StatusCode::ACCEPTED,
        "Device access must not require an enterprise session: {accepted:?}"
    );
    let stack = worker(&f.base).await?;
    let mut changed = local.clone();
    changed["revision"] = json!(5);
    changed["interactiveUser"]["identity"] = json!("502");
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let poll = claim_with_context(&f.router, &changed).await?;
            ensure!(poll.0 == StatusCode::OK && poll.1["task"].is_null(), "changed OS identity must never receive a replacement System offer: {poll:?}");
            if pg(&format!("SELECT state->>'cancellation' FROM mdm_commands.action_runs WHERE tenant_id='{}' AND id='{}'", case_tenant(), accepted.1["runId"].as_str().unwrap()))?.trim() == "confirmed" { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, anyhow::Error>(())
    }).await??;
    local["revision"] = json!(6);
    ensure!(claim_with_context(&f.router, &local).await?.0 == StatusCode::OK);
    // Each Start checks the exact effect target bound at request and Offer, while the broker remains available.
    for failure in ["identity", "session", "helper", "user"] {
        let (id, policy) = publish_definition(&mut f, value.clone()).await?;
        let accepted = call(
            &f,
            Method::POST,
            INVOKE,
            Some(request(id, &policy, json!({}))),
            true,
            false,
        )
        .await?;
        ensure!(accepted.0 == StatusCode::ACCEPTED);
        let task = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let poll = claim_with_context(&f.router, &local).await?;
                ensure!(poll.0 == StatusCode::OK, "claim: {poll:?}");
                if !poll.1["task"].is_null() {
                    return Ok::<_, anyhow::Error>(poll.1["task"].clone());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await??;
        let target = json!({"kind":"user","identity":"501","sessionId":os_session});
        ensure!(
            task["payload"]["task"]["taskId"] == accepted.1["runId"]
                && task["payload"]["task"]["executionTarget"] == target
                && task["payload"]["task"]["runAs"] == "logged_in_user"
                && task["payload"]["task"]["authorization"]["subject"]["kind"] == "device"
        );
        ensure!(
            event_with_context(&f.router, &task, &local, json!({"kind":"received"}))
                .await?
                .0
                == StatusCode::OK
        );
        let mut changed = local.clone();
        changed["revision"] = json!(local["revision"].as_u64().unwrap() + 1);
        match failure {
            "identity" => changed["interactiveUser"]["identity"] = json!("502"),
            "session" => changed["interactiveUser"]["sessionId"] = json!(Uuid::new_v4()),
            "helper" => changed["userHelper"] = json!(false),
            "user" => changed["interactiveUser"] = Value::Null,
            _ => unreachable!(),
        }
        let rejected =
            event_with_context(&f.router, &task, &changed, json!({"kind":"start"})).await?;
        ensure!(
            rejected.0 == StatusCode::FORBIDDEN,
            "{failure} change must reject Start despite an available System broker: {rejected:?}"
        );
        let started = event_with_context(&f.router, &task, &local, json!({"kind":"start"})).await?;
        ensure!(
            started.0 == StatusCode::OK
                && started.1["permit"]["payload"]["task"]["executionTarget"] == target
                && started.1["permit"]["payload"]["task"]["runAs"] == "logged_in_user",
            "only the original OS session may start: {started:?}"
        );
        let result = event_with_context(&f.router, &task, &local, json!({"kind":"result","exitCode":0,"quality":"complete","collectedAt":2,"output":{"version":"1.2","healthy":true},"diagnostics":{"stdout":"","stderr":"","durationMs":1,"executedAt":1,"failure":null}})).await?;
        ensure!(result.0 == StatusCode::OK, "result: {result:?}");
        let missing_helper = json!({"revision":local["revision"].as_u64().unwrap()+1,"osVersion":[14,0,0,0],"userHelper":false,"systemBroker":true,"interactiveUser":null,"sourceCredentials":[],"msixSideload":false,"msixUnsigned":false});
        ensure!(claim_with_context(&f.router, &missing_helper).await?.0 == StatusCode::OK);
        let state = call(
            &f,
            Method::GET,
            &format!(
                "{INVOKE}/{}",
                task["payload"]["task"]["authorization"]["requestId"]
                    .as_str()
                    .unwrap()
            ),
            None,
            true,
            false,
        )
        .await?;
        ensure!(
            state.0 == StatusCode::OK && state.1["state"]["execution"] == "succeeded",
            "historical state must not require a live execution helper: {state:?}"
        );
        local["revision"] = json!(local["revision"].as_u64().unwrap() + 2);
        ensure!(claim_with_context(&f.router, &local).await?.0 == StatusCode::OK);
    }
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.self_service"]
async fn check_in_interval_is_shared_by_automatic_and_targeted_calls() -> Result<()> {
    let mut f = Fixture::new().await?;
    f.register().await?;
    claim_request(&f.router, Uuid::new_v4()).await?;
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    let (resource, _, _) = f.resource().await?;
    let mut value = definition(resource, false);
    value["action"]["frequency"] = json!("every_trigger");
    value["action"]["schedule"]["trigger"] = json!({"kind":"check_in","minimumSeconds":3600});
    let (id, policy) = publish_definition(&mut f, value).await?;
    let stack = worker(&f.base).await?;
    let automatic = claim(&f.router).await?;
    ensure!(automatic["payload"]["task"]["authorization"]["kind"] == "policy");
    complete(&f.router, &automatic).await?;
    ensure!(
        call(
            &f,
            Method::POST,
            INVOKE,
            Some(request(id, &policy, json!({}))),
            true,
            true
        )
        .await?
        .0 == StatusCode::CONFLICT,
        "automatic run must consume the same minimum interval"
    );
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, true, true).await?.1["items"] == json!([]),
        "cooldown remained in directory"
    );
    ensure!(run_count(id)?.trim() == "1");
    pg(&format!(
        "UPDATE mdm_commands.action_runs SET created_at=created_at-3601 WHERE id='{}'",
        automatic["payload"]["task"]["taskId"].as_str().unwrap()
    ))?;
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, true, true).await?.1["items"]
            .as_array()
            .unwrap()
            .len()
            == 1,
        "elapsed cooldown did not restore directory"
    );
    let accepted = call(
        &f,
        Method::POST,
        INVOKE,
        Some(request(id, &policy, json!({}))),
        true,
        true,
    )
    .await?;
    ensure!(accepted.0 == StatusCode::ACCEPTED);
    let targeted = claim(&f.router).await?;
    ensure!(targeted["payload"]["task"]["taskId"] == accepted.1["runId"]);
    complete(&f.router, &targeted).await?;
    ensure!(
        call(
            &f,
            Method::POST,
            INVOKE,
            Some(request(id, &policy, json!({}))),
            true,
            true
        )
        .await?
        .0 == StatusCode::CONFLICT,
        "targeted run must consume the same minimum interval"
    );
    ensure!(
        claim_request(&f.router, Uuid::new_v4()).await?.1["task"].is_null(),
        "targeted run must also suppress automatic check-in"
    );
    ensure!(run_count(id)?.trim() == "2");
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.self_service"]
async fn sensitive_status_rechecks_read_permissions_without_leaking_diagnostics() -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    let mut f = Fixture::new().await?;
    f.register().await?;
    claim_request(&f.router, Uuid::new_v4()).await?;
    f.grants.push(Grant {
        operation: Permission::InventoryFieldsWrite,
        scope: Scope::Tenant,
    });
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
        .await?;
    let key = "custom.self_service_secret";
    let field = json!({"key":key,"version":1,"valueType":{"kind":"string","maxLength":128,"allowEmpty":false},"nullable":false,"manual":false,"sources":{"agent.script":100},"platforms":["macos"],"sensitivity":"sensitive","unit":null,"searchable":true,"itemKey":null});
    ensure!(f.author.call(&f.router, Method::PUT, &format!("/api/v1/asset-fields/{key}"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":field}}))).await?.0 == StatusCode::OK);
    let resource_id = Uuid::new_v4();
    let bytes = b"printf '{}'";
    let digest = rss_mdm_resource::Digest::of(bytes).bytes();
    let script = json!({"profile":"posix_sh","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{"secret":{"type":"string"}},"required":["secret"],"additionalProperties":false},"purpose":{"kind":"collection","scope":{"kind":"device"},"applicability":{"minimumOsVersion":null,"minimumBuild":null,"editions":[],"enrollments":[],"tools":{},"capabilities":[]},"mappings":{key:{"pointer":"/secret","conversion":{"kind":"identity"},"columns":{}}}},"timeoutSeconds":60,"outputBytes":4096,"maxRows":1});
    resource(
        &mut f.author,
        &f.router,
        resource_id,
        0,
        json!({"action":"create","kind":"script"}),
    )
    .await?;
    resource(&mut f.author, &f.router, resource_id, 1, json!({"action":"version","version":"v1","kind":"script","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"script","artifact":{"reference":"self-service-secret","length":bytes.len(),"sha256":digest},"definition":script}}]})).await?;
    ensure!(upload(&f.author, &f.router, resource_id, bytes).await? == StatusCode::CREATED);
    resource(
        &mut f.author,
        &f.router,
        resource_id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    let (id, policy) = publish_definition(&mut f, definition(resource_id, false)).await?;
    let input = request(id, &policy, json!({}));
    ensure!(
        call(&f, Method::POST, INVOKE, Some(input.clone()), true, true)
            .await?
            .0
            == StatusCode::ACCEPTED
    );
    let stack = worker(&f.base).await?;
    let task = claim(&f.router).await?;
    task_event(&f.router, &task, json!({"kind":"received"})).await?;
    task_event(&f.router, &task, json!({"kind":"start"})).await?;
    let canary = "self-service-private-canary";
    task_event(&f.router, &task, json!({"kind":"result","exitCode":0,"quality":"complete","output":{"secret":canary},"diagnostics":{"stdout":canary,"stderr":canary,"durationMs":1,"executedAt":1,"failure":null}})).await?;
    let path = format!("{INVOKE}/{}", input["operationId"].as_str().unwrap());
    let mut full = f.grants.clone();
    full.push(Grant {
        operation: Permission::InventorySensitiveRead,
        scope: Scope::Tenant,
    });
    let no_read = full
        .iter()
        .filter(|g| g.operation != Permission::InventoryRead)
        .cloned()
        .collect();
    for grants in [no_read, f.grants.clone()] {
        crate::test_support::identity::set_grants(case_tenant(), &f.author_id, grants).await?;
        let denied = call(&f, Method::GET, &path, None, true, true).await?;
        ensure!(
            denied.0 == StatusCode::OK
                && denied.1["result"].is_null()
                && denied.1["state"]["execution"] == "succeeded"
                && !denied.1.to_string().contains(canary),
            "read denied without leakage: {denied:?}"
        );
    }
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, full).await?;
    let permitted = call(&f, Method::GET, &path, None, true, true).await?;
    ensure!(
        permitted.0 == StatusCode::OK
            && permitted.1["result"]["evidence"]["output"]["secret"] == canary
            && permitted.1["result"]["evidence"]["diagnostics"]["stdout"] == canary
            && permitted.1["result"]["evidence"]["diagnostics"]["stderr"] == canary
    );
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
        .await?;
    let denied = call(&f, Method::GET, &path, None, true, true).await?;
    ensure!(
        denied.0 == StatusCode::OK
            && denied.1["result"].is_null()
            && denied.1["state"]["execution"] == "succeeded"
            && !denied.1.to_string().contains(canary),
        "withdrawal must suppress the full result"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.self_service"]
async fn employee_request_ids_are_independent_and_unknown_is_hidden() -> Result<()> {
    let mut f = Fixture::new().await?;
    f.register().await?;
    claim_request(&f.router, Uuid::new_v4()).await?;
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    let (resource, _, _) = f.resource().await?;
    let (first, first_policy) = publish_definition(&mut f, definition(resource, false)).await?;
    let (second, second_policy) = publish_definition(&mut f, definition(resource, false)).await?;
    let shared = Uuid::new_v4();
    let mut one = request(first, &first_policy, json!({}));
    one["operationId"] = json!(shared);
    let accepted_one = call(&f, Method::POST, INVOKE, Some(one.clone()), true, true).await?;
    ensure!(accepted_one.0 == StatusCode::ACCEPTED);
    let original = f.author.clone();
    let mut employee = Browser::default();
    ensure!(employee.login(&f.router, "admin").await? == StatusCode::OK);
    let other = browser_subject(&employee, &f.router).await?;
    ensure!(other != f.author_id);
    crate::test_support::identity::set_grants(case_tenant(), &other, f.grants.clone()).await?;
    f.author = employee;
    let mut two = request(second, &second_policy, json!({}));
    two["operationId"] = json!(shared);
    let accepted_two = call(&f, Method::POST, INVOKE, Some(two.clone()), true, true).await?;
    ensure!(
        accepted_two.0 == StatusCode::ACCEPTED,
        "second employee collision: {accepted_two:?}"
    );
    ensure!(accepted_one.1["runId"] != accepted_two.1["runId"]);
    ensure!(
        call(&f, Method::POST, INVOKE, Some(two), true, true)
            .await?
            .1
            == accepted_two.1
    );
    let status_path = format!("{INVOKE}/{shared}");
    ensure!(
        call(&f, Method::GET, &status_path, None, true, true)
            .await?
            .1["runId"]
            == accepted_two.1["runId"]
    );
    f.author = original;
    ensure!(
        call(&f, Method::POST, INVOKE, Some(one), true, true)
            .await?
            .1
            == accepted_one.1
    );
    ensure!(
        call(&f, Method::GET, &status_path, None, true, true)
            .await?
            .1["runId"]
            == accepted_one.1["runId"]
    );
    let events = audit_records()?;
    let matching: Vec<_> = events
        .iter()
        .filter(|record| {
            record.source() == "mdm.business"
                && record.operation() == Some(shared.to_string().as_str())
        })
        .collect();
    ensure!(
        matching.len() == 2,
        "employees must retain independent original events"
    );
    ensure!(
        matching[0].decoded.event().identity().event_id().as_str()
            != matching[1].decoded.event().identity().event_id().as_str()
    );
    let (available, available_policy) =
        publish_definition(&mut f, definition(resource, false)).await?;
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, true, true).await?.1["items"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    let first_run = accepted_one.1["runId"].as_str().unwrap();
    pg(&format!(
        "INSERT INTO mdm_commands.action_runs SELECT (jsonb_populate_record(NULL::mdm_commands.action_runs,to_jsonb(r)||jsonb_build_object('id',gen_random_uuid(),'occurrence','fixture-capacity:'||n))).* FROM mdm_commands.action_runs r CROSS JOIN generate_series(1,126) n WHERE r.id='{first_run}'"
    ))?;
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, true, true).await?.1["items"] == json!([]),
        "capacity-exhausted script remained in directory"
    );
    ensure!(
        call(
            &f,
            Method::POST,
            INVOKE,
            Some(request(available, &available_policy, json!({}))),
            true,
            true
        )
        .await?
        .0 == StatusCode::CONFLICT
    );
    pg(&format!(
        "DELETE FROM mdm_commands.action_runs WHERE tenant_id='{}' AND occurrence LIKE 'fixture-capacity:%'",
        case_tenant()
    ))?;
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, true, true).await?.1["items"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    post(&mut f.author,&f.router,&format!("/api/v1/policies/{available}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":available_policy["revision"],"input":{"action":"disable"}})).await?;
    // Pending on the first Policy becomes a genuine Unknown through the existing reducer.
    let stack = worker(&f.base).await?;
    let task = claim(&f.router).await?;
    task_event(&f.router, &task, json!({"kind":"received"})).await?;
    task_event(&f.router, &task, json!({"kind":"start"})).await?;
    let run = task["payload"]["task"]["taskId"].as_str().unwrap();
    pg(&format!(
        "UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{{startedAt}}',to_jsonb(floor(extract(epoch FROM clock_timestamp()))::bigint-61)) WHERE id='{run}'"
    ))?;
    let policy = task["payload"]["task"]["authorization"]["policyId"]
        .as_str()
        .unwrap();
    for _ in 0..2 {
        f.execution
            .recover_action_fixture(Uuid::parse_str(policy)?)
            .await?;
    }
    ensure!(
        pg(&format!(
            "SELECT state->>'execution' FROM mdm_commands.action_runs WHERE id='{run}'"
        ))?
        .trim()
            == "unknown"
    );
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, true, true).await?.1["items"] == json!([]),
        "Unknown or pending script remained in directory"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.self_service"]
async fn explicit_access_uses_live_identity_membership_and_device_subjects_without_management_grants()
-> Result<()> {
    let mut f = Fixture::new().await?;
    f.register().await?;
    claim_request(&f.router, Uuid::new_v4()).await?;
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    let (resource, _, _) = f.resource().await?;
    let mut admin = Browser::default();
    ensure!(admin.login(&f.router, "admin").await? == StatusCode::OK);
    let group = Uuid::new_v4();
    let group_path = format!("/api/v1/authorization/user-groups/{group}");
    let group_value = json!({"name":"Self service employees","enabled":true,"members":[crate::test_support::identity::user(case_tenant(), &f.author_id)]});
    ensure!(
        admin
            .call(
                &f.router,
                Method::PUT,
                &group_path,
                Some(
                    json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":group_value})
                )
            )
            .await?
            .0
            == StatusCode::OK
    );
    let publisher = browser_subject(&admin, &f.router).await?;
    crate::test_support::identity::set_grants(case_tenant(), &publisher, f.grants.clone()).await?;
    let mut published = Vec::new();
    for access in [
        json!({"kind":"device"}),
        json!({"kind":"users","selectors":[{"kind":"user_group","id":group}]}),
        json!({"kind":"authenticated_user"}),
        json!({"kind":"authenticated_user"}),
    ] {
        let mut value = definition(resource, false);
        value["selfService"]["access"] = access;
        published.push(publish_definition_as(&mut admin, &f.router, value).await?);
    }
    for selector in [
        json!({"kind":"idp_group","source":{"providerId":Uuid::new_v4(),"issuer":"https://idp.example.invalid","configurationVersion":1},"id":"employees"}),
        json!({"kind":"department","source":{"providerId":Uuid::new_v4(),"issuer":"https://idp.example.invalid","configurationVersion":1},"id":"engineering","matching":"subtree"}),
    ] {
        let mut value = definition(resource, false);
        value["selfService"]["access"] = json!({"kind":"users","selectors":[selector]});
        publish_definition_as(&mut admin, &f.router, value).await?;
    }
    let mut cross_tenant = definition(resource, false);
    cross_tenant["selfService"]["access"] = json!({"kind":"users","selectors":[{"kind":"user","instanceId":crate::test_support::identity::INSTANCE,"tenantId":Uuid::new_v4(),"principalId":f.author_id}]});
    let invalid = f.author.call(&f.router, Method::POST, &format!("/api/v1/policies/{}", Uuid::new_v4()), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":cross_tenant}}))).await?;
    ensure!(invalid.0 == StatusCode::BAD_REQUEST);
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, Vec::new()).await?;
    let device_directory = call(&f, Method::GET, DIRECTORY, None, true, false).await?;
    ensure!(
        device_directory.0 == StatusCode::OK
            && device_directory.1["items"].as_array().unwrap().len() == 1
    );
    let employee_directory = call(&f, Method::GET, DIRECTORY, None, true, true).await?;
    ensure!(
        employee_directory.0 == StatusCode::OK
            && employee_directory.1["items"].as_array().unwrap().len() == 4,
        "untrusted IdP/department facts must not match: {employee_directory:?}"
    );
    let expected_user = json!({"kind":"user","user":{
        "tenantId":case_tenant(),
        "instanceId":crate::test_support::identity::INSTANCE,
        "principalId":f.author_id
    }});
    for item in employee_directory.1["items"].as_array().unwrap() {
        let expected = if item["policyId"] == published[0].0.to_string() {
            json!({"kind":"device"})
        } else {
            expected_user.clone()
        };
        ensure!(
            item["subject"] == expected,
            "incorrect qualified subject: {item}"
        );
    }
    ensure!(device_directory.1["items"][0]["subject"] == json!({"kind":"device"}));
    let human_directory = call(
        &f,
        Method::GET,
        "/api/v1/agent/runtime/self-service?source=human",
        None,
        true,
        true,
    )
    .await?;
    ensure!(
        human_directory.0 == StatusCode::OK
            && human_directory.1["items"] == employee_directory.1["items"],
        "caller origin must not change qualified subjects: {human_directory:?}"
    );
    let stack = worker(&f.base).await?;
    let (device, policy) = &published[0];
    let device_input = request(*device, policy, json!({}));
    let accepted = call(
        &f,
        Method::POST,
        INVOKE,
        Some(device_input.clone()),
        true,
        false,
    )
    .await?;
    ensure!(accepted.0 == StatusCode::ACCEPTED);
    let device_task = claim(&f.router).await?;
    ensure!(
        device_task["payload"]["task"]["authorization"]["subject"]["kind"] == "device"
            && device_task["payload"]["task"]["runAs"] == "system"
    );
    ensure!(
        device_task["payload"]["task"]["authorization"]["subject"]
            == device_directory.1["items"][0]["subject"]
    );
    complete(&f.router, &device_task).await?;
    ensure!(
        call(
            &f,
            Method::GET,
            &format!("{INVOKE}/{}", device_input["operationId"].as_str().unwrap()),
            None,
            true,
            false
        )
        .await?
        .1["state"]["execution"]
            == "succeeded"
    );
    let (group_policy, policy) = &published[1];
    ensure!(
        call(
            &f,
            Method::POST,
            INVOKE,
            Some(request(*group_policy, policy, json!({}))),
            true,
            true
        )
        .await?
        .0 == StatusCode::ACCEPTED
    );
    let grouped = claim(&f.router).await?;
    ensure!(grouped["payload"]["task"]["authorization"]["subject"] == expected_user);
    let mut disabled = group_value.clone();
    disabled["enabled"] = json!(false);
    ensure!(
        admin
            .call(
                &f.router,
                Method::PUT,
                &group_path,
                Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"value":disabled}))
            )
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        task_event_request(
            &f.router,
            &grouped,
            Uuid::new_v4(),
            &mut json!({"kind":"start"})
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    for index in [2, 3] {
        let (id, policy) = &published[index];
        ensure!(
            call(
                &f,
                Method::POST,
                INVOKE,
                Some(request(*id, policy, json!({}))),
                true,
                true
            )
            .await?
            .0 == StatusCode::ACCEPTED
        );
    }
    // Hold both offers first; revocation must forbid the unstarted one and permit safe result intake on the started one.
    let one = claim(&f.router).await?;
    task_event(&f.router, &one, json!({"kind":"received"})).await?;
    task_event(&f.router, &one, json!({"kind":"start"})).await?;
    let two = claim(&f.router).await?;
    let identity = crate::test_support::identity::identity(case_tenant()).await?;
    let secret = rss_identity_core::session::SessionSecret::parse(
        f.author
            .cookies
            .get("__Host-identity-session")
            .unwrap()
            .clone(),
    )?;
    let proof = identity
        .authority
        .inspect_session(identity.tenant, secret, crate::identity::deadline())
        .await?;
    identity
        .authority
        .revoke_current_session(proof, crate::identity::deadline())
        .await?;
    ensure!(
        task_event_request(
            &f.router,
            &two,
            Uuid::new_v4(),
            &mut json!({"kind":"start"})
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    task_event(
        &f.router,
        &one,
        json!({"kind":"result","exitCode":0,"quality":"complete","output":{"ok":true}}),
    )
    .await?;
    let execution = pg(&format!(
        "SELECT state->>'execution' FROM mdm_commands.action_runs WHERE tenant_id='{}' AND id='{}'",
        case_tenant(),
        one["payload"]["task"]["taskId"].as_str().unwrap()
    ))?;
    ensure!(
        execution.trim() == "succeeded",
        "started execution must finish after enterprise logout: {execution}"
    );
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, true, true).await?.0 == StatusCode::UNAUTHORIZED
    );
    ensure!(call(&f, Method::GET, DIRECTORY, None, true, false).await?.0 == StatusCode::OK);
    f.author = Browser::default();
    ensure!(
        f.author
            .login_password(&f.router, "other", crate::test_support::identity::PASSWORD)
            .await?
            == StatusCode::OK
    );
    let reread = call(
        &f,
        Method::GET,
        &format!(
            "{INVOKE}/{}",
            one["payload"]["task"]["authorization"]["requestId"]
                .as_str()
                .unwrap()
        ),
        None,
        true,
        true,
    )
    .await?;
    ensure!(
        reread.0 == StatusCode::OK
            && reread.1["state"]["execution"] == "succeeded"
            && reread.1["result"].is_null(),
        "same principal may read accepted state through a new enterprise session: {reread:?}"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

async fn software_self_service_call(
    router: &Router,
    credential: &str,
    employee: &Browser,
    method: Method,
    path: &str,
    value: Option<Value>,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mdm.example.test:9445")
        .header(
            "x-rss-user-session",
            employee.cookies.get("__Host-identity-session").unwrap(),
        )
        .extension(crate::test_support::agent::evidence(credential).unwrap());
    let body = match value {
        Some(value) => {
            request = request.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&value)?)
        }
        None => Body::empty(),
    };
    let response = router.clone().oneshot(request.body(body)?).await?;
    let status = response.status();
    Ok((
        status,
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?,
    ))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.self_service"]
async fn available_software_requires_request_and_deduplicates_users_policies_and_verified_effects()
-> Result<()> {
    use crate::test_support::software_execution as software;
    let mut f = software::Fixture::approved(software::Platform::MacOs).await?;
    let mut other = Browser::default();
    ensure!(other.login(&f.router, "admin").await? == StatusCode::OK);
    let employee = f
        .author
        .call(&f.router, Method::GET, "/api/v1/authorization", None)
        .await?
        .1;
    let administrator = other
        .call(&f.router, Method::GET, "/api/v1/authorization", None)
        .await?
        .1;
    let grants = |view: &Value| {
        view["grants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|grant| {
                serde_json::from_value::<crate::authorization::Grant>(
                    json!({"operation":grant["operation"],"scope":grant["scope"]}),
                )
            })
            .collect::<serde_json::Result<Vec<_>>>()
    };
    let mut administrator_grants = grants(&administrator)?;
    let employee_grants = grants(&employee)?;
    for grant in employee_grants {
        if !administrator_grants.contains(&grant) {
            administrator_grants.push(grant);
        }
    }
    crate::test_support::identity::set_grants(
        case_tenant(),
        administrator["principalId"].as_str().unwrap(),
        administrator_grants,
    )
    .await?;
    // Keep approval authority with an administrator while the requesting employee loses every management grant.
    for (path, revision) in [
        (
            format!(
                "/api/v1/software/sources/{}/revisions/{}",
                f.source_snapshot["id"].as_str().unwrap(),
                f.source_snapshot["revision"].as_str().unwrap()
            ),
            2,
        ),
        (
            format!("/api/v1/software/resources/{}/versions/v1", f.dependency),
            1,
        ),
        (
            format!("/api/v1/software/resources/{}/versions/v1", f.resource),
            1,
        ),
    ] {
        crate::test_support::software::write(
            &mut other,
            &f.router,
            &path,
            revision,
            json!({"action":"withdraw","evidence":["transfer-approval-authority"]}),
        )
        .await?;
        let approved = crate::test_support::software::write(
            &mut other,
            &f.router,
            &path,
            revision + 1,
            json!({"action":"approve","evidence":["administrator-approval"]}),
        )
        .await?;
        if path == format!("/api/v1/software/resources/{}/versions/v1", f.resource) {
            f.first_operation = approved["admission"]["operation"].clone();
        }
    }
    let mut policies = Vec::new();
    for _ in 0..2 {
        let id = Uuid::new_v4();
        let mut definition =
            software::authored(f.resource, f.scope, "available_install", &f.first_operation);
        definition["selfService"] = json!({"access":{"kind":"authenticated_user"},"published":true,"displayName":"Install app","description":"Approved installer","prerequisites":"","sideEffects":"Install","category":"Applications","keywords":[]});
        let published = crate::test_support::software::write(
            &mut other,
            &f.router,
            &format!("/api/v1/policies/{id}"),
            0,
            json!({"action":"put","enabled":true,"definition":definition}),
        )
        .await?;
        policies.push((id, published));
    }
    let current = f
        .author
        .call(&f.router, Method::GET, "/api/v1/authorization", None)
        .await?
        .1;
    crate::test_support::identity::set_grants(
        case_tenant(),
        current["principalId"].as_str().unwrap(),
        Vec::new(),
    )
    .await?;
    let employee_authorization = f
        .author
        .call(&f.router, Method::GET, "/api/v1/authorization", None)
        .await?;
    ensure!(
        employee_authorization.0 == StatusCode::OK
            && employee_authorization.1["grants"] == json!([]),
        "ordinary employee must retain zero effective management grants: {employee_authorization:?}"
    );
    let poll=agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(&f.credential),Some(json!({"wireVersion":1,"executionContext":software::context(software::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh"],"operationId":Uuid::new_v4()}))).await?;
    ensure!(
        poll.0 == StatusCode::OK && poll.1["task"].is_null(),
        "AvailableInstall must not prequeue: {poll:?}"
    );
    let directory = software_self_service_call(
        &f.router,
        &f.credential,
        &f.author,
        Method::GET,
        DIRECTORY,
        None,
    )
    .await?;
    ensure!(directory.0 == StatusCode::OK && directory.1["items"].as_array().unwrap().len() == 2);
    ensure!(
        directory.1["items"][0]["task"]["kind"] == "software"
            && directory.1["items"][0]["task"]["runAs"] == "system"
            && directory.1["items"][0]["selfService"]["riskLevel"] == 2
    );
    let expected_subject = json!({"kind":"user","user":{
        "tenantId":current["tenantId"],
        "instanceId":current["instanceId"],
        "principalId":current["principalId"]
    }});
    ensure!(
        directory.1["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["subject"] == expected_subject)
    );
    let mut unconfirmed = request(policies[0].0, &policies[0].1, json!({}));
    unconfirmed["confirmed"] = json!(false);
    ensure!(
        software_self_service_call(
            &f.router,
            &f.credential,
            &f.author,
            Method::POST,
            INVOKE,
            Some(unconfirmed)
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    let one = request(policies[0].0, &policies[0].1, json!({}));
    let two = request(policies[1].0, &policies[1].1, json!({}));
    use sqlx::Connection;
    let mut blocker =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let mut observer =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let backend: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut blocker)
        .await?;
    let mut blocked = blocker.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2465))")
        .bind(format!("{}:{}", case_tenant(), software::case_device()))
        .execute(&mut *blocked)
        .await?;
    let release = async {
        let overlap = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let waiters: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_locks w JOIN pg_locks held ON (w.database,w.classid,w.objid,w.objsubid)=(held.database,held.classid,held.objid,held.objsubid) WHERE held.pid=$1 AND held.locktype='advisory' AND held.granted AND w.locktype='advisory' AND NOT w.granted").bind(backend).fetch_one(&mut observer).await?;
                let audit_chain: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity business JOIN pg_stat_activity audit ON business.pid=ANY(pg_blocking_pids(audit.pid)) WHERE business.datname=current_database() AND audit.datname=current_database() AND business.usename='mdm_command_runtime' AND audit.usename='mdm_command_runtime' AND business.wait_event_type='Lock' AND audit.wait_event_type='Lock' AND business.query LIKE '%pg_advisory_xact_lock(hashtextextended($1,2465))%' AND audit.query LIKE '%rss_audit.reserve%' AND $1=ANY(pg_blocking_pids(business.pid)))").bind(backend).fetch_one(&mut observer).await?;
                if waiters == 2 || audit_chain { return Ok::<_,anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await;
        blocked.rollback().await?;
        overlap??;
        Ok::<_, anyhow::Error>(())
    };
    let (a, b, overlap) = tokio::join!(
        software_self_service_call(
            &f.router,
            &f.credential,
            &f.author,
            Method::POST,
            INVOKE,
            Some(one.clone())
        ),
        software_self_service_call(
            &f.router,
            &f.credential,
            &f.author,
            Method::POST,
            INVOKE,
            Some(two.clone())
        ),
        release
    );
    overlap?;
    let (a, b) = (a?, b?);
    ensure!(
        (a.0 == StatusCode::ACCEPTED && b.0 == StatusCode::CONFLICT)
            || (b.0 == StatusCode::ACCEPTED && a.0 == StatusCode::CONFLICT),
        "same version/system effect must accept one zero-grant employee request across competing policies: {a:?} {b:?}"
    );
    let (accepted, input) = if a.0 == StatusCode::ACCEPTED {
        (a, one)
    } else {
        (b, two)
    };
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{}' AND policy_version IN ('{}','{}') AND software_effect IS NOT NULL",case_tenant(),policies[0].1["versionId"].as_str().unwrap(),policies[1].1["versionId"].as_str().unwrap()))?.trim() == "1", "competing new requests must commit one exact effect and one Run");
    let stack = software::worker(&f.base, f.content.clone()).await?;
    let employee = &f.author;
    ensure!(
        software_self_service_call(
            &f.router,
            &f.credential,
            &other,
            Method::POST,
            INVOKE,
            Some(request(policies[0].0, &policies[0].1, json!({})))
        )
        .await?
        .0 == StatusCode::CONFLICT,
        "shared pending System effect must also block a different user"
    );
    ensure!(
        software_self_service_call(
            &f.router,
            &f.credential,
            employee,
            Method::POST,
            INVOKE,
            Some(input.clone())
        )
        .await?
        .1 == accepted.1
    );
    let task = software::claim(&f.router).await?;
    ensure!(task["payload"]["task"]["authorization"]["subject"] == expected_subject);
    ensure!(
        task["payload"]["task"]["taskId"] == accepted.1["runId"]
            && task["payload"]["task"]["authorization"]["kind"] == "self_service"
            && task["payload"]["task"]["authorization"]["subject"]["kind"] == "user"
            && task["payload"]["task"]["authorization"]["subject"]["user"]["principalId"]
                == current["principalId"]
    );
    ensure!(
        software::event(&f.router, &task, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        software::event(&f.router, &task, json!({"kind":"start"}))
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        software::event(
            &f.router,
            &task,
            software::result_event(&task, "install", Some(17), "present", false)?
        )
        .await?
        .0 == StatusCode::OK
    );
    let status = software_self_service_call(
        &f.router,
        &f.credential,
        employee,
        Method::GET,
        &format!("{INVOKE}/{}", input["operationId"].as_str().unwrap()),
        None,
    )
    .await?;
    ensure!(
        status.0 == StatusCode::OK
            && status.1["state"]["execution"] == "succeeded"
            && status.1["result"] == json!({"kind":"software","effect":"verified"})
    );
    for (id, policy) in &policies {
        ensure!(
            software_self_service_call(
                &f.router,
                &f.credential,
                &f.author,
                Method::POST,
                INVOKE,
                Some(request(*id, policy, json!({})))
            )
            .await?
            .0 == StatusCode::CONFLICT,
            "verified system effect must suppress another policy/user installation"
        );
    }
    ensure!(
        software_self_service_call(
            &f.router,
            &f.credential,
            &f.author,
            Method::GET,
            DIRECTORY,
            None
        )
        .await?
        .1["items"]
            == json!([])
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

#[test]
fn explicit_unpublished_access_null_follows_the_write_contract() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../management-http/schema/PolicyWrite.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let body = serde_json::json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":uuid::Uuid::new_v4(),"action":{"kind":"execution","resource":{"id":"repair","version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"parameters":{},"runLifetimeSeconds":300},"selfService":{"access":null,"published":false,"displayName":"Repair","description":"","prerequisites":"","sideEffects":"","category":"Support","keywords":[]}}}});
    assert!(validator.is_valid(&body));
    let mut missing = body;
    missing["input"]["definition"]["selfService"]
        .as_object_mut()
        .unwrap()
        .remove("access");
    assert!(!validator.is_valid(&missing));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.self_service"]
async fn software_unknown_survives_same_account_relogin_and_keeps_other_accounts_separate()
-> Result<()> {
    use crate::test_support::software_execution as software;
    let mut local = software::context(software::Platform::Windows);
    let session = Uuid::new_v4();
    let sid = "S-1-5-21-1-2-3-1001";
    local["interactiveUser"] = json!({"identity":sid,"sessionId":session,"administrator":false});
    let mut f = software::Fixture::with_profiles(
        software::Platform::Windows,
        json!([
            "inventory.collect.v1",
            "software.msi.system.v1",
            "software.msi.user.v1"
        ]),
        local.clone(),
    )
    .await?;
    let resource_id = Uuid::new_v4();
    let bytes = b"controlled user MSI";
    let digest = rss_mdm_resource::Digest::of(bytes).bytes();
    let invocation = json!({"runAs":"logged_in_user","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let definition = json!({"source":f.source_snapshot,"package":"Private.UserInstall","version":"1","artifacts":{"package":{"reference":"user-msi","length":bytes.len(),"sha256":digest}},"reboot":"report","downgrade":"deny","dependencies":[],"behavior":{"kind":"msi","installer":"package","scope":"user","install":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{CCCCCCCC-DDDD-EEEE-FFFF-AAAAAAAAAAAA}","version":"1"},"upgradeInvocation":invocation},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}});
    let path = format!("/api/v1/resources/{resource_id}");
    crate::test_support::software::write(
        &mut f.author,
        &f.router,
        &path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    crate::test_support::software::write(&mut f.author,&f.router,&path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":"windows","architecture":"x86_64","key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
    software::upload_windows(&f.author, &f.router, resource_id, bytes).await?;
    crate::test_support::software::write(
        &mut f.author,
        &f.router,
        &path,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let approval = crate::test_support::software::write(
        &mut f.author,
        &f.router,
        &format!("/api/v1/software/resources/{resource_id}/versions/v1"),
        0,
        json!({"action":"approve","evidence":["user-profile"]}),
    )
    .await?;
    let mut definition = software::authored(
        resource_id,
        f.scope,
        "available_install",
        &approval["admission"]["operation"],
    );
    definition["action"]["resource"]["variants"] = json!({"windows_x86_64":"default"});
    definition["selfService"] = json!({"access":{"kind":"device"},"published":true,"displayName":"User installation","description":"","prerequisites":"","sideEffects":"Install for current OS account","category":"Apps","keywords":[]});
    let policy = Uuid::new_v4();
    let published = crate::test_support::software::write(
        &mut f.author,
        &f.router,
        &format!("/api/v1/policies/{policy}"),
        0,
        json!({"action":"put","enabled":true,"definition":definition}),
    )
    .await?;
    let poll = |context: Value| {
        agent_call(
            &f.router,
            Method::POST,
            "/api/v1/agent/runtime/tasks/claim",
            Some(&f.credential),
            Some(
                json!({"wireVersion":1,"executionContext":context,"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["power_shell7"],"operationId":Uuid::new_v4()}),
            ),
        )
    };
    ensure!(poll(local.clone()).await?.0 == StatusCode::OK);
    let accepted = software_self_service_call(
        &f.router,
        &f.credential,
        &f.author,
        Method::POST,
        INVOKE,
        Some(request(policy, &published, json!({}))),
    )
    .await?;
    ensure!(accepted.0 == StatusCode::ACCEPTED);
    let stack = software::worker(&f.base, f.content.clone()).await?;
    let task = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let response = poll(local.clone()).await?;
            ensure!(
                response.0 == StatusCode::OK,
                "user software claim: {response:?}"
            );
            if !response.1["task"].is_null() {
                return Ok::<_, anyhow::Error>(response.1["task"].clone());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    ensure!(
        task["payload"]["task"]["steps"][0]["target"]
            == json!({"kind":"user","identity":sid,"sessionId":session})
    );
    for event in [
        json!({"kind":"received"}),
        json!({"kind":"start"}),
        software::result_event(&task, "install", None, "unknown", false)?,
    ] {
        ensure!(
            software::event_with(&f.router, &f.credential, &task, event)
                .await?
                .0
                == StatusCode::OK
        );
    }
    local["revision"] = json!(2);
    local["interactiveUser"]["sessionId"] = json!(Uuid::new_v4());
    ensure!(poll(local.clone()).await?.0 == StatusCode::OK);
    let hidden = software_self_service_call(
        &f.router,
        &f.credential,
        &f.author,
        Method::GET,
        DIRECTORY,
        None,
    )
    .await?;
    ensure!(
        hidden.0 == StatusCode::OK && hidden.1["items"] == json!([]),
        "relogin cannot erase Unknown: {hidden:?}"
    );
    ensure!(
        software_self_service_call(
            &f.router,
            &f.credential,
            &f.author,
            Method::POST,
            INVOKE,
            Some(request(policy, &published, json!({})))
        )
        .await?
        .0 == StatusCode::CONFLICT
    );
    let old_state = software_self_service_call(
        &f.router,
        &f.credential,
        &f.author,
        Method::GET,
        &format!("{INVOKE}/{}", accepted.1["requestId"].as_str().unwrap()),
        None,
    )
    .await?;
    ensure!(old_state.0 == StatusCode::OK && old_state.1["state"]["execution"] == "unknown");
    local["revision"] = json!(3);
    local["interactiveUser"]["identity"] = json!("S-1-5-21-1-2-3-1002");
    ensure!(poll(local.clone()).await?.0 == StatusCode::OK);
    ensure!(
        software_self_service_call(
            &f.router,
            &f.credential,
            &f.author,
            Method::POST,
            INVOKE,
            Some(request(policy, &published, json!({})))
        )
        .await?
        .0 == StatusCode::ACCEPTED,
        "another OS account is a different installation effect"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
