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
    value["selfService"] = json!({"published":true,"displayName":"Repair","description":"Repair the application","prerequisites":"Signed-in employee","sideEffects":"May restart the application","category":"Support","keywords":["repair"]});
    value
}
async fn publish_definition(f: &mut Fixture, value: Value) -> Result<(Uuid, Value)> {
    let id = Uuid::new_v4();
    let policy=post(&mut f.author,&f.router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":value}})).await?;
    Ok((id, policy))
}
fn request(id: Uuid, policy: &Value, parameters: Value) -> Value {
    json!({"operationId":Uuid::new_v4(),"policyId":id,"policyRevision":policy["revision"],"policyVersion":policy["versionId"],"source":"ai","confirmed":true,"parameters":parameters})
}
const INVOKE: &str = "/api/v1/agent/runtime/self-service/scripts/invocations";
const DIRECTORY: &str = "/api/v1/agent/runtime/self-service/scripts?source=ai";
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
    let directory = call(&f, Method::GET, DIRECTORY, None, true, true).await?;
    ensure!(
        directory.0 == StatusCode::OK && directory.1["items"].as_array().unwrap().len() == 1,
        "directory: {directory:?}"
    );
    ensure!(
        directory.1["items"][0]["selfService"]["allowAi"] == true
            && directory.1["items"][0]["selfService"]["riskLevel"] == 2
    );
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, false, true).await?.0 == StatusCode::UNAUTHORIZED
    );
    ensure!(
        call(&f, Method::GET, DIRECTORY, None, true, false).await?.0 == StatusCode::UNAUTHORIZED
    );
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
    ensure!(task["payload"]["taskId"] == accepted.1["runId"]);
    ensure!(task["payload"]["parameters"] == json!({"name":"Acme","path":"/Applications"}));
    ensure!(task["payload"]["arguments"] == json!(["Acme"]));
    ensure!(task["payload"]["environment"]["RSS_PARAM_PATH"] == "/Applications");
    ensure!(
        task["payload"]["authorization"]["requestId"] == input["operationId"]
            && task["payload"]["authorization"]["actor"]["principalId"] == f.author_id
            && task["payload"]["authorization"]["source"] == "ai"
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
            && status.1["attemptId"] == task["payload"]["attemptId"]
    );
    ensure!(
        status.1["result"]["quality"] == "complete"
            && status.1["result"]["collectedAt"] == 2
            && status.1["result"]["receivedAt"].as_i64().unwrap() > 2
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
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_attempts WHERE run='{}' AND permit IS NOT NULL",task["payload"]["taskId"].as_str().unwrap()))?.trim()=="0");
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.self_service"]
async fn grants_and_scope_are_rechecked_and_ai_switch_does_not_change_automation() -> Result<()> {
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
    let revoked = f
        .grants
        .iter()
        .filter(|g| g.operation != crate::authorization::Permission::ScriptExecute)
        .cloned()
        .collect();
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, revoked).await?;
    let mut start = json!({"kind":"start"});
    ensure!(
        task_event_request(&f.router, &task, Uuid::new_v4(), &mut start)
            .await?
            .0
            == StatusCode::FORBIDDEN,
        "frozen grant must track rule revocation"
    );
    ensure!(call(&f, Method::GET, DIRECTORY, None, true, true).await?.0 == StatusCode::FORBIDDEN);
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
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
    value["action"]["schedule"]=policy_definition(resource,case_task_scope())["action"].get("schedule").cloned().unwrap_or_else(||json!({"trigger":{"kind":"check_in","minimumSeconds":60},"misfire":{"kind":"coalesce_one"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null}));
    let (automatic, _) = publish_definition(&mut f, value).await?;
    let normal = claim(&f.router).await?;
    ensure!(
        normal["payload"]["authorization"]["kind"] == "policy"
            && normal["payload"]["authorization"]["policyId"] == automatic.to_string(),
        "allowAi must not disable automation"
    );
    complete(&f.router, &normal).await?;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
