use crate::test_support::agent_execution::*;
use crate::test_support::*;
use anyhow::Context;
use std::collections::BTreeSet;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.history"]
async fn policy_run_history_cursor_summary_and_detail() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.register().await?;
    let (resource, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let mut grants = fixture.grants.clone();
    grants.extend(crate::test_support::identity::device_grants(
        None,
        &["operation_read"],
    )?);
    crate::test_support::identity::set_grants(case_tenant(), &fixture.author_id, grants).await?;
    let stack = worker(&fixture.base).await?;
    let router = &fixture.router;
    let author = &mut fixture.author;
    let plan = publish(author, router, resource).await?;
    let completed = claim(router).await?;
    complete(router, &completed).await?;
    let task = pg(&format!(
        "SELECT id FROM mdm_commands.action_runs WHERE policy_version IN(SELECT id FROM mdm_policy.versions WHERE policy='{plan}') AND occurrence NOT LIKE 'history-fixture:%' ORDER BY created_at,id LIMIT 1"
    ))?
    .trim()
    .to_owned();
    Uuid::parse_str(&task)?;
    pg(&format!(
        "INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,result) SELECT tenant_id,gen_random_uuid(),policy_version,device,registration,generation,'history-fixture:'||n,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,result FROM mdm_commands.action_runs CROSS JOIN generate_series(1,25) n WHERE id='{task}'"
    ))?;

    let result: Result<()> = async {
        let available_at = pg(&format!(
            "SELECT available_at FROM mdm_commands.action_runs WHERE id='{task}'"
        ))?
        .trim()
        .parse::<i64>()?;
        let mut path = format!("/api/v2/policies/{plan}/runs");
        let mut ids = Vec::new();
        let mut unique = BTreeSet::new();
        loop {
            let (status, page) = author.call(router, Method::GET, &path, None).await?;
            ensure!(status == StatusCode::OK, "run history page: {status} {page}");
            let items = page["items"].as_array().context("run history items")?;
            ensure!(items.len() <= 20, "unbounded run history page: {page}");
            for item in items {
                ensure!(
                    item["availableAt"].as_i64() == Some(available_at),
                    "history fixture changed the shared ordering coordinate: {item}"
                );
                ensure!(
                    item["result"].get("output").is_none(),
                    "run summary exposed output: {item}"
                );
                ensure!(
                    item["result"]["diagnostics"].get("stdout").is_none()
                        && item["result"]["diagnostics"].get("stderr").is_none(),
                    "run summary exposed diagnostic streams: {item}"
                );
                let id = item["taskId"].as_str().context("history taskId")?.to_owned();
                ensure!(unique.insert(id.clone()), "duplicate run history item: {id}");
                ids.push(id);
            }
            let Some(cursor) = page["nextCursor"].as_object() else {
                ensure!(page["nextCursor"].is_null(), "invalid run cursor: {page}");
                break;
            };
            let after_at = cursor["availableAt"].as_i64().context("cursor availableAt")?;
            let after_id = cursor["taskId"].as_str().context("cursor taskId")?;
            path = format!(
                "/api/v2/policies/{plan}/runs?afterAt={after_at}&afterId={after_id}"
            );
        }
        ensure!(ids.len() == 26, "run history lost records: {ids:?}");
        let mut path=format!("/api/v3/operations?kind=action_run&policy={plan}&limit=3&descending=true");
        let mut directory_ids=Vec::new();
        loop {
            let (status,page)=author.call(router,Method::GET,&path,None).await?;
            ensure!(status==StatusCode::OK,"cross-device directory: {status} {page}");
            ensure!(page["statistics"]["total"]==26 && page["statistics"]["actionRuns"]==26);
            for item in page["items"].as_array().context("directory items")? {
                ensure!(item["evidence"]["result"].get("output").is_none());
                ensure!(item["evidence"]["result"]["diagnostics"].get("stdout").is_none());
                directory_ids.push(item["id"].as_str().context("directory id")?.to_owned());
            }
            let Some(cursor)=page["nextCursor"].as_object() else{break};
            path=format!("/api/v3/operations?kind=action_run&policy={plan}&limit=3&descending=true&after={}&afterKind={}",cursor["id"].as_str().unwrap(),cursor["kind"].as_str().unwrap());
            ensure!(directory_ids.len()<=26,"directory repeated pages");
        }
        ensure!(directory_ids.len()==26 && directory_ids.windows(2).all(|pair|pair[0]>pair[1]));
        let filtered=author.call(router,Method::GET,&format!("/api/v3/policies?action=execution&resource={resource}&limit=1"),None).await?;
        ensure!(filtered.0==StatusCode::OK && filtered.1["items"][0]["id"]==plan.to_string());
        let grants_without_read=fixture.grants.iter().filter(|g|g.operation!=crate::authorization::Permission::OperationRead).cloned().collect();
        crate::test_support::identity::set_grants(case_tenant(),&fixture.author_id,grants_without_read).await?;
        ensure!(author.call(router,Method::GET,&path,None).await?.0==StatusCode::FORBIDDEN);
        let mut restored=fixture.grants.clone();restored.extend(crate::test_support::identity::device_grants(None,&["operation_read"])?);
        crate::test_support::identity::set_grants(case_tenant(),&fixture.author_id,restored).await?;
        ensure!(
            ids.windows(2).all(|pair| pair[0] > pair[1]),
            "equal-time run history was not ordered by descending task id: {ids:?}"
        );

        let (status, detail) = author
            .call(
                router,
                Method::GET,
                &format!("/api/v2/policies/{plan}/runs/{task}"),
                None,
            )
            .await?;
        ensure!(status == StatusCode::OK, "run detail: {status} {detail}");
        ensure!(detail["result"]["output"]["version"] == "1.2", "run detail: {detail}");
        ensure!(
            detail["result"]["diagnostics"]["stdout"] == "captured stdout"
                && detail["result"]["diagnostics"]["stderr"] == "captured stderr",
            "run detail lost diagnostic streams: {detail}"
        );
        ensure!(
            author
                .call(
                    router,
                    Method::GET,
                    &format!("/api/v2/policies/{}/runs/{task}", Uuid::new_v4()),
                    None,
                )
                .await?
                .0
                == StatusCode::NOT_FOUND
        );
        ensure!(
            author
                .call(
                    router,
                    Method::GET,
                    &format!("/api/v2/policies/{plan}/runs?afterAt={available_at}"),
                    None,
                )
                .await?
                .0
                == StatusCode::BAD_REQUEST
        );

        let records=audit_records()?;
        let version=pg(&format!("SELECT policy_version FROM mdm_commands.action_runs WHERE id='{task}'"))?;
        let found=records.iter().find(|r|r.payload["plan"]==version.trim() && r.target()==task && r.action()=="command_accept").expect("task/policy-version audit coordinates");
        let registration=found.payload["registration"].as_str().expect("task registration");uuid::Uuid::parse_str(registration)?;
        ensure!(pg(&format!("SELECT device FROM mdm_access.registrations WHERE tenant_id='{TENANT}' AND id='{registration}'", TENANT = case_tenant()))?.trim()==case_device_id());
        Ok(())
    }
    .await;
    let cleanup = pg(&format!(
        "DELETE FROM mdm_commands.action_runs WHERE tenant_id='{}' AND device='{}' AND occurrence LIKE 'history-fixture:%'",
        case_tenant(),
        case_device_id()
    ));
    result?;
    cleanup?;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.history"]
async fn sensitive_collection_run_details_reauthorize_both_read_paths() -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    let mut f = Fixture::new().await?;
    f.register().await?;
    f.grants.push(Grant {
        operation: Permission::InventoryFieldsWrite,
        scope: Scope::Tenant,
    });
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
        .await?;
    let key = "custom.confidential_observation";
    let field = json!({"key":key,"version":1,"valueType":{"kind":"string","maxLength":128,"allowEmpty":false},"nullable":false,"manual":false,"sources":{"agent.script":100},"platforms":["macos"],"sensitivity":"sensitive","unit":null,"searchable":true,"itemKey":null});
    ensure!(f.author.call(&f.router,Method::PUT,&format!("/api/v2/asset-fields/{key}"),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","definition":field}}))).await?.0==StatusCode::OK);
    let id = Uuid::new_v4();
    let bytes = b"printf '{}'";
    let digest = rss_mdm_resource::Digest::of(bytes).bytes();
    let definition = json!({"profile":"posix_sh","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{"secret":{"type":"string"}},"required":["secret"],"additionalProperties":false},"purpose":{"kind":"collection","mappings":{key:"/secret"}},"timeoutSeconds":60,"outputBytes":4096,"maxRows":1});
    resource(
        &mut f.author,
        &f.router,
        id,
        0,
        json!({"action":"create","kind":"script"}),
    )
    .await?;
    resource(&mut f.author,&f.router,id,1,json!({"action":"version","version":"v1","kind":"script","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"script","artifact":{"reference":"sensitive-script","length":bytes.len(),"sha256":digest},"definition":definition}}]})).await?;
    ensure!(upload(&f.author, &f.router, id, bytes).await? == StatusCode::CREATED);
    resource(
        &mut f.author,
        &f.router,
        id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    let stack = worker(&f.base).await?;
    for remote in [false, true] {
        let parent = if remote {
            let parent = Uuid::new_v4();
            let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
            post(&mut f.author,&f.router,"/api/v3/remote-operations",json!({"operationId":parent,"resource":policy_definition(id,case_task_scope())["action"]["resource"],"targets":{"kind":"devices","devices":[case_device_id()]},"action":{"kind":"execute","parameters":{}},"deadline":now+600})).await?;
            parent
        } else {
            publish(&mut f.author, &f.router, id).await?
        };
        let task = claim(&f.router).await?;
        task_event(&f.router, &task, json!({"kind":"received"})).await?;
        task_event(&f.router, &task, json!({"kind":"start"})).await?;
        task_event(&f.router,&task,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"secret":"private-collection-canary"},"diagnostics":{"stdout":"private-collection-canary","stderr":"private-collection-canary","durationMs":1,"executedAt":1,"failure":null}})).await?;
        let route = if remote {
            "remote-operations"
        } else {
            "policies"
        };
        let version = if remote { 3 } else { 2 };
        let path = format!(
            "/api/v{version}/{route}/{parent}/runs/{}",
            task["payload"]["taskId"].as_str().unwrap()
        );
        let denied = f.author.call(&f.router, Method::GET, &path, None).await?;
        ensure!(
            denied.0 == StatusCode::FORBIDDEN
                && !denied.1.to_string().contains("private-collection-canary"),
            "sensitive result leaked through {route}: {denied:?}"
        );
        let mut granted = f.grants.clone();
        granted.push(Grant {
            operation: Permission::InventorySensitiveRead,
            scope: Scope::Tenant,
        });
        crate::test_support::identity::set_grants(case_tenant(), &f.author_id, granted).await?;
        let detail = f.author.call(&f.router, Method::GET, &path, None).await?;
        ensure!(
            detail.0 == StatusCode::OK
                && detail.1["result"]["output"]["secret"] == "private-collection-canary"
                && detail.1["result"]["diagnostics"]["stdout"] == "private-collection-canary"
        );
        // Keep the original loaded snapshot after withdrawal, then call the service directly.
        let stale = crate::device::test_support::admin(case_tenant(), "other-a").await?;
        ensure!(stale.manage(Permission::InventorySensitiveRead).is_ok());
        crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
            .await?;
        let audit =
            rss_mdm_audit_integration::RequestAudit::new(case_tenant().into(), "command_read");
        let task_id = Uuid::parse_str(task["payload"]["taskId"].as_str().unwrap())?;
        let denied = if remote {
            f.execution
                .queries()
                .remote_action_run(&stale, parent, task_id, &audit)
                .await
        } else {
            f.execution
                .queries()
                .action_run(&stale, parent, task_id, &audit)
                .await
        };
        ensure!(
            matches!(
                denied,
                Err(rss_mdm_execution_service::queries::QueryError::Forbidden)
            ),
            "stale sensitive grant survived withdrawal"
        );
    }
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.history"]
async fn device_capabilities_use_current_permissions_after_proof_capture() -> Result<()> {
    use crate::authorization::Permission;
    let mut f = Fixture::new().await?;
    f.register().await?;
    let stale = crate::device::test_support::admin(case_tenant(), "other-a").await?;
    ensure!(
        stale
            .require(Permission::ScriptExecute, Some(case_device_id()))
            .is_ok()
    );
    let queries = f.execution.queries();
    let initial = serde_json::to_value(
        queries
            .directory_capabilities(&stale, case_device_id(), true, true)
            .await?,
    )?;
    ensure!(initial[0]["permission"]["allowed"] == true);
    let withdrawn = f
        .grants
        .iter()
        .filter(|g| g.operation != Permission::ScriptExecute)
        .cloned()
        .collect();
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, withdrawn).await?;
    let current = serde_json::to_value(
        queries
            .directory_capabilities(&stale, case_device_id(), true, true)
            .await?,
    )?;
    ensure!(
        current[0]["permission"]["allowed"] == false
            && current[0]["permission"]["reason"] == "permission_denied",
        "stale action capability: {current}"
    );
    let withdrawn = f
        .grants
        .iter()
        .filter(|g| g.operation != Permission::InventoryRead)
        .cloned()
        .collect();
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, withdrawn).await?;
    ensure!(matches!(
        queries
            .directory_capabilities(&stale, case_device_id(), true, true)
            .await,
        Err(rss_mdm_execution_service::queries::QueryError::Forbidden)
    ));
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.history"]
async fn capability_product_support_requires_signer_and_content_independently() -> Result<()> {
    use rss_runtime::ManagedResource;
    let base: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    for (signed, content) in [(true, true), (true, false), (false, true), (false, false)] {
        let mut config = base.clone();
        if !signed {
            config["task_signing"] = Value::Null;
        }
        if !content {
            config["content"] = Value::Null;
        }
        let f = Fixture::from_config(config).await?;
        let proof = crate::device::test_support::admin(case_tenant(), "other-a").await?;
        let capabilities = serde_json::to_value(
            f.execution
                .queries()
                .directory_capabilities(&proof, case_device_id(), true, true)
                .await?,
        )?;
        let state = if signed && content {
            "supported"
        } else {
            "unsupported"
        };
        for capability in capabilities
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["channel"] == "agent")
        {
            ensure!(
                capability["productSupport"]["state"] == state,
                "incorrect configured support: signer={signed}, content={content}, {capability}"
            );
        }
        f.plan_runtime.close().await;
        rss_mdm_execution_service::Resource(f.execution)
            .shutdown()
            .await?;
    }
    Ok(())
}
