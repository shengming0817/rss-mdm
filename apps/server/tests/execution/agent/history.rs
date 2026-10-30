use crate::audit_test_support::audit_records;
use crate::test_support::agent_execution::*;
use crate::test_support::{process::*, runtime::*, *};
use anyhow::Context;
use std::collections::BTreeSet;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.history"]
async fn policy_run_history_cursor_summary_and_detail() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    fixture.register().await?;
    claim_request(&fixture.router, Uuid::new_v4()).await?;
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
    crate::test_support::identity::seed_grants(case_tenant(), &fixture.author_id, grants).await?;
    let stack = crate::test_support::software_execution::worker(&fixture.base, fixture.execution.clone()).await?;
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
        "INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,result,source_objects,origin) SELECT tenant_id,gen_random_uuid(),policy_version,device,registration,generation,'history-fixture:'||n,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,result,source_objects,origin FROM mdm_commands.action_runs CROSS JOIN generate_series(1,25) n WHERE id='{task}'"
    ))?;

    let result: Result<()> = async {
        let available_at = pg(&format!(
            "SELECT available_at FROM mdm_commands.action_runs WHERE id='{task}'"
        ))?
        .trim()
        .parse::<i64>()?;
        let (status, default_page) = author.call(router, Method::GET, &format!("/api/v1/policies/{plan}/runs"), None).await?;
        ensure!(status == StatusCode::OK && default_page["items"].as_array().unwrap().len() == 26 && default_page["nextCursor"].is_null());
        for invalid in ["limit=1001", "afterAt=0", "afterId=invalid"] {
            ensure!(author.call(router, Method::GET, &format!("/api/v1/policies/{plan}/runs?{invalid}"), None).await?.0 == StatusCode::BAD_REQUEST);
        }
        let mut path = format!("/api/v1/policies/{plan}/runs?limit=20");
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
            let Some(cursor) = page["nextCursor"].as_str() else {
                ensure!(page["nextCursor"].is_null(), "invalid run cursor: {page}");
                break;
            };
            path = format!("/api/v1/policies/{plan}/runs?limit=20&cursor={cursor}");
        }
        ensure!(ids.len() == 26, "run history lost records: {ids:?}");
        let mut path=format!("/api/v1/operations?filter=kind==action_run;policy=={plan}&limit=3&sort=-id,-kind");
        let mut directory_ids=Vec::new();
        loop {
            let (status,page)=author.call(router,Method::GET,&path,None).await?;
            ensure!(status==StatusCode::OK,"cross-device directory: {status} {page}");
            let(_,statistics)=author.call(router,Method::GET,&format!("/api/v1/operations/statistics?filter=kind==action_run;policy=={plan}"),None).await?;
            ensure!(statistics["statistics"]["total"]==26 && statistics["statistics"]["actionRuns"]==26);
            for item in page["items"].as_array().context("directory items")? {
                ensure!(item["evidence"]["result"].get("output").is_none());
                ensure!(item["evidence"]["result"]["diagnostics"].get("stdout").is_none());
                directory_ids.push(item["id"].as_str().context("directory id")?.to_owned());
            }
            let Some(cursor)=page["nextCursor"].as_str() else{break};
            path=format!("/api/v1/operations?filter=kind==action_run;policy=={plan}&limit=3&sort=-id,-kind&cursor={cursor}");
            ensure!(directory_ids.len()<=26,"directory repeated pages");
        }
        ensure!(directory_ids.len()==26 && directory_ids.windows(2).all(|pair|pair[0]>pair[1]));
        // A projected page never needs the large run result; its cursor still binds
        // the projection and current authorization.
        let projected = format!("/api/v1/operations?filter=kind==action_run;policy=={plan}&limit=1&fields=id,kind");
        let (status, page) = author.call(router, Method::GET, &projected, None).await?;
        ensure!(status == StatusCode::OK, "projected directory: {status} {page}");
        ensure!(page["items"][0].get("evidence").is_none());
        ensure!(page.get("statistics").is_none());
        let cursor = page["nextCursor"].as_str().context("projected cursor")?;
        let continuation = format!("{projected}&cursor={cursor}");
        let replay = continuation.replace("fields=id,kind", "fields=id,kind,status");
        ensure!(author.call(router, Method::GET, &replay, None).await?.0 == StatusCode::CONFLICT);
        let evidence = pg(&format!("SELECT result::text FROM mdm_commands.action_runs WHERE id='{task}'"))?;
        pg(&format!("SAVEPOINT reverted; UPDATE mdm_commands.action_runs SET result=jsonb_set(result,'{{receivedAt}}',to_jsonb((result->>'receivedAt')::bigint+1)) WHERE id='{task}'; ROLLBACK TO reverted"))?;
        ensure!(pg(&format!("SELECT result::text FROM mdm_commands.action_runs WHERE id='{task}'"))? == evidence, "rolled-back evidence changed persisted facts");
        ensure!(author.call(router, Method::GET, &continuation, None).await?.0 == StatusCode::OK);
        pg(&format!("UPDATE mdm_commands.action_runs SET result=jsonb_set(result,'{{receivedAt}}',to_jsonb((result->>'receivedAt')::bigint+1)) WHERE id='{task}'"))?;
        ensure!(author.call(router, Method::GET, &continuation, None).await?.0 == StatusCode::OK, "committed evidence invalidated live continuation");
        let filtered=author.call(router,Method::GET,&format!("/api/v1/policies?filter=action==execution;resource=={resource}&limit=1"),None).await?;
        ensure!(filtered.0==StatusCode::OK && filtered.1["items"][0]["id"]==plan.to_string());
        let grants_without_read=fixture.grants.iter().filter(|g|g.operation!=crate::authorization::Permission::OperationRead).cloned().collect();
        crate::test_support::identity::change_grants(case_tenant(),&fixture.author_id,grants_without_read).await?;
        ensure!(author.call(router,Method::GET,&path,None).await?.0==StatusCode::FORBIDDEN);
        let mut restored=fixture.grants.clone();restored.extend(crate::test_support::identity::device_grants(None,&["operation_read"])?);
        crate::test_support::identity::change_grants(case_tenant(),&fixture.author_id,restored).await?;
        ensure!(
            ids.windows(2).all(|pair| pair[0] > pair[1]),
            "equal-time run history was not ordered by descending task id: {ids:?}"
        );

        let (status, detail) = author
            .call(
                router,
                Method::GET,
                &format!("/api/v1/policies/{plan}/runs/{task}"),
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
                    &format!("/api/v1/policies/{}/runs/{task}", Uuid::new_v4()),
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
                    &format!("/api/v1/policies/{plan}/runs?afterAt={available_at}"),
                    None,
                )
                .await?
                .0
                == StatusCode::BAD_REQUEST
        );

        let records=audit_records().await?;
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
    crate::test_support::runtime::stop_worker(stack).await?;
    Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.history"]
async fn sensitive_collection_run_details_reauthorize_both_read_paths() -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
    f.register().await?;
    claim_request(&f.router, Uuid::new_v4()).await?;
    let key = "custom.confidential_observation";
    let field = json!({"key":key,"version":1,"valueType":{"kind":"string","maxLength":128,"allowEmpty":false},"nullable":false,"manual":false,"sources":{"agent.script":100},"platforms":["macos"],"sensitivity":"sensitive","unit":null,"searchable":true,"itemKey":null});
    let tenant = f.planning.tenant;
    let field = serde_json::from_value(field)?;
    let inserted = f.planning.inventory.runtime.local_tx(tenant, crate::identity::deadline(), move |tx| Box::pin(async move {
        tx.with_connection(move |connection| Box::pin(async move { rss_mdm_inventory_postgres::publish_field_in(connection, tenant, 0, &field).await.map_err(|e| sqlx::Error::Protocol(e.to_string())) })).await
    })).await.fold(Ok, Err, Err, Err, Err, Err)?;
    ensure!(inserted);
    let id = Uuid::new_v4();
    let bytes = b"printf '{}'";
    let definition = json!({"profile":"posix_sh","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{"secret":{"type":"string"}},"required":["secret"],"additionalProperties":false},"purpose":{"kind":"collection","scope":{"kind":"device"},"applicability":{"minimumOsVersion":null,"minimumBuild":null,"editions":[],"enrollments":[],"tools":{},"capabilities":[]},"mappings":{key:{"pointer":"/secret","conversion":{"kind":"identity"},"columns":{}}}},"timeoutSeconds":60,"outputBytes":4096,"maxRows":1});
    f.seed_script_resource(id, bytes, definition).await?;
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    {
        let policy = seed_script_policy(&f, id).await?;
        let task_id = seed_script_run(&f, policy).await?;
        seed_script_result(&f, task_id, json!({"secret":"private-collection-canary"}), "private-collection-canary").await?;
        let path = format!(
            "/api/v1/policies/{policy}/runs/{}",
            task_id
        );
        let denied = f.author.call(&f.router, Method::GET, &path, None).await?;
        ensure!(
            denied.0 == StatusCode::OK
                && denied.1.to_string().contains("private-collection-canary"),
            "Sensitive classification added a permission requirement: {denied:?}"
        );
        let mut granted = f.grants.clone();
        granted.push(Grant {
            operation: Permission::InventorySensitiveRead,
            scope: Scope::Tenant,
        });
        crate::test_support::identity::change_grants(case_tenant(), &f.author_id, granted).await?;
        let detail = f.author.call(&f.router, Method::GET, &path, None).await?;
        ensure!(
            detail.0 == StatusCode::OK
                && detail.1["result"]["output"]["secret"] == "private-collection-canary"
                && detail.1["result"]["diagnostics"]["stdout"] == "private-collection-canary"
        );
        // Keep the original loaded snapshot after withdrawal, then call the service directly.
        let stale = crate::device::test_support::admin(case_tenant(), "other-a").await?;
        ensure!(stale.manage(Permission::InventorySensitiveRead).is_ok());
        crate::test_support::identity::change_grants(case_tenant(), &f.author_id, f.grants.iter().filter(|g|g.operation != Permission::InventoryRead).cloned().collect())
            .await?;
        let audit =
            rss_mdm_audit_integration::RequestAudit::new(case_tenant().into(), "command_read", rss_mdm_audit_integration::AuditIntent::Routine);
        let denied = f.queries.action_run(&stale, policy, task_id, &audit).await;
        ensure!(
            matches!(
                denied,
                Err(rss_mdm_execution_service::queries::QueryError::Forbidden)
            ),
            "stale inventory grant survived withdrawal"
        );
    }
    Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.history"]
async fn device_capabilities_use_current_permissions_after_proof_capture() -> Result<()> {
    use crate::authorization::Permission;
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources
        .finish(async {
            f.register().await?;
            claim_request(&f.router, Uuid::new_v4()).await?;
            let stale = crate::device::test_support::admin(case_tenant(), "other-a").await?;
            ensure!(
                stale
                    .require(Permission::ScriptExecute, Some(case_device_id()))
                    .is_ok()
            );
            let queries = f.queries.clone();
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
            crate::test_support::identity::change_grants(case_tenant(), &f.author_id, withdrawn)
                .await?;
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
            crate::test_support::identity::change_grants(case_tenant(), &f.author_id, withdrawn)
                .await?;
            ensure!(matches!(
                queries
                    .directory_capabilities(&stale, case_device_id(), true, true)
                    .await,
                Err(rss_mdm_execution_service::queries::QueryError::Forbidden)
            ));
            crate::test_support::identity::change_grants(
                case_tenant(),
                &f.author_id,
                f.grants.clone(),
            )
            .await?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.history"]
async fn device_activities_preserve_stages_and_incremental_snapshot() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources
        .finish(async {
            use crate::test_support::agent::agent_call;
            use rss_mdm_agent_wire::activities::{
                ActivityExecution, ActivityPhase as Phase, ActivityReporting,
            };
            let path = "/api/v1/agent/runtime/management-activities";
            fixture.register().await?;
            ensure!(
                agent_call(&fixture.router, Method::GET, path, None, None)
                    .await?
                    .0
                    == StatusCode::UNAUTHORIZED
            );
            for query in [
                "limit=201",
                "limit=0",
                "unknown=1",
                "from=-1",
                "from=20&until=10",
            ] {
                ensure!(
                    agent_call(
                        &fixture.router,
                        Method::GET,
                        &format!("{path}?{query}"),
                        Some(case_credential()),
                        None
                    )
                    .await?
                    .0 == StatusCode::BAD_REQUEST
                );
            }
            claim_request(&fixture.router, Uuid::new_v4()).await?;
            let (resource, _, _) = fixture.resource().await?;
            fixture
                .scope(
                    case_task_scope(),
                    json!([{"kind":"device","id":case_device_id()}]),
                )
                .await?;
            let stack = crate::test_support::software_execution::worker(
                &fixture.base,
                fixture.execution.clone(),
            )
            .await?;
            let outcome: Result<()> = async {
                let policy = publish(&mut fixture.author, &fixture.router, resource).await?;
                let task = claim(&fixture.router).await?;
                let task_id = task["payload"]["task"]["taskId"].clone();
                let mut ready = false;
                for _ in 0..32 {
                    let (status, value) = agent_call(
                        &fixture.router,
                        Method::GET,
                        &format!("{path}?task={}&limit=200", task_id.as_str().unwrap()),
                        Some(case_credential()),
                        None,
                    )
                    .await?;
                    ensure!(
                        status == StatusCode::OK,
                        "activity catch-up {status} {value}"
                    );
                    let phases = value["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter_map(|v| v["phase"].as_str())
                        .collect::<BTreeSet<_>>();
                    if phases.contains("accepted") && phases.contains("offered") {
                        ready = true;
                        break;
                    }
                }
                ensure!(ready, "accepted/offered source stages absent");
                let (status, first) = agent_call(
                    &fixture.router,
                    Method::GET,
                    &format!("{path}?limit=1"),
                    Some(case_credential()),
                    None,
                )
                .await?;
                ensure!(status == StatusCode::OK, "activity list {status} {first}");
                let first: rss_mdm_agent_wire::activities::ManagementActivityPage =
                    serde_json::from_value(first)?;
                let snapshot = first.as_of;
                let mut ids = BTreeSet::new();
                let mut before = BTreeSet::new();
                let mut continued = false;
                let mut page = first;
                let sync = page.sync_cursor.clone();
                // New receipt facts must not leak into the already frozen history snapshot.
                complete(&fixture.router, &task).await?;
                loop {
                    ensure!(page.as_of == snapshot && page.items.len() <= 1);
                    for item in &page.items {
                        ensure!(ids.insert(item.id.clone()), "duplicate history activity");
                        if item.links.task.map(|id| json!(id)) == Some(task_id.clone()) {
                            before.insert(item.phase);
                        }
                        ensure!(
                            item.phase != Phase::Result,
                            "post-snapshot result leaked into history"
                        );
                    }
                    let Some(cursor) = page.next_cursor else {
                        break;
                    };
                    continued = true;
                    let (status, value) = agent_call(
                        &fixture.router,
                        Method::GET,
                        &format!("{path}?limit=1&cursor={cursor}"),
                        Some(case_credential()),
                        None,
                    )
                    .await?;
                    ensure!(
                        status == StatusCode::OK,
                        "history continuation {status} {value}"
                    );
                    page = serde_json::from_value(value)?;
                }
                ensure!(
                    continued
                        && before.contains(&Phase::Accepted)
                        && before.contains(&Phase::Offered),
                    "history skipped required stages or continuation"
                );
                let mut after = BTreeSet::new();
                let mut cursor = sync;
                let mut seen = BTreeSet::new();
                let mut result_id = None;
                for _ in 0..64 {
                    let (status, value) = agent_call(
                        &fixture.router,
                        Method::GET,
                        &format!("{path}/changes?limit=2&cursor={cursor}"),
                        Some(case_credential()),
                        None,
                    )
                    .await?;
                    ensure!(status == StatusCode::OK, "changes {status} {value}");
                    let encoded = value.to_string();
                    for forbidden in [
                        "captured stdout",
                        "captured stderr",
                        "principal",
                        "osIdentity",
                        "privateKey",
                        "parameters",
                    ] {
                        ensure!(!encoded.contains(forbidden), "activity leaked {forbidden}");
                    }
                    let changes: rss_mdm_agent_wire::activities::ManagementActivityPage =
                        serde_json::from_value(value)?;
                    for item in &changes.items {
                        if item.links.task.map(|id| json!(id)) == Some(task_id.clone()) {
                            after.insert(item.phase);
                            if item.phase == Phase::Started {
                                ensure!(item.execution == Some(ActivityExecution::Running));
                            }
                        }
                        ensure!(seen.insert(item.id.clone()), "incremental fact repeated");
                        if item.links.task.map(|id| json!(id)) == Some(task_id.clone())
                            && item.phase == Phase::Result
                        {
                            ensure!(
                                item.links.policy.map(|id| id.to_string())
                                    == Some(policy.to_string())
                            );
                            ensure!(item.reporting == Some(ActivityReporting::Acknowledged));
                            result_id = Some(item.id.clone());
                        }
                    }
                    let more = changes.next_cursor.is_some();
                    cursor = changes.next_cursor.unwrap_or(changes.sync_cursor);
                    if !more && result_id.is_some() {
                        break;
                    }
                }
                ensure!(
                    [Phase::Received, Phase::Started, Phase::Result]
                        .into_iter()
                        .all(|p| after.contains(&p)),
                    "incremental history skipped required stages"
                );
                let id = result_id.context("completed task missing from incremental activities")?;
                let (status, detail) = agent_call(
                    &fixture.router,
                    Method::GET,
                    &format!("{path}/{id}"),
                    Some(case_credential()),
                    None,
                )
                .await?;
                ensure!(
                    status == StatusCode::OK
                        && detail["activity"]["id"] == id
                        && detail["personal"] == false,
                    "detail {status} {detail}"
                );
                ensure!(
                    agent_call(
                        &fixture.router,
                        Method::GET,
                        &format!("{path}/{id}?view=personal"),
                        Some(case_credential()),
                        None
                    )
                    .await?
                    .0 == StatusCode::FORBIDDEN
                );
                ensure!(
                    agent_call(
                        &fixture.router,
                        Method::GET,
                        &format!("{path}/changes?policy={}&cursor={cursor}", Uuid::new_v4()),
                        Some(case_credential()),
                        None
                    )
                    .await?
                    .0 == StatusCode::CONFLICT
                );
                ensure!(
                    agent_call(
                        &fixture.router,
                        Method::GET,
                        &format!("{path}?cursor={cursor}"),
                        Some(case_credential()),
                        None
                    )
                    .await?
                    .0 == StatusCode::CONFLICT
                );
                ensure!(
                    agent_call(
                        &fixture.router,
                        Method::GET,
                        &format!("{path}/mdm.business:missing"),
                        Some(case_credential()),
                        None
                    )
                    .await?
                    .0 == StatusCode::NOT_FOUND
                );
                Ok(())
            }
            .await;
            crate::test_support::runtime::stop_worker(stack).await?;
            outcome
        })
        .await
}
