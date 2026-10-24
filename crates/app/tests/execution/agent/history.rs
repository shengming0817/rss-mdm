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
        "INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,result,source_objects) SELECT tenant_id,gen_random_uuid(),policy_version,device,registration,generation,'history-fixture:'||n,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,result,source_objects FROM mdm_commands.action_runs CROSS JOIN generate_series(1,25) n WHERE id='{task}'"
    ))?;

    let result: Result<()> = async {
        let available_at = pg(&format!(
            "SELECT available_at FROM mdm_commands.action_runs WHERE id='{task}'"
        ))?
        .trim()
        .parse::<i64>()?;
        let mut path = format!("/api/v1/policies/{plan}/runs");
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
                "/api/v1/policies/{plan}/runs?afterAt={after_at}&afterId={after_id}"
            );
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
        // the projection and the committed execution generation.
        let projected = format!("/api/v1/operations?filter=kind==action_run;policy=={plan}&limit=1&fields=id,kind");
        let (status, page) = author.call(router, Method::GET, &projected, None).await?;
        ensure!(status == StatusCode::OK, "projected directory: {status} {page}");
        ensure!(page["items"][0].get("evidence").is_none());
        ensure!(page.get("statistics").is_none());
        let cursor = page["nextCursor"].as_str().context("projected cursor")?;
        let continuation = format!("{projected}&cursor={cursor}");
        let replay = continuation.replace("fields=id,kind", "fields=id,kind,status");
        ensure!(author.call(router, Method::GET, &replay, None).await?.0 == StatusCode::CONFLICT);
        let revision = pg("SELECT revision FROM mdm_commands.query_revisions WHERE tenant_id=current_setting('rss.tenant_id')::uuid")?;
        pg(&format!("SAVEPOINT reverted; UPDATE mdm_commands.action_runs SET result=jsonb_set(result,'{{effect}}','\"query-test\"') WHERE id='{task}'; ROLLBACK TO reverted"))?;
        ensure!(pg("SELECT revision FROM mdm_commands.query_revisions WHERE tenant_id=current_setting('rss.tenant_id')::uuid")? == revision, "rolled-back evidence changed directory generation");
        ensure!(author.call(router, Method::GET, &continuation, None).await?.0 == StatusCode::OK);
        pg(&format!("UPDATE mdm_commands.action_runs SET result=jsonb_set(result,'{{effect}}','\"query-test\"') WHERE id='{task}'"))?;
        ensure!(author.call(router, Method::GET, &continuation, None).await?.0 == StatusCode::CONFLICT, "committed evidence did not invalidate the cursor");
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
    let mut tx = f.authority.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
    ensure!(rss_mdm_inventory_postgres::publish_field_in(&mut tx, f.authority.identity.tenant, 0, &serde_json::from_value(field)?).await?);
    tx.commit().await?;
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
        let policy = publish(&mut f.author, &f.router, id).await?;
        let task_id = Uuid::new_v4();
        let mut tx = f.authority.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_tenant()).execute(&mut *tx).await?;
        let object = f.planning.objects.endpoint(&mut tx, f.authority.identity.tenant, case_device_id()).await?;
        tx.rollback().await?;
        let source_objects = serde_json::to_value(vec![object])?;
        let tenant = f.authority.identity.tenant;
        f.command_runtime.local_tx(tenant, crate::identity::deadline(), move |tx| Box::pin(async move {
            tx.with_connection(move |c| Box::pin(async move {
                let state = rss_mdm_execution_service::actions::state::RunState::new(300, 1).expect("valid run horizon");
                sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,source_objects) SELECT p.tenant_id,$2,p.current_version,r.device,r.id,r.generation,'retained-sensitive-result',1,1,300,$4,true,$5,$6 FROM mdm_policy.policies p JOIN mdm_access.registrations r ON r.tenant_id=p.tenant_id AND r.device=$3 AND r.channel='agent' AND r.state='active' WHERE p.tenant_id=$1::uuid AND p.id=$7")
                    .bind(tenant.to_string()).bind(task_id).bind(case_device_id()).bind(serde_json::to_value(state).expect("run state"))
                    .bind(vec![7u8;32]).bind(source_objects).bind(policy).execute(c).await?;
                Ok(())
            })).await
        })).await.fold(Ok, |e|Err(anyhow::anyhow!(e)), |e|Err(anyhow::anyhow!(e)), |_|Err(anyhow::anyhow!("seed rollback unconfirmed")), |_|Err(anyhow::anyhow!("seed commit unconfirmed")), |e|Err(anyhow::anyhow!(e)))?;
        seed_script_result(&f, task_id, "private-collection-canary").await?;
        let path = format!(
            "/api/v1/policies/{policy}/runs/{}",
            task_id
        );
        let denied = f.author.call(&f.router, Method::GET, &path, None).await?;
        ensure!(
            denied.0 == StatusCode::FORBIDDEN
                && !denied.1.to_string().contains("private-collection-canary"),
            "sensitive result leaked through Policy: {denied:?}"
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
        crate::test_support::identity::change_grants(case_tenant(), &f.author_id, f.grants.clone())
            .await?;
        let audit =
            rss_mdm_audit_integration::RequestAudit::new(case_tenant().into(), "command_read");
        let denied = f.queries.action_run(&stale, policy, task_id, &audit).await;
        ensure!(
            matches!(
                denied,
                Err(rss_mdm_execution_service::queries::QueryError::Forbidden)
            ),
            "stale sensitive grant survived withdrawal"
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
