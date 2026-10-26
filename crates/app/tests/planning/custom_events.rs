//! Real HTTP acceptance, independent member settlement, replay and execution association.
use crate::planning::test_support::RunningAutomation;
use crate::test_support::agent_execution::*;
use crate::test_support::runtime::case_tenant;
use crate::test_support::*;

fn endpoint() -> String {
    format!("/api/v1/devices/{}/policy-events", case_device_id())
}
fn batch_path(batch: &Value) -> String {
    format!(
        "/api/v1/devices/{}/policy-event-batches/{}",
        case_device_id(),
        batch["batchId"].as_str().unwrap()
    )
}
async fn setup() -> Result<Fixture> {
    let mut f = Fixture::new().await?;
    let events = Arc::new(rss_mdm_flow_service::planning::events::Events {
        planning: f.planning.clone(),
        execution: f.execution.clone(),
    });
    f.router = f.router.clone().merge(f.authority.protect(
        rss_mdm_http_contract::Router::new().nest(
            "/api/v1",
            rss_mdm_management_http::policy_events::routes(events.clone()),
        ),
    )?);
    let tasks = Arc::new(rss_mdm_agent_channel::TaskState {
        access: Arc::new(rss_mdm_agent_channel::Store::from_pool(
            f.authority.pool.clone(),
        )),
        enrollment: f.enrollment.clone(),
        execution: f.execution.clone(),
        identity: Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(
                f.authority.identity.authority.clone(),
                f.authority.identity.tenant,
            ),
        ),
        authorization: f.authority.authorization.clone(),
    });
    let envelope = rss_mdm_agent_channel::boundary::Envelope {
        admission: Arc::new(tokio::sync::Semaphore::new(32)),
        requests: Arc::new(tokio::sync::Semaphore::new(32)),
        host: "mdm.example.test:9445".into(),
        clock: crate::test_support::runtime::monotonic(),
        audit_store: f.authority.audit.clone(),
        tenant: case_tenant().into(),
    };
    f.router = f.router.clone().merge(
        rss_mdm_http_contract::Router::new()
            .nest(
                "/api/v1/agent/runtime",
                rss_mdm_agent_channel::event_router(tasks, events, envelope),
            )
            .into_axum(),
    );
    f.register_profile(json!([
        "inventory.collect.v1",
        "inventory.native.v1",
        "task.execute.v1"
    ]))
    .await?;
    ensure!(claim_request(&f.router, Uuid::new_v4()).await?.0 == StatusCode::OK);
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    Ok(f)
}
async fn policy(f: &mut Fixture, resource: Uuid, event: &str, scope: Uuid) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let mut definition = policy_definition(resource, scope);
    definition["customEvent"] = json!(event);
    definition["action"]["frequency"] = json!("every_trigger");
    definition["action"]["schedule"] = json!({"trigger":{"kind":"manual"},"misfire":{"kind":"coalesce_one"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null});
    post(&mut f.author,&f.router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":definition}})).await?;
    Ok(id)
}
fn request(event: &str) -> Value {
    json!({"operationId":Uuid::new_v4(),"event":event,"source":{"kind":"human"},"executionContext":null})
}
async fn get(f: &mut Fixture, path: &str) -> Result<Value> {
    let (status, value) = f.author.call(&f.router, Method::GET, path, None).await?;
    ensure!(status == StatusCode::OK, "{status}: {value}");
    Ok(value)
}
async fn settled(f: &mut Fixture, batch: &Value) -> Result<Value> {
    let path = format!("{}/members", batch_path(batch));
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let value = get(f, &path).await?;
            if value["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|v| v["state"] != "pending")
            {
                return Ok::<_, anyhow::Error>(value);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.custom_events"]
async fn event_batches_freeze_members_replay_and_keep_independent_results() -> Result<()> {
    let mut f = setup().await?;
    let resources = std::mem::take(&mut f.resources);
    resources
        .finish(async {
            let empty = request("empty");
            let zero = post(&mut f.author, &f.router, &endpoint(), empty.clone()).await?;
            ensure!(zero["members"] == 0);
            ensure!(post(&mut f.author, &f.router, &endpoint(), empty).await? == zero);
            let (resource, _, _) = f.resource().await?;
            let first = policy(&mut f, resource, "refresh", case_task_scope()).await?;
            let second = policy(&mut f, resource, "refresh", case_empty_scope()).await?;
            let input = request("refresh");
            let batch = post(&mut f.author, &f.router, &endpoint(), input.clone()).await?;
            ensure!(batch["members"] == 2);
            let late = policy(&mut f, resource, "refresh", case_task_scope()).await?;
            ensure!(post(&mut f.author, &f.router, &endpoint(), input.clone()).await? == batch);
            let mut conflict = input.clone();
            conflict["event"] = json!("changed");
            ensure!(
                f.author
                    .call(&f.router, Method::POST, &endpoint(), Some(conflict))
                    .await?
                    .0
                    == StatusCode::CONFLICT
            );
            let worker = RunningAutomation::start_with_execution(
                f.planning.clone(),
                Some(f.execution.clone()),
            )
            .await;
            let results = settled(&mut f, &batch).await?;
            let items = results["items"].as_array().unwrap();
            ensure!(items.len() == 2);
            ensure!(
                items
                    .iter()
                    .any(|v| v["policyId"] == first.to_string() && v["state"] == "accepted")
            );
            ensure!(
                items
                    .iter()
                    .any(|v| v["policyId"] == second.to_string() && v["state"] == "rejected")
            );
            ensure!(!items.iter().any(|v| v["policyId"] == late.to_string()));
            let task = claim(&f.router).await?;
            ensure!(task["payload"]["task"]["authorization"]["policyId"] == first.to_string());
            complete(&f.router, &task).await?;
            let done = get(&mut f, &format!("{}/members", batch_path(&batch))).await?;
            ensure!(
                done["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v["operations"][0]["state"]["execution"] == "succeeded")
            );
            ensure!(post(&mut f.author, &f.router, &endpoint(), input).await? == batch);
            worker.stop().await;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.custom_events"]
async fn response_loss_concurrency_versions_and_pagination_keep_original_batch() -> Result<()> {
    let mut f = setup().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async{
        let(resource,_,_)=f.resource().await?;
        let first=policy(&mut f,resource,"versions",case_task_scope()).await?;
        let changed=policy(&mut f,resource,"versions",case_task_scope()).await?;
        let input=request("versions");
        f.plan_runtime.inject_next_transaction_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
        let response=f.author.call(&f.router,Method::POST,&endpoint(),Some(input.clone())).await?;
        ensure!(response.0==StatusCode::SERVICE_UNAVAILABLE);
        let mut a=f.author.clone();let mut b=f.author.clone();let path=endpoint();
        let (left,right)=tokio::join!(post(&mut a,&f.router,&path,input.clone()),post(&mut b,&f.router,&path,input.clone()));
        let batch=left?;ensure!(batch==right? && batch["members"]==2);
        for (id,name,lifetime) in [(first,"renamed",300),(changed,"versions",600)]{
            let mut view=get(&mut f,&format!("/api/v1/policies/{id}")).await?;
            view["definition"]["customEvent"]=json!(name);view["definition"]["action"]["runLifetimeSeconds"]=json!(lifetime);
            post(&mut f.author,&f.router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"put","enabled":true,"definition":view["definition"]}})).await?;
        }
        let worker=RunningAutomation::start_with_execution(f.planning.clone(),Some(f.execution.clone())).await;
        let all=settled(&mut f,&batch).await?;
        ensure!(all["items"].as_array().unwrap().iter().any(|v|v["policyId"]==first.to_string() && v["state"]=="accepted"));
        ensure!(all["items"].as_array().unwrap().iter().any(|v|v["policyId"]==changed.to_string() && v["decision"]["reason"]=="policy_changed"));
        let page=get(&mut f,&format!("{}/members?limit=1",batch_path(&batch))).await?;
        ensure!(page["items"].as_array().unwrap().len()==1);
        let cursor=page["nextCursor"].as_str().ok_or_else(||anyhow::anyhow!("missing continuation: {page}"))?;
        let next=get(&mut f,&format!("{}/members?limit=1&cursor={cursor}",batch_path(&batch))).await?;
        ensure!(next["items"].as_array().unwrap().len()==1 && next["items"][0]["id"]!=page["items"][0]["id"]);
        worker.stop().await;
        let resumed=RunningAutomation::start_with_execution(f.planning.clone(),Some(f.execution.clone())).await;
        ensure!(post(&mut f.author,&f.router,&endpoint(),input).await?==batch);
        ensure!(run_count(first)?.trim()=="1" && run_count(changed)?.trim()=="0");
        resumed.stop().await;Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.custom_events"]
async fn agent_events_use_device_scope_and_expired_members_never_create_work() -> Result<()> {
    use crate::test_support::agent::agent_call;
    let mut f = setup().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async{
        let(resource,_,_)=f.resource().await?;
        let visible=policy(&mut f,resource,"local",case_task_scope()).await?;
        let hidden=policy(&mut f,resource,"local",case_empty_scope()).await?;
        let mut input=request("local");input["executionContext"]=crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs);
        let path="/api/v1/agent/runtime/policy-events";
        ensure!(agent_call(&f.router,Method::POST,path,None,Some(input.clone())).await?.0!=StatusCode::ACCEPTED);
        let (status,batch)=agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(input.clone())).await?;
        ensure!(status==StatusCode::ACCEPTED,"{status}: {batch}");ensure!(batch["members"]==1);
        ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(input.clone())).await?.1==batch);
        let mut forged=input;forged["device"]=json!("another-device");
        ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(forged)).await?.0==StatusCode::BAD_REQUEST);
        let id=Uuid::parse_str(batch["batchId"].as_str().unwrap())?;
        crate::test_support::process::pg(&format!("UPDATE mdm_planning.event_batches SET created_at=floor(extract(epoch FROM clock_timestamp()))::bigint-120,deadline=floor(extract(epoch FROM clock_timestamp()))::bigint-60 WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?;
        let worker=RunningAutomation::start_with_execution(f.planning.clone(),Some(f.execution.clone())).await;
        let result=settled(&mut f,&batch).await?;
        ensure!(result["items"][0]["state"]=="expired");
        ensure!(run_count(visible)?.trim()=="0" && run_count(hidden)?.trim()=="0");
        worker.stop().await;Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=planning.custom_events"]
async fn early_native_agent_collection_reuses_run_clock_without_a_second_schedule() -> Result<()> {
    use crate::test_support::agent::agent_call;
    use rss_mdm_resource as r;
    use sha2::{Digest, Sha256};
    let mut f = setup().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async{
        let r::blueprints::Definition::AgentCollection{template}=r::blueprints::get("macos.agent.identity","1").unwrap().definition else{unreachable!()};
        let bytes=template.canonical();let digest:[u8;32]=Sha256::digest(&bytes).into();let resource_id=Uuid::new_v4();
        resource(&mut f.author,&f.router,resource_id,0,json!({"action":"create","kind":"agent_collection"})).await?;
        resource(&mut f.author,&f.router,resource_id,1,json!({"action":"version","version":"v1","kind":"agent_collection","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"agent_collection","artifact":{"reference":"native.json","length":bytes.len(),"sha256":digest},"definition":template}}]})).await?;
        ensure!(upload_for(&f.author,&f.router,resource_id,&bytes,"macos","aarch64").await?==StatusCode::CREATED);
        resource(&mut f.author,&f.router,resource_id,2,json!({"action":"activate","version":"v1"})).await?;
        let context=crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs);
        let claim_body=||json!({"wireVersion":1,"operationId":Uuid::new_v4(),"profiles":[],"executionContext":context,"environment":{"edition":null,"tools":{},"nativeEngines":{"macos.hardware":1}}});
        ensure!(agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(case_credential()),Some(claim_body())).await?.0==StatusCode::OK);
        let now:i64=crate::test_support::process::pg("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")?.trim().parse()?;
        let policy_id=Uuid::new_v4();
        post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy_id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"customEvent":"collect","scope":case_task_scope(),"action":{"kind":"agent_collection","resource":{"id":resource_id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"schedule":{"trigger":{"kind":"interval","anchor":now+120,"seconds":3600},"notBefore":0,"jitterSeconds":0,"misfire":{"kind":"coalesce_one"}},"runLifetimeSeconds":300}}}})).await?;
        let worker=RunningAutomation::start_with_execution(f.planning.clone(),Some(f.execution.clone())).await;
        let batch=post(&mut f.author,&f.router,&endpoint(),request("collect")).await?;
        let result=settled(&mut f,&batch).await?;ensure!(result["items"][0]["state"]=="accepted","{result}");
        let run_id=Uuid::parse_str(result["items"][0]["decision"]["operations"][0]["id"].as_str().unwrap())?;
        let task=tokio::time::timeout(Duration::from_secs(30),async{loop{let(status,value)=agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(case_credential()),Some(claim_body())).await?;ensure!(status==StatusCode::OK,"{value}");if !value["task"].is_null(){return Ok::<_,anyhow::Error>(value["task"].clone());}tokio::time::sleep(Duration::from_millis(25)).await;}}).await??;
        task_event(&f.router,&task,json!({"kind":"received"})).await?;
        task_event(&f.router,&task,json!({"kind":"start"})).await?;
        // Simulate an expired unknown read; a fresh read may proceed without treating it as a write fence.
        crate::test_support::process::pg(&format!("UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{{execution}}','\"unknown\"'),deadline=available_at+1 WHERE tenant_id='{}' AND id='{run_id}'",case_tenant()))?;
        let runtime=f.command_runtime.clone();let borrowed=runtime.clone();let execution=f.execution.clone();
        let result=borrowed.local_tx(f.planning.tenant,crate::identity::deadline(),|tx|Box::pin(async move{
            let run=rss_mdm_execution_service::actions::storage::load_run(tx,run_id).await.map_err(|e|sqlx::Error::Protocol(e.to_string()))?;
            let started=run.state.started_at.ok_or_else(||sqlx::Error::Protocol("missing start".into()))?;
            let reader=rss_mdm_policy_postgres::PolicyReader::bind(runtime.clone(),tx.tenant_id());
            let plan=rss_mdm_execution_service::actions::storage::load_source(&reader,tx,run.source).await.map_err(|e|sqlx::Error::Protocol(e.to_string()))?;
            let early=Uuid::new_v4();let due=Uuid::new_v4();
            for (at,id) in [(started+120,early),(started+3600,due)] {rss_mdm_execution_service::actions::production::accept_for_device(&execution,tx,&plan,&run.target,rss_mdm_execution_service::actions::production::AdmissionTrigger::Agent(Uuid::new_v4()),at,id).await.map_err(|e|sqlx::Error::Protocol(e.to_string()))?;}
            let tenant=tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move{let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=ANY($2)").bind(tenant).bind(vec![early,due]).fetch_all(c).await?;Ok(ids==vec![due])})).await
        })).await.fold(Ok,|e|Err(anyhow::anyhow!("{e:?}")),|e|Err(anyhow::anyhow!("{e:?}")),|e|Err(anyhow::anyhow!("{e:?}")),|e|Err(anyhow::anyhow!("{e:?}")),|e|Err(anyhow::anyhow!("{e:?}")))?;
        ensure!(result,"the old fixed anchor must not admit another collection");
        worker.stop().await;Ok(())
    }).await
}
