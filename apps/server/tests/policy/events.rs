//! Real HTTP acceptance, independent member settlement, replay and execution association.
use crate::planning::test_support::RunningAutomation;
use crate::test_support::agent_execution::*;
use crate::test_support::process::pg;
use crate::test_support::runtime::case_tenant;
use crate::test_support::*;

pub(super) fn endpoint() -> String {
    format!("/api/v1/devices/{}/policy-events", case_device_id())
}
pub(super) fn batch_path(batch: &Value) -> String {
    format!(
        "/api/v1/devices/{}/policy-event-batches/{}",
        case_device_id(),
        batch["batchId"].as_str().unwrap()
    )
}
pub(super) async fn setup() -> Result<Fixture> {
    let mut f = Fixture::new().await?;
    let events = f.events.clone();
    f.router = f.router.clone().merge(f.authority.protect(
        {
 rss_mdm_http_contract::route_module! { struct SetupModule1 for [Browser] { api_v1 at "/api/v1" } }
 SetupModule1 { api_v1: rss_mdm_management_http::policy_events::routes(events.clone()) }.assemble()
},
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
        f.resources.native_router(
            {
 rss_mdm_http_contract::route_module! { struct SetupModule2 for [Browser] { api_v1_agent_runtime at "/api/v1/agent/runtime" } }
 SetupModule2 { api_v1_agent_runtime: rss_mdm_agent_channel::event_router(tasks, events, envelope) }.assemble()
}
                .into_axum(),
        ),
    );
    f.register_profile(json!([
        "inventory.collect.v1",
        "task.execute.v1",
        "device.unmanage.v1",
        "inventory.native.v1"
    ]))
    .await?;
    ensure!(claim_request(&f.router, Uuid::new_v4()).await?.0 == StatusCode::OK);
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    f.scope(case_empty_scope(), json!([])).await?;
    f.grants.push(crate::authorization::Grant {
        operation: crate::authorization::Permission::InventoryCollect,
        scope: crate::authorization::Scope::AllDevices,
    });
    f.grants.push(crate::authorization::Grant {
        operation: crate::authorization::Permission::InventorySensitiveRead,
        scope: crate::authorization::Scope::Tenant,
    });
    crate::test_support::identity::seed_grants(case_tenant(), &f.author_id, f.grants.clone())
        .await?;
    Ok(f)
}
pub(super) async fn policy(
    f: &mut Fixture,
    resource: Uuid,
    event: &str,
    scope: Uuid,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let mut definition = policy_definition(resource, scope);
    definition["customEvent"] = json!(event);
    definition["action"]["frequency"] = json!("every_trigger");
    definition["action"]["schedule"] = json!({"trigger":{"kind":"manual"},"misfire":{"kind":"coalesce_one"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null});
    let written = post(&mut f.author,&f.router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":definition}})).await?;
    ensure!(
        written["definition"]["customEvent"] == event,
        "Policy write lost the admitted custom event: {written}"
    );
    Ok(id)
}
pub(super) fn request(event: &str) -> Value {
    json!({"operationId":Uuid::new_v4(),"event":event,"source":{"kind":"human"},"executionContext":null})
}
pub(super) async fn get(f: &mut Fixture, path: &str) -> Result<Value> {
    let (status, value) = f.author.call(&f.router, Method::GET, path, None).await?;
    ensure!(status == StatusCode::OK, "{status}: {value}");
    Ok(value)
}
pub(super) async fn settled(f: &mut Fixture, batch: &Value) -> Result<Value> {
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
#[ignore = "make t2 MODULE=policy.events"]
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
            let worker = RunningAutomation::start_with_events(
                f.planning.clone(),
                Some(f.events.clone()),
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
            let dispatcher =
                crate::test_support::software_execution::worker(&f.base, f.execution.clone())
                    .await?;
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
            let activity_path = "/api/v1/agent/runtime/management-activities";
            let mut root = None;
            for _ in 0..32 {
                let (status, page) = crate::test_support::agent::agent_call(
                    &f.router,
                    Method::GET,
                    &format!(
                        "{activity_path}?batch={}&limit=200",
                        batch["batchId"].as_str().unwrap()
                    ),
                    Some(case_credential()),
                    None,
                )
                .await?;
                ensure!(status == StatusCode::OK, "batch activities {status} {page}");
                let rows = page["items"].as_array().unwrap();
                if rows.iter().any(|v| v["decision"] == "accepted")
                    && rows.iter().any(|v| v["decision"] == "rejected")
                {
                    root = rows
                        .iter()
                        .find(|v| v["phase"] == "accepted" && v["kind"] == "batch")
                        .map(|v| v["id"].as_str().unwrap().to_owned());
                    break;
                }
            }
            let root = root.ok_or_else(|| {
                anyhow::anyhow!("batch/member decisions missing from activity history")
            })?;
            let (status, detail) = crate::test_support::agent::agent_call(
                &f.router,
                Method::GET,
                &format!("{activity_path}/{root}"),
                Some(case_credential()),
                None,
            )
            .await?;
            ensure!(status == StatusCode::OK, "batch detail {status} {detail}");
            let execution = detail["related"].as_array().unwrap().iter().filter(|v|v["links"]["task"]==task["payload"]["task"]["taskId"]).collect::<Vec<_>>();
            ensure!(execution.iter().all(|v|v["origin"]=="human"),"human event lost its origin: {execution:?}");
            ensure!(execution.iter().filter(|v|v["phase"]=="accepted").count()==1,"expected one execution acceptance: {execution:?}");
            for phase in ["accepted","offered","received","started","result"] {ensure!(execution.iter().any(|v|v["phase"]==phase),"missing {phase}");}
            let child = detail["related"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| {
                    v["phase"] == "result"
                        && v["links"]["task"] == task["payload"]["task"]["taskId"]
                })
                .ok_or_else(|| {
                    anyhow::anyhow!("batch detail lacks exact child result: {detail}")
                })?;
            let (status, reverse) = crate::test_support::agent::agent_call(
                &f.router,
                Method::GET,
                &format!("{activity_path}/{}", child["id"].as_str().unwrap()),
                Some(case_credential()),
                None,
            )
            .await?;
            ensure!(
                status == StatusCode::OK
                    && reverse["related"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|v| v["links"]["batch"] == batch["batchId"]
                            && v["decision"] == "accepted"),
                "child lost exact batch parent: {reverse}"
            );
            ensure!(post(&mut f.author, &f.router, &endpoint(), input).await? == batch);
            let ai_policy=Uuid::new_v4();
            let mut ai_definition=policy_definition(resource,case_task_scope());
            ai_definition["customEvent"]=json!("origin-ai");
            ai_definition["action"]["schedule"]=json!({"trigger":{"kind":"manual"},"misfire":{"kind":"coalesce_one"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null});
            ai_definition["selfService"]=json!({"access":{"kind":"device"},"published":false,"presentation":{"displayName":"AI origin","description":"","prerequisites":"","sideEffects":"","category":"Support","keywords":[]},"allowAi":true,"riskLevel":1});
            post(&mut f.author,&f.router,&format!("/api/v1/policies/{ai_policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":ai_definition}})).await?;
            let mut ai_input=request("origin-ai");ai_input["source"]=json!({"kind":"ai"});
            let ai_batch=post(&mut f.author,&f.router,&endpoint(),ai_input).await?;
            let ai_members=settled(&mut f,&ai_batch).await?;
            ensure!(ai_members["items"][0]["state"]=="accepted","{ai_members}");
            let ai_task=claim(&f.router).await?;complete(&f.router,&ai_task).await?;
            let mut ai_page=Value::Null;
            for _ in 0..32 {
                let(status,page)=crate::test_support::agent::agent_call(&f.router,Method::GET,&format!("{activity_path}?task={}&limit=200",ai_task["payload"]["task"]["taskId"].as_str().unwrap()),Some(case_credential()),None).await?;
                ensure!(status==StatusCode::OK,"{page}");ai_page=page;
                if ai_page["items"].as_array().unwrap().iter().any(|v|v["phase"]=="result"){break;}
            }
            let ai_facts=ai_page["items"].as_array().unwrap();
            ensure!(ai_facts.iter().all(|v|v["origin"]=="ai") && ai_facts.iter().filter(|v|v["phase"]=="accepted").count()==1,"{ai_page}");
            for phase in ["accepted","offered","received","started","result"] {ensure!(ai_facts.iter().any(|v|v["phase"]==phase),"AI child missing {phase}: {ai_page}");}
            worker.stop().await;
            crate::test_support::runtime::stop_worker(dispatcher).await?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=policy.events"]
async fn response_loss_concurrency_versions_and_pagination_keep_original_batch() -> Result<()> {
    let mut f = setup().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async{
        let(resource,_,_)=f.resource().await?;
        let first=policy(&mut f,resource,"versions",case_task_scope()).await?;
        let changed=policy(&mut f,resource,"versions",case_task_scope()).await?;
        let input=request("versions");
        f.planning.policy.runtime.inject_next_transaction_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
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
        let worker=RunningAutomation::start_with_events(f.planning.clone(),Some(f.events.clone())).await;
        let all=settled(&mut f,&batch).await?;
        ensure!(all["items"].as_array().unwrap().iter().any(|v|v["policyId"]==first.to_string() && v["state"]=="accepted"));
        ensure!(all["items"].as_array().unwrap().iter().any(|v|v["policyId"]==changed.to_string() && v["decision"]["reason"]=="policy_changed"));
        let page=get(&mut f,&format!("{}/members?limit=1",batch_path(&batch))).await?;
        ensure!(page["items"].as_array().unwrap().len()==1);
        let cursor=page["nextCursor"].as_str().ok_or_else(||anyhow::anyhow!("missing continuation: {page}"))?;
        let next=get(&mut f,&format!("{}/members?limit=1&cursor={cursor}",batch_path(&batch))).await?;
        ensure!(next["items"].as_array().unwrap().len()==1 && next["items"][0]["id"]!=page["items"][0]["id"]);
        worker.stop().await;
        let resumed=RunningAutomation::start_with_events(f.planning.clone(),Some(f.events.clone())).await;
        ensure!(post(&mut f.author,&f.router,&endpoint(),input).await?==batch);
        ensure!(run_count(first)?.trim()=="1" && run_count(changed)?.trim()=="0");
        resumed.stop().await;Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=policy.events"]
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
        crate::test_support::process::pg(&format!("UPDATE mdm_policy.event_batches SET created_at=floor(extract(epoch FROM clock_timestamp()))::bigint-120,deadline=floor(extract(epoch FROM clock_timestamp()))::bigint-60 WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?;
        let worker=RunningAutomation::start_with_events(f.planning.clone(),Some(f.events.clone())).await;
        let result=settled(&mut f,&batch).await?;
        ensure!(result["items"][0]["state"]=="expired");
        ensure!(run_count(visible)?.trim()=="0" && run_count(hidden)?.trim()=="0");
        worker.stop().await;Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=policy.events"]
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
        let worker=RunningAutomation::start_with_events(f.planning.clone(),Some(f.events.clone())).await;
        let batch=post(&mut f.author,&f.router,&endpoint(),request("collect")).await?;
        let result=settled(&mut f,&batch).await?;ensure!(result["items"][0]["state"]=="accepted","{result}");
        let run_id=Uuid::parse_str(result["items"][0]["decision"]["operations"][0]["id"].as_str().unwrap())?;
        let dispatcher=crate::test_support::software_execution::worker(&f.base,f.execution.clone()).await?;
        let task=tokio::time::timeout(Duration::from_secs(30),async{let mut body=claim_body();loop{let(status,value)=agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(case_credential()),Some(body.clone())).await?;if status==StatusCode::SERVICE_UNAVAILABLE {tokio::time::sleep(Duration::from_millis(50)).await;continue;}ensure!(status==StatusCode::OK,"{value}");if !value["task"].is_null(){return Ok::<_,anyhow::Error>(value["task"].clone());}body=claim_body();tokio::time::sleep(Duration::from_millis(25)).await;}}).await??;
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
            for (at,id) in [(started+120,early),(started+3600,due)] {execution.accept_scheduled_for_fixture_in(tx,&plan,&run.target,rss_mdm_execution_service::actions::production::AdmissionTrigger::Agent(Uuid::new_v4()),at,id).await.map_err(|e|sqlx::Error::Protocol(e.to_string()))?;}
            let tenant=tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move{let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=ANY($2)").bind(tenant).bind(vec![early,due]).fetch_all(c).await?;Ok(ids==vec![due])})).await
        })).await.fold(Ok,|e|Err(anyhow::anyhow!("{e:?}")),|e|Err(anyhow::anyhow!("{e:?}")),|e|Err(anyhow::anyhow!("{e:?}")),|e|Err(anyhow::anyhow!("{e:?}")),|e|Err(anyhow::anyhow!("{e:?}")))?;
        ensure!(result,"the old fixed anchor must not admit another collection");
        worker.stop().await;crate::test_support::runtime::stop_worker(dispatcher).await?;Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=policy.events"]
async fn member_commit_unknown_resumes_original_run_and_original_request() -> Result<()> {
    use rss_reconcile::DurableStore;
    let mut f = setup().await?;
    let resources = std::mem::take(&mut f.resources);
    resources
        .finish(async {
            let (resource, _, _) = f.resource().await?;
            let policy = policy(&mut f, resource, "resume", case_task_scope()).await?;
            let input = request("resume");
            let batch = post(&mut f.author, &f.router, &endpoint(), input.clone()).await?;
            let id = Uuid::parse_str(batch["batchId"].as_str().unwrap())?;
            let scheduler = crate::scheduler::SchedulerStorage::open(
                crate::device::test_support::options("mdm_scheduler_runtime")?
                    .password("runtime-fixture"),
            )
            .await?;
            let work = crate::automation::PolicyWork::new(
                f.planning.policy.clone(),
                f.events.clone(),
                scheduler.store.clone(),
            );
            let timer = rss_mdm_policy_service::clock::Timer::new();
            let cancel = tokio_util::sync::CancellationToken::new();
            let control = rss_reconcile::Control::new(&timer, Duration::from_secs(15), &cancel);
            let target = crate::automation::jobs::event_target(f.planning.tenant, id);
            work.wake(
                &target,
                &rss_reconcile::ResourceSet::empty(target.scope().tenant()),
                &control,
            )
            .await?;
            let scope =
                rss_reconcile::Scope::new(f.planning.tenant, crate::automation::jobs::EVENT_SCOPE)?;
            let planning_only = crate::automation::PolicyWork::management_only(
                f.planning.policy.clone(),
                scheduler.store.clone(),
            );
            ensure!(
                planning_only
                    .claim_due(&scope, 1, Duration::from_secs(2), &control)
                    .await
                    .is_err(),
                "pure OwnerFixture must not claim events"
            );
            drop(planning_only);
            let claim = work
                .claim_due(&scope, 1, Duration::from_secs(2), &control)
                .await?
                .claims
                .pop()
                .ok_or_else(|| anyhow::anyhow!("event claim missing"))?;
            ensure!(claim.target() == &target);
            let observed = crate::test_support::runtime::reconcile_ready(
                work.observe(&claim, &control).await?,
            );
            f.planning.policy.runtime.inject_next_transaction_fault(
                rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            );
            ensure!(
                work.apply(&claim, observed, &control)
                    .await
                    .unwrap_err()
                    .kind()
                    == rss_reconcile::ErrorKind::CommitUnknown
            );
            let committed = committed_member(id, policy)?;
            ensure!(
                committed["members"][0][1]["state"] == "accepted"
                    && committed["runs"]
                        .as_array()
                        .is_some_and(|runs| runs.len() == 1),
                "commit must have published the member and its original run: {committed}"
            );
            let audit = member_audit_ids().await?;
            drop(work);
            rss_runtime::ManagedResource::shutdown(&scheduler).await?;
            let worker =
                RunningAutomation::start_with_events(f.planning.clone(), Some(f.events.clone()))
                    .await;
            let settled = settled(&mut f, &batch).await?;
            ensure!(settled["items"][0]["state"] == "accepted", "{settled}");
            ensure!(run_count(policy)?.trim() == "1");
            ensure!(
                committed_member(id, policy)? == committed,
                "restart replaced the already committed member/run identity"
            );
            ensure!(
                member_audit_ids().await? == audit,
                "restart duplicated member business audit"
            );
            let detail = get(&mut f, &batch_path(&batch)).await?;
            ensure!(detail["request"] == input);
            ensure!(post(&mut f.author, &f.router, &endpoint(), input).await? == batch);
            worker.stop().await;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=policy.events"]
async fn agent_context_updates_and_revision_conflicts_use_original_owner() -> Result<()> {
    use crate::test_support::agent::agent_call;
    let mut f = setup().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async{
        let path="/api/v1/agent/runtime/policy-events";
        let mut input=request("context");let mut context=crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs);
        context["revision"]=json!(2);input["executionContext"]=context.clone();
        let(status,accepted)=agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(input.clone())).await?;
        ensure!(status==StatusCode::ACCEPTED,"{status}: {accepted}");
        let list_path=format!("/api/v1/agent/runtime/policy-event-batches?filter=operationId=={}",input["operationId"].as_str().unwrap());
        let(status,list)=agent_call(&f.router,Method::GET,&list_path,Some(case_credential()),None).await?;
        ensure!(status==StatusCode::OK && list["items"][0]["id"]==accepted["batchId"],"{list}");
        let detail_path=format!("/api/v1/agent/runtime/policy-event-batches/{}",accepted["batchId"].as_str().unwrap());
        let(status,detail)=agent_call(&f.router,Method::GET,&detail_path,Some(case_credential()),None).await?;
        ensure!(status==StatusCode::OK && detail["request"]==input,"{detail}");
        let(status,members)=agent_call(&f.router,Method::GET,&format!("{detail_path}/members"),Some(case_credential()),None).await?;
        ensure!(status==StatusCode::OK && members["items"].as_array().is_some_and(Vec::is_empty),"{members}");
        let stored=crate::test_support::process::pg(&format!("SELECT execution_context->>'revision' FROM mdm_agent.bindings b JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(b.tenant_id,b.registration) WHERE b.tenant_id='{}' AND r.device='{}'",case_tenant(),case_device_id()))?;
        ensure!(stored.trim()=="2");
        for (revision,sideload,helper) in [(1,false,true),(2,false,false),(3,true,true)]{
            let mut invalid=request("context");let mut c=context.clone();c["revision"]=json!(revision);c["msixSideload"]=json!(sideload);c["userHelper"]=json!(helper);invalid["executionContext"]=c;
            ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(invalid)).await?.0!=StatusCode::ACCEPTED);
        }
        ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(input)).await?.1==accepted);
        Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=policy.events"]
async fn non_run_owners_return_no_change_and_exact_retirement_progress() -> Result<()> {
    let mut f = setup().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async{
        f.grants.extend(crate::test_support::identity::device_grants(None,&["account_write","device_unmanage"])?);
        crate::test_support::identity::seed_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
        let access=Uuid::new_v4();
        post(&mut f.author,&f.router,&format!("/api/v1/policies/{access}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"customEvent":"access","scope":case_task_scope(),"action":{"kind":"device_access","mac":null,"windows":{"kind":"rss_factor","accounts":["local"]},"selfEnrollment":false,"role":null}}}})).await?;
        // Prepare both authored policies before the measured event workers start.
        let retire=Uuid::new_v4();
        post(&mut f.author,&f.router,&format!("/api/v1/policies/{retire}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"customEvent":"retire","scope":case_task_scope(),"action":{"kind":"unmanage_device","runLifetimeSeconds":300}}}})).await?;
        let worker=RunningAutomation::start_with_events(f.planning.clone(),Some(f.events.clone())).await;
        let batch=post(&mut f.author,&f.router,&endpoint(),request("access")).await?;
        let result=settled(&mut f,&batch).await?;ensure!(result["items"][0]["state"]=="no_change","{result}");ensure!(run_count(access)?.trim()=="0");
        let retire_request=request("retire");
        let batch=post(&mut f.author,&f.router,&endpoint(),retire_request.clone()).await?;
        let result=settled(&mut f,&batch).await?;ensure!(result["items"][0]["state"]=="accepted","{result}");
        ensure!(result["items"][0]["decision"]["operations"][0]["kind"]=="retirement");
        ensure!(result["items"][0]["operations"][0]["state"]["channels"].as_array().is_some_and(|v|!v.is_empty()),"{result}");
        let retirement=result["items"][0]["decision"]["operations"][0]["id"].clone();
        let dispatcher=crate::test_support::software_execution::worker(&f.base,f.execution.clone()).await?;
        let task=claim(&f.router).await?;
        ensure!(task["payload"]["kind"]=="unmanage" && task["payload"]["task"]["retirementId"]==retirement,"{task}");
        task_event(&f.router,&task,json!({"kind":"received"})).await?;
        task_event(&f.router,&task,json!({"kind":"start"})).await?;
        task_event(&f.router,&task,json!({"kind":"unmanage_result","outcome":"unknown"})).await?;
        let path="/api/v1/agent/runtime/management-activities";
        let mut page=Value::Null;
        for _ in 0..32 {
            let (status,value)=crate::test_support::agent::agent_call(&f.router,Method::GET,&format!("{path}?batch={}&request={}&limit=200",batch["batchId"].as_str().unwrap(),retire_request["operationId"].as_str().unwrap()),Some(case_credential()),None).await?;
            ensure!(status==StatusCode::OK,"{value}");page=value;
            if page["items"].as_array().unwrap().iter().any(|v|v["phase"]=="result"){break;}
        }
        let rows=page["items"].as_array().unwrap();
        let children=rows.iter().filter(|v|v["links"]["task"]==task["payload"]["task"]["taskId"]).collect::<Vec<_>>();
        ensure!(!children.is_empty() && children.iter().all(|v|v["links"]["retirement"]==retirement && v["origin"]=="human"),"{page}");
        for phase in ["accepted","offered","received","started","result"] {ensure!(children.iter().any(|v|v["phase"]==phase),"retirement missing {phase}: {page}");}
        let child=children.iter().find(|v|v["phase"]=="result").unwrap();
        let root=rows.iter().find(|v|v["kind"]=="batch" && v["phase"]=="accepted").unwrap();
        for (id,expected) in [(root["id"].as_str().unwrap(),child["id"].clone()),(child["id"].as_str().unwrap(),root["id"].clone())] {
            let (status,detail)=crate::test_support::agent::agent_call(&f.router,Method::GET,&format!("{path}/{id}"),Some(case_credential()),None).await?;
            ensure!(status==StatusCode::OK && detail["related"].as_array().unwrap().iter().any(|v|v["id"]==expected),"retirement relation absent: {detail}");
        }
        worker.stop().await;crate::test_support::runtime::stop_worker(dispatcher).await?;Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=policy.events"]
async fn retirement_event_requires_authority_for_every_associated_endpoint() -> Result<()> {
    use crate::authorization::{Grant, Permission, Scope};
    let mut f = setup().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async{
        f.grants.extend(crate::test_support::identity::device_grants(None,&["device_unmanage"])?);
        crate::test_support::identity::seed_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
        let policy=Uuid::new_v4();
        post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"customEvent":"paired-retire","scope":case_task_scope(),"action":{"kind":"unmanage_device","runLifetimeSeconds":300}}}})).await?;
        // A legal confirmed association is a precondition; this test exercises event authorization, not pairing.
        let peer=format!("event-mdm-{}",Uuid::new_v4());let(registration,_)=crate::test_support::inventory::seed_source(&peer,"mdm","mdm.windows","event-model")?;
        let association=Uuid::new_v4();let tenant=case_tenant();let agent=case_device_id();
        crate::test_support::process::pg(&format!("INSERT INTO mdm_devices.associations(tenant_id,id,version,state,evidence,hardware,confirmed_by,confirmed_at) VALUES('{tenant}','{association}',1,'confirmed','fixture confirmed physical device','{{}}','fixture',1); INSERT INTO mdm_devices.members(tenant_id,association_id,device,channel,registration_id,generation) SELECT tenant_id,'{association}',device,channel,id,generation FROM mdm_access.registrations WHERE tenant_id='{tenant}' AND (id='{registration}' OR(device='{agent}' AND channel='agent' AND state='active' AND purpose='primary'));"))?;
        f.grants.retain(|g|g.operation!=Permission::DeviceUnmanage);
        f.grants.push(Grant{operation:Permission::DeviceUnmanage,scope:Scope::Device{id:agent.into()}});
        crate::test_support::identity::seed_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
        let batch=post(&mut f.author,&f.router,&endpoint(),request("paired-retire")).await?;
        let result=get(&mut f,&format!("{}/members",batch_path(&batch))).await?;
        ensure!(result["items"][0]["decision"]["reason"]=="permission_denied","{result}");
        ensure!(crate::test_support::process::pg(&format!("SELECT count(*) FROM mdm_devices.retirements WHERE tenant_id='{tenant}'"))?.trim()=="0");
        Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=policy.events"]
async fn rotated_credential_cannot_accept_replay_or_read_but_accepted_work_survives() -> Result<()>
{
    use rss_mdm_agent_wire::runtime::PolicyEventRequest;
    use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
    let mut f = setup().await?;
    f.grants.push(crate::authorization::Grant {
        operation: crate::authorization::Permission::Credentials,
        scope: crate::authorization::Scope::Device {
            id: case_device_id().into(),
        },
    });
    crate::test_support::identity::seed_grants(case_tenant(), &f.author_id, f.grants.clone())
        .await?;
    let enrollment = crate::test_support::agent::service(&f.authority).await?;
    f.router = f.router.clone().merge(f.authority.protect(
        {
 rss_mdm_http_contract::route_module! { struct RotatedCredentialCannotAcceptReplayOrReadButAcceptedWorkSurvivesModule1 for [Browser] { api_v1 at "/api/v1" } }
 RotatedCredentialCannotAcceptReplayOrReadButAcceptedWorkSurvivesModule1 { api_v1: rss_mdm_management_http::agent_enrollment::routes(Some(enrollment.clone())) }.assemble()
},
    )?);
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let events=f.events.clone();
        let old_peer=crate::test_support::agent::evidence(case_credential()).unwrap();
        // Retaining this authenticated principal is the synchronization point before rotation commits.
        let old=enrollment.authenticate(&old_peer).await?;
        let audit=|| {let a=RequestAudit::new(case_tenant().into(),"policy_event",AuditIntent::Management);a.identify_device(old.registration());a};
        let (resource,_,_)=f.resource().await?;
        let policy=policy(&mut f,resource,"credential-race",case_task_scope()).await?;
        let mut body=request("credential-race");
        body["executionContext"]=crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs);
        let input:PolicyEventRequest=serde_json::from_value(body.clone())?;
        let a=audit();let accepted=serde_json::to_value(events.invoke_agent(&old,&input,&a).await?)?;a.finalize(None);
        let secret=crate::test_support::runtime::credential("event-credential-rotation");
        let csr=crate::test_support::agent::csr()?;
        let grant=post(&mut f.author,&f.router,&format!("/api/v1/agent-registrations/{}/recovery",old.registration()),json!({"wireVersion":1,"operationId":Uuid::new_v4(),"secret":secret,"platform":"macos","csr":csr})).await?;
        crate::test_support::agent::complete_grant(&enrollment,&grant,&json!({"secret":secret,"csr":csr,"runtime":{"platform":"macos","architecture":"aarch64","capabilities":["inventory.collect.v1","task.execute.v1","device.unmanage.v1","inventory.native.v1"],"executionContext":body["executionContext"]}}),"event-rotated").await?;
        let peer=crate::test_support::agent::evidence("event-rotated").unwrap();
        let current=enrollment.authenticate(&peer).await?;
        ensure!(current.registration()==old.registration() && current.generation()==old.generation() && current.credential()!=old.credential());
        let mut fresh=input.clone();fresh.operation_id=Uuid::new_v4();
        for request in [&fresh,&input] {
            let a=audit();ensure!(events.invoke_agent(&old,request,&a).await.is_err(),"superseded credential accepted a request");a.finalize(None);
        }
        let batch=Uuid::parse_str(accepted["batchId"].as_str().unwrap())?;
        for (id,members) in [(None,false),(Some(batch),false),(Some(batch),true)] {
            let a=audit();ensure!(events.read_agent(&old,id,members,&(if members { &rss_mdm_policy_service::events::queries::MEMBERS } else { &rss_mdm_policy_service::events::queries::BATCHES }).parse("")?,&a).await.is_err(),"superseded credential read a batch");a.finalize(None);
        }
        let a=audit();ensure!(serde_json::to_value(events.invoke_agent(&current,&input,&a).await?)?==accepted);a.finalize(None);
        let worker=RunningAutomation::start_with_events(f.planning.clone(),Some(f.events.clone())).await;
        let result=settled(&mut f,&accepted).await?;
        ensure!(result["items"][0]["state"]=="accepted" && run_count(policy)?.trim()=="1","accepted work must outlive credential rotation: {result}");
        worker.stop().await;
        let a=audit();ensure!(serde_json::to_value(events.read_agent(&current,Some(batch),false,&rss_mdm_policy_service::events::queries::BATCHES.parse("")?,&a).await?)?["id"]==accepted["batchId"]);a.finalize(None);
        crate::test_support::process::pg(&format!("UPDATE mdm_access.report_sources SET enabled=false WHERE tenant_id='{}' AND registration='{}'",case_tenant(),current.registration()))?;
        let a=audit();ensure!(events.invoke_agent(&current,&fresh,&a).await.is_err());a.finalize(None);
        let a=audit();ensure!(events.read_agent(&current,Some(batch),false,&rss_mdm_policy_service::events::queries::BATCHES.parse("")?,&a).await.is_err());a.finalize(None);
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=policy.events"]
async fn only_started_current_parent_can_accept_a_new_child_but_terminal_parent_can_replay()
-> Result<()> {
    use crate::test_support::agent::agent_call;
    let mut f = setup().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let(resource,_,_)=f.resource().await?;
        policy(&mut f,resource,"parent_run",case_task_scope()).await?;
        let parent_batch=post(&mut f.author,&f.router,&endpoint(),request("parent_run")).await?;
        let workers=RunningAutomation::start_with_events(f.planning.clone(),Some(f.events.clone())).await;
        let dispatcher=crate::test_support::software_execution::worker(&f.base,f.execution.clone()).await?;
        let result=async {
            settled(&mut f,&parent_batch).await?;
            let task=claim(&f.router).await?;
            let parent=task["payload"]["task"]["taskId"].as_str().ok_or_else(||anyhow::anyhow!("parent task identity missing"))?;
            let mut child=request("child_without_subscribers");
            child["source"]=json!({"kind":"policy","runId":parent});
            child["executionContext"]=crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs);
            let path="/api/v1/agent/runtime/policy-events";
            let mut forged=child.clone();forged["source"]["runId"]=json!(Uuid::new_v4());
            ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(forged)).await?.0!=StatusCode::ACCEPTED);
            ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(child.clone())).await?.0!=StatusCode::ACCEPTED,"unstarted parent accepted a child");
            task_event(&f.router,&task,json!({"kind":"received"})).await?;
            task_event(&f.router,&task,json!({"kind":"start"})).await?;
            let(status,accepted)=agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(child.clone())).await?;
            ensure!(status==StatusCode::ACCEPTED,"started parent: {status} {accepted}");
            let mut changed=child.clone();changed["source"]["runId"]=json!(Uuid::new_v4());
            ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(changed)).await?.0!=StatusCode::ACCEPTED);
            task_event(&f.router,&task,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"1.2","healthy":true}})).await?;
            let(status,replayed)=agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(child.clone())).await?;
            ensure!(status==StatusCode::ACCEPTED && replayed==accepted,"terminal parent lost original receipt");
            child["operationId"]=json!(Uuid::new_v4());
            ensure!(agent_call(&f.router,Method::POST,path,Some(case_credential()),Some(child)).await?.0!=StatusCode::ACCEPTED,"terminal parent started a new child");
            Ok(())
        }.await;
        crate::test_support::runtime::stop_worker(dispatcher).await?;
        workers.stop().await;
        result
    }).await
}

fn committed_member(batch: Uuid, policy: Uuid) -> Result<Value> {
    Ok(serde_json::from_str(&crate::test_support::process::pg(
        &format!(
            "SELECT jsonb_build_object('members',(SELECT jsonb_agg(jsonb_build_array(id,decision) ORDER BY id) FROM mdm_policy.event_members WHERE tenant_id='{tenant}' AND batch='{batch}'),'runs',(SELECT jsonb_agg(r.id ORDER BY r.id) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id='{tenant}' AND v.policy='{policy}'))",
            tenant = case_tenant()
        ),
    )?)?)
}
async fn member_audit_ids() -> Result<Vec<String>> {
    let mut ids = crate::audit_test_support::audit_records()
        .await?
        .into_iter()
        .filter(|r| r.source() == "mdm.business" && r.action() == "policy_event_member")
        .map(|r| r.event.event().identity().event_id().as_str().to_owned())
        .collect::<Vec<_>>();
    ids.sort();
    Ok(ids)
}

#[tokio::test]
#[ignore = "make t2 MODULE=policy.events"]
async fn policy_participants_reject_foreign_runtime_before_any_effect() -> Result<()> {
    let mut f = setup().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let action:rss_mdm_policy::Action=serde_json::from_value(policy_definition(Uuid::new_v4(),Uuid::new_v4())["action"].clone())?;
        for (runtime,expected) in [(f.planning.policy.runtime.clone(),true),(f.command_runtime.clone(),false)] {
            let result=runtime.local_tx_with_context(f.planning.tenant,crate::identity::deadline(),(&f.inputs,&f.events.execution,&action),|(inputs,events,action),tx|Box::pin(async move {
                let inputs_ok=inputs.software_binding_in(tx,action).await.is_ok();
                let events_ok=events.validate_policy_transaction_in(tx).is_ok();
                Ok((inputs_ok, events_ok))
            })).await.fold(Ok,Err,Err,Err,Err,Err)?;
            ensure!(result==(expected,expected),"each participant must independently enforce the initiating runtime: {result:?}");
        }
        let valid=f.planning.policy.runtime.local_tx(f.planning.tenant,crate::identity::deadline(),|tx|Box::pin(async move {
            tx.with_connection(|c|Box::pin(async move {
                sqlx::query_scalar::<_,bool>("SELECT NOT has_table_privilege(current_user,'mdm_access.requests','SELECT,INSERT,UPDATE,DELETE') AND has_column_privilege(current_user,'mdm_access.requests','source','SELECT') AND NOT has_column_privilege(current_user,'mdm_access.requests','password_digest','SELECT') AND NOT pg_has_role(current_user,'mdm_command_runtime','MEMBER') AND NOT has_table_privilege(current_user,'mdm_commands.attempts','INSERT,UPDATE,DELETE') AND has_column_privilege(current_user,'mdm_commands.action_runs','access_binding','UPDATE') AND has_column_privilege(current_user,'mdm_agent.bindings','execution_context','UPDATE') AND NOT has_column_privilege(current_user,'mdm_agent.bindings','platform','UPDATE') AND NOT has_any_column_privilege(current_user,'mdm_access.credentials','UPDATE') AND NOT has_any_column_privilege(current_user,'mdm_access.report_sources','UPDATE') AND NOT has_table_privilege(current_user,'mdm.asset_epochs','INSERT,UPDATE,DELETE') AND NOT has_sequence_privilege(current_user,'mdm.asset_event_ids','USAGE,UPDATE') AND has_function_privilege(current_user,'mdm.asset_visible(jsonb,bigint)','EXECUTE') AND NOT has_function_privilege(current_user,'mdm.advance_asset_epoch(uuid)','EXECUTE') AND has_column_privilege(current_user,'mdm_access.device_access_bindings','document','UPDATE') AND NOT has_table_privilege(current_user,'mdm_access.device_access_bindings','INSERT,UPDATE,DELETE')").fetch_one(c).await
            })).await
        })).await.fold(Ok,Err,Err,Err,Err,Err)?;
        ensure!(valid,"Policy participant must retain its narrow identity");
        // A runtime admitted for both tenants reaches the product's own tenant check.
        use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
        use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRuntime};
        let config=crate::test_support::identity::config(case_tenant())?;
        let db=&config.business_databases.policy;
        let peer=rss_request_context::TenantId::parse(crate::test_support::case::peer())?;
        let runtime=Arc::new(PgRuntime::connect_producer(
            PgConfig::new(&db.host,db.port,&db.name,&db.user,
                PgPassword::new(crate::config::secret(&db.password_file)?.as_str()),
                PgPrivateCa::from_pem(std::fs::read(&db.ca_file)?)?).with_pool_limits(0,2),
            crate::lifecycle::RuntimeTimer,
            ExecutionBinding::new(StorageIdentity::new(config.storage_binding.target,config.storage_binding.lineage)?,
                vec![(f.planning.tenant,Epoch::new(1)?),(peer,Epoch::new(1)?)])?
        ).await?);
        let result=async {
            let budget=rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
            let audit=Arc::new(f.authority.audit.on_runtime(runtime.clone(),f.planning.tenant,&budget.control()).await?);
            let participant=rss_mdm_execution_service::policy_events::PolicyEvents::bind(
                runtime.clone(),f.planning.tenant,audit,f.materials.clone()).await?;
            let rejected=runtime.local_tx(peer,crate::identity::deadline(),|tx|Box::pin(async move {
                Ok(matches!(participant.validate_policy_transaction_in(tx),
                    Err(rss_mdm_execution_service::transaction::Fault::Request(rss_mdm_execution_service::Error::Forbidden))))
            })).await.fold(Ok,Err,Err,Err,Err,Err)?;
            ensure!(rejected,"same-runtime foreign tenant reached Policy participation");
            Ok::<_,anyhow::Error>(())
        }.await;
        runtime.close().await;
        result?;
        Ok(())
    }).await
}

// Product composition proof: the Policy member and native command share one transaction.
#[tokio::test]
#[ignore = "make t2 MODULE=policy.events"]
async fn native_configuration_event_commits_or_rolls_back_all_facts() -> Result<()> {
    use rss_reconcile::DurableStore;
    let mut f = native_event_fixture().await?;
    let scheduler = crate::scheduler::SchedulerStorage::open(
        crate::device::test_support::options("mdm_scheduler_runtime")?.password("runtime-fixture"),
    )
    .await?;
    f.resources.resource(scheduler.clone());
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let device = crate::test_support::case::name("native-event-device");
        let batch = post(&mut f.author, &f.router, &format!("/api/v1/devices/{device}/policy-events"), request("native-atomic")).await?;
        ensure!(batch["members"] == 1, "native event must freeze one member: {batch}");
        let batch_id = Uuid::parse_str(batch["batchId"].as_str().unwrap())?;
        let work = rss_mdm_policy_service::worker::PolicyWork::new(f.planning.policy.clone(), f.events.clone(), scheduler.store.clone());
        let timer = rss_mdm_policy_service::clock::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(30), &cancel);
        let target = rss_mdm_policy_service::worker::jobs::event_target(f.planning.tenant, batch_id);
        work.wake(&target, &rss_reconcile::ResourceSet::empty(f.planning.tenant), &control).await?;
        let claim = work.claim_due(target.scope(), 1, Duration::from_secs(30), &control).await?.claims.pop().ok_or_else(||anyhow::anyhow!("native event claim missing"))?;
        ensure!(claim.target() == &target);
        let before = native_event_facts(batch_id)?;
        ensure!(before["operations"] == 0 && before["commands"] == 0 && before["outbox"] == 0 && before["claims"] == 0);
        // Fail after native acceptance, when Policy stores the member decision.
        // This case owns a fresh database; production roles/grants are unchanged.
        pg("ALTER TABLE mdm_policy.event_members ADD CONSTRAINT native_event_fault CHECK (decision->>'state' <> 'accepted')")?;
        let observed = crate::test_support::runtime::reconcile_ready(work.observe(&claim, &control).await?);
        let failed = work.apply(&claim, observed, &control).await;
        pg("ALTER TABLE mdm_policy.event_members DROP CONSTRAINT native_event_fault")?;
        ensure!(failed.is_err(), "member failure unexpectedly committed");
        ensure!(native_event_facts(batch_id)? == before, "failed member leaked native command, outbox, claims or audit");
        let observed = crate::test_support::runtime::reconcile_ready(work.observe(&claim, &control).await?);
        crate::test_support::runtime::reconcile_ready(work.apply(&claim, observed, &control).await?);
        let after = native_event_facts(batch_id)?;
        ensure!(after["operations"] == 1 && after["commands"] == 1 && after["outbox"] == 1 && after["claims"] == 1, "native facts must commit together: {after}");
        ensure!(after["member"]["state"] == "accepted" && after["member"]["operations"][0]["kind"] == "native", "event did not accept a native command: {after}");
        ensure!(after["member"]["operations"][0]["id"] == after["commandId"], "member referenced a different native operation");
        ensure!(after["audits"].as_i64().unwrap() > before["audits"].as_i64().unwrap());
        ensure!(crate::audit_test_support::audit_count(|r|r.action()=="policy_event_member").await? == 1, "native acceptance omitted or duplicated the member audit");
        work.release(&claim, &control).await?;
        Ok(())
    }).await
}

fn native_event_facts(batch: Uuid) -> Result<Value> {
    Ok(serde_json::from_str(&pg(&format!(
        "SELECT jsonb_build_object('member',(SELECT decision FROM mdm_policy.event_members WHERE tenant_id='{tenant}' AND batch='{batch}'),'operations',(SELECT count(*) FROM mdm_commands.operations WHERE tenant_id='{tenant}' AND device='{device}'),'commands',(SELECT count(*) FROM rss_device_command.commands c JOIN mdm_commands.operations o ON o.tenant_id=c.tenant_id AND o.id::text=c.command_id WHERE o.tenant_id='{tenant}' AND o.device='{device}'),'commandId',(SELECT min(c.command_id) FROM rss_device_command.commands c JOIN mdm_commands.operations o ON o.tenant_id=c.tenant_id AND o.id::text=c.command_id WHERE o.tenant_id='{tenant}' AND o.device='{device}'),'outbox',(SELECT count(*) FROM rss_transactional_messaging.outbox b JOIN mdm_commands.operations o ON o.tenant_id=b.tenant_id AND b.message_id='dispatch.'||o.id::text WHERE o.tenant_id='{tenant}' AND o.device='{device}'),'claims',(SELECT count(*) FROM mdm_planning.configuration_claims WHERE tenant_id='{tenant}' AND device='{device}'),'audits',(SELECT count(*) FROM rss_audit.records WHERE tenant_id='{tenant}'))",
        tenant = case_tenant(),
        device = crate::test_support::case::name("native-event-device")
    ))?)?)
}

async fn native_event_fixture() -> Result<Fixture> {
    let mut f = Fixture::new().await?;
    let setup = async {
        let events = f.events.clone();
        rss_mdm_http_contract::route_module! { struct NativeEventModule for [Browser] { api_v1 at "/api/v1" } }
        f.router = f.router.clone().merge(f.authority.protect(NativeEventModule {
            api_v1: rss_mdm_management_http::policy_events::routes(events),
        }.assemble())?);
        let device = crate::test_support::case::name("native-event-device");
        let proof = crate::device::test_support::admin(case_tenant(), "admin-a").await?;
        let credential = crate::device::test_support::proof(case_tenant(), rss_mdm_inventory::Channel::Mdm, 91);
        let mut tx = f.authority.pool.begin().await?;
        crate::Database::configure_transaction(&mut tx, case_tenant()).await?;
        rss_mdm_registration_service::device::fixture::native_in(&mut tx, &proof, &credential,
            rss_mdm_registration_service::device::fixture::NativeSeed {
                device, request:Uuid::new_v4(), ids:[Uuid::new_v4(),Uuid::new_v4(),Uuid::new_v4()],
                windows_profile:Some(rss_mdm_registration_service::enrollment::WindowsProfile::Device),
            }).await?;
        tx.commit().await?;
        pg(&format!("INSERT INTO mdm_commands.capabilities(tenant_id,registration,generation,os_version,edition,session,observed_at) SELECT tenant_id,id,generation,'10.0.22621.0',48,1,floor(extract(epoch FROM clock_timestamp()))::bigint FROM mdm_access.registrations WHERE tenant_id='{}' AND device='{device}' AND state='active'",case_tenant()))?;
        f.grants.extend(crate::test_support::identity::device_grants(None, &["configuration_write"])?);
        crate::test_support::identity::seed_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
        let scope = Uuid::new_v4();
        f.scope(scope, json!([{"kind":"device","id":device}])).await?;
        let resource = Uuid::new_v4();
        crate::test_support::planning_http::native_configuration_resource(
            &f.planning.resource.runtime, f.planning.tenant, f.content.as_deref().expect("native content"),
            resource,"windows","x86_64",crate::test_support::planning_http::windows_configuration()).await?;
        post(&mut f.author,&f.router,&format!("/api/v1/policies/{}",Uuid::new_v4()),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"customEvent":"native-atomic","action":{"kind":"configuration","resource":{"id":resource,"version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"exit":"retain"}}}})).await?;
        Ok::<_,anyhow::Error>(())
    }.await;
    if let Err(error) = setup {
        return f.resources.finish(async { Err(error) }).await;
    }
    Ok(f)
}
