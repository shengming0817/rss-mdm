//! Real product HTTP, Policy/Scope, registration authority and durable task receipts.
use crate::test_support::{
    agent::*,
    agent_execution::{self as execution, Fixture},
    http::{Browser, browser_subject},
    process::*,
    runtime::*,
    *,
};
use anyhow::Context;

fn context(revision: u64, session: Uuid, account: Uuid) -> Value {
    let mut c = crate::test_support::software_execution::context(
        crate::test_support::software_execution::Platform::MacOs,
    );
    c["revision"] = json!(revision);
    c["interactiveUser"] =
        json!({"identity":"501","generatedUid":account,"sessionId":session,"administrator":false});
    c
}
async fn claim(f: &Fixture, c: &Value) -> Result<(StatusCode, Value)> {
    agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(execution::case_credential()),Some(json!({"wireVersion":1,"executionContext":c,"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":[],"operationId":Uuid::new_v4()}))).await
}
async fn user_call(
    f: &Fixture,
    path: &str,
    input: Value,
    with_user: bool,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/agent/runtime/device-access/{path}"))
        .header("host", "mdm.example.test:9445")
        .header("content-type", "application/json")
        .extension(evidence(execution::case_credential()).unwrap());
    if with_user {
        request = request.header(
            "x-rss-user-session",
            &f.author.cookies["__Host-identity-session"],
        );
    }
    let response = f
        .router
        .clone()
        .oneshot(request.body(Body::from(serde_json::to_vec(&input)?))?)
        .await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&bytes)?))
}
async fn setup(f: &mut Fixture) -> Result<Uuid> {
    f.register_profile(json!(["inventory.collect.v1", "device_access.v1"]))
        .await?;
    f.grants
        .extend(crate::test_support::identity::device_grants(
            None,
            &["account_write"],
        )?);
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
        .await?;
    ensure!(
        f.author
            .login_password(&f.router, "other", crate::test_support::identity::PASSWORD)
            .await?
            == StatusCode::OK
    );
    let scope = Uuid::new_v4();
    f.scope(
        scope,
        json!([{"kind":"endpoint","id":execution::case_device_id()}]),
    )
    .await?;
    let policy = Uuid::new_v4();
    execution::post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"device_access","selfEnrollment":true,"role":null}}}})).await?;
    Ok(policy)
}
async fn event(f: &Fixture, task: &Value, c: &Value, event: Value) -> Result<(StatusCode, Value)> {
    agent_call(&f.router,Method::POST,&format!("/api/v1/agent/runtime/tasks/{}/events",task["payload"]["task"]["taskId"].as_str().context("task id")?),Some(execution::case_credential()),Some(json!({"wireVersion":1,"executionContext":c,"operationId":Uuid::new_v4(),"attemptId":task["payload"]["task"]["attemptId"],"event":event}))).await
}

#[tokio::test]
#[ignore = "MODULE=device-access.http: real HTTP/PG association ceremony, session switch and replay"]
async fn first_binding_requires_current_device_and_human_then_stays_admin_only() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let policy=setup(&mut f).await?;let account=Uuid::new_v4();let c=context(2,Uuid::new_v4(),account);
        ensure!(claim(&f,&c).await?.0==StatusCode::OK);
        let begin=json!({"operationId":Uuid::new_v4(),"policy":policy});
        ensure!(user_call(&f,"begin",begin.clone(),false).await?.0==StatusCode::UNAUTHORIZED);
        let started=user_call(&f,"begin",begin,true).await?;ensure!(started.0==StatusCode::OK,"begin: {started:?}");
        let confirm=json!({"operationId":Uuid::new_v4(),"challenge":started.1["id"],"nonce":started.1["nonce"],"localSession":started.1["localSession"]});
        let mut forged=confirm.clone();forged["localSession"]["account"]["generatedUid"]=json!(Uuid::new_v4());
        ensure!(user_call(&f,"confirm",forged,true).await?.0==StatusCode::CONFLICT);
        let switched=context(3,Uuid::new_v4(),account);
        ensure!(claim(&f,&switched).await?.0==StatusCode::OK);
        ensure!(user_call(&f,"confirm",confirm,true).await?.0==StatusCode::CONFLICT);
        let restarted=user_call(&f,"begin",json!({"operationId":Uuid::new_v4(),"policy":policy}),true).await?;
        ensure!(restarted.0==StatusCode::OK);
        let confirm=json!({"operationId":Uuid::new_v4(),"challenge":restarted.1["id"],"nonce":restarted.1["nonce"],"localSession":restarted.1["localSession"]});
        let accepted=user_call(&f,"confirm",confirm.clone(),true).await?;ensure!(accepted.0==StatusCode::OK,"confirm: {accepted:?}");
        ensure!(accepted.1["state"]=="pending" && accepted.1["appliedRevision"].is_null());
        let switched_again=context(4,Uuid::new_v4(),account);
        ensure!(claim(&f,&switched_again).await?.0==StatusCode::OK);
        ensure!(user_call(&f,"confirm",confirm,true).await?.1==accepted.1);
        ensure!(user_call(&f,"begin",json!({"operationId":Uuid::new_v4(),"policy":policy}),true).await?.0==StatusCode::CONFLICT);
        let id=accepted.1["id"].as_str().context("binding id")?;
        let path=format!("/api/v1/devices/{}/device-access/bindings/{id}",execution::case_device_id());
        let command=json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"unbind"}});
        let unbound=f.author.call(&f.router,Method::PUT,&path,Some(command.clone())).await?;
        ensure!(unbound.0==StatusCode::OK && unbound.1["serverState"]=="revoked","unbind {unbound:?}");
        ensure!(unbound.1["appliedRevision"].is_null());
        ensure!(f.author.call(&f.router,Method::PUT,&path,Some(command)).await?.1==unbound.1);
        ensure!(user_call(&f,"begin",json!({"operationId":Uuid::new_v4(),"policy":policy}),true).await?.0==StatusCode::CONFLICT);
        let count=pg(&format!("SELECT count(*) FROM mdm_access.device_access_bindings WHERE tenant_id='{}' AND device='{}'",case_tenant(),execution::case_device_id()))?;
        ensure!(count=="1");Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=device-access.http: real task delivery, separate applied state, policy invalidation"]
async fn ack_does_not_apply_and_mac_token_evidence_is_account_bound() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let policy=setup(&mut f).await?;let account=Uuid::new_v4();let c=context(2,Uuid::new_v4(),account);
        ensure!(claim(&f,&c).await?.0==StatusCode::OK);
        let started=user_call(&f,"begin",json!({"operationId":Uuid::new_v4(),"policy":policy}),true).await?;
        ensure!(started.0==StatusCode::OK,"begin: {started:?}");
        let accepted=user_call(&f,"confirm",json!({"operationId":Uuid::new_v4(),"challenge":started.1["id"],"nonce":started.1["nonce"],"localSession":started.1["localSession"]}),true).await?;
        ensure!(accepted.0==StatusCode::OK,"confirm: {accepted:?}");
        let claimed=claim(&f,&c).await?;ensure!(claimed.0==StatusCode::OK,"claim {claimed:?}");
        let task=claimed.1["task"].clone();ensure!(task["payload"]["kind"]=="device_access","task {task}");
        ensure!(event(&f,&task,&c,json!({"kind":"received"})).await?.0==StatusCode::OK);
        let list=format!("/api/v1/devices/{}/device-access",execution::case_device_id());
        let received=f.author.call(&f.router,Method::GET,&list,None).await?;
        ensure!(received.0==StatusCode::OK && received.1[0]["receivedRevision"]==1 && received.1[0]["appliedRevision"].is_null(),"received {received:?}");
        ensure!(event(&f,&task,&c,json!({"kind":"start"})).await?.0==StatusCode::OK);
        let spec=&task["payload"]["task"];
        let mut result=json!({"kind":"device_access_result","bindingId":spec["bindingId"],"bindingGeneration":spec["bindingGeneration"],"revision":spec["revision"],"definitionDigest":spec["definitionDigest"],"effect":{"state":"applied","account":{"platform":"macos","generatedUid":account},"role":"standard","mac":{"secureToken":"present","volumeOwner":"unknown","filevaultUnlock":"unknown"}}});
        let mut wrong=result.clone();wrong["effect"]["account"]["generatedUid"]=json!(Uuid::new_v4());
        ensure!(event(&f,&task,&c,wrong).await?.0==StatusCode::CONFLICT);
        let applied=event(&f,&task,&c,result.take()).await?;ensure!(applied.0==StatusCode::OK,"applied {applied:?}");
        let ready=f.author.call(&f.router,Method::GET,&list,None).await?;
        ensure!(ready.1[0]["serverState"]=="active" && ready.1[0]["appliedRevision"]==1);
        let id=ready.1[0]["id"].as_str().context("binding")?;
        let path=format!("/api/v1/devices/{}/device-access/bindings/{id}",execution::case_device_id());
        let grants=crate::test_support::identity::device_grants(Some(execution::case_device_id()),&["inventory_read"])?;
        crate::test_support::identity::set_grants(case_tenant(),&f.author_id,grants).await?;
        ensure!(f.author.call(&f.router,Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"unbind"}}))).await?.0==StatusCode::FORBIDDEN);
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=device-access.http: administrator creation, pending Secure Token, late result after unlink"]
async fn administrator_creation_and_late_completion_cannot_revive_unlinked_binding() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let policy=setup(&mut f).await?;let c=context(2,Uuid::new_v4(),Uuid::new_v4());
        ensure!(claim(&f,&c).await?.0==StatusCode::OK);
        let id=Uuid::new_v4();let device=execution::case_device_id();
        let path=format!("/api/v1/devices/{device}/device-access/bindings/{id}");
        let input=json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"action":{"kind":"put","instance":crate::test_support::identity::INSTANCE,"principal":f.author_id,"policy":policy,"account":{"kind":"create","platform":"macos","name":"workuser"}}});
        let mut foreign=input.clone();foreign["action"]["instance"]=json!(Uuid::new_v4());
        ensure!(f.author.call(&f.router,Method::PUT,&path,Some(foreign)).await?.0==StatusCode::FORBIDDEN);
        let created=f.author.call(&f.router,Method::PUT,&path,Some(input.clone())).await?;
        ensure!(created.0==StatusCode::OK && created.1["serverState"]=="pending" && created.1["account"].is_null(),"create {created:?}");
        ensure!(f.author.call(&f.router,Method::PUT,&path,Some(input.clone())).await?.1==created.1);
        let op=format!("/api/v1/devices/{device}/device-access/operations/{}",input["operationId"].as_str().context("operation")?);
        ensure!(f.author.call(&f.router,Method::GET,&op,None).await?.1==created.1);
        let claimed=claim(&f,&c).await?;ensure!(claimed.0==StatusCode::OK,"claim {claimed:?}");let task=claimed.1["task"].clone();
        ensure!(task["payload"]["task"]["action"]["kind"]=="create");
        ensure!(event(&f,&task,&c,json!({"kind":"received"})).await?.0==StatusCode::OK);
        ensure!(event(&f,&task,&c,json!({"kind":"start"})).await?.0==StatusCode::OK);
        let spec=&task["payload"]["task"];let account=Uuid::new_v4();
        let mut result=json!({"kind":"device_access_result","bindingId":id,"bindingGeneration":1,"revision":1,"definitionDigest":spec["definitionDigest"],"effect":{"state":"applied","account":{"platform":"macos","generatedUid":account},"role":"standard","mac":{"secureToken":"needs_administrator","volumeOwner":"unknown","filevaultUnlock":"unknown"}}});
        let pending=event(&f,&task,&c,result.clone()).await?;ensure!(pending.0==StatusCode::OK,"pending token {pending:?}");
        let observed=f.author.call(&f.router,Method::GET,&format!("/api/v1/devices/{device}/device-access"),None).await?;
        ensure!(observed.1[0]["serverState"]=="pending" && observed.1[0]["appliedRevision"].is_null());
        let unbound=f.author.call(&f.router,Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"unbind"}}))).await?;
        ensure!(unbound.0==StatusCode::OK && unbound.1["serverState"]=="revoked");
        result["effect"]["mac"]["secureToken"]=json!("present");
        let late=event(&f,&task,&c,result).await?;ensure!(late.0==StatusCode::OK,"late receipt {late:?}");
        let listed=f.author.call(&f.router,Method::GET,&format!("/api/v1/devices/{device}/device-access"),None).await?;
        ensure!(listed.1[0]["serverState"]=="revoked" && listed.1[0]["appliedRevision"].is_null());
        let cleanup=claim(&f,&c).await?;ensure!(cleanup.0==StatusCode::OK,"cleanup {cleanup:?}");
        ensure!(cleanup.1["task"]["payload"]["task"]["action"]["kind"]=="unbind");
        ensure!(cleanup.1["task"]["payload"]["task"]["action"]["account"]["generatedUid"]==account.to_string());
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=device-access.http: expired unstarted renewal, late creation after policy edit, scope-exit cleanup"]
async fn offline_delivery_and_late_creation_converge_without_recreating_account() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let policy=setup(&mut f).await?;
        let c=context(2,Uuid::new_v4(),Uuid::new_v4());
        ensure!(claim(&f,&c).await?.0==StatusCode::OK);
        let id=Uuid::new_v4();let device=execution::case_device_id();
        let path=format!("/api/v1/devices/{device}/device-access/bindings/{id}");
        let created=f.author.call(&f.router,Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"action":{"kind":"put","instance":crate::test_support::identity::INSTANCE,"principal":f.author_id,"policy":policy,"account":{"kind":"create","platform":"macos","name":"lateuser"}}}))).await?;
        ensure!(created.0==StatusCode::OK,"create {created:?}");
        let offered=claim(&f,&c).await?;ensure!(offered.0==StatusCode::OK);
        let expired=offered.1["task"]["payload"]["task"]["taskId"].as_str().context("offered")?;
        pg(&format!("UPDATE mdm_commands.action_runs SET available_at=0,deadline=1,state=jsonb_set(state,'{{deadline}}','1') WHERE tenant_id='{}' AND id='{expired}'",case_tenant()))?;
        let renewed=claim(&f,&c).await?;ensure!(renewed.0==StatusCode::OK,"renew {renewed:?}");
        let task=renewed.1["task"].clone();ensure!(task["payload"]["task"]["taskId"]!=expired && !task.is_null());
        for kind in ["received","start"] {ensure!(event(&f,&task,&c,json!({"kind":kind})).await?.0==StatusCode::OK);}
        let url=format!("/api/v1/policies/{policy}");
        let old=f.author.call(&f.router,Method::GET,&url,None).await?;
        ensure!(old.0==StatusCode::OK,"read policy {old:?}");
        let mut definition=old.1["definition"].clone();definition["action"]["role"]=json!("administrator");
        execution::post(&mut f.author,&f.router,&url,json!({"operationId":Uuid::new_v4(),"expectedRevision":old.1["revision"],"input":{"action":"put","enabled":true,"definition":definition}})).await?;
        ensure!(claim(&f,&c).await?.1["task"].is_null(),"started creation must block another delivery");
        let account=Uuid::new_v4();let spec=&task["payload"]["task"];
        let result=json!({"kind":"device_access_result","bindingId":id,"bindingGeneration":spec["bindingGeneration"],"revision":spec["revision"],"definitionDigest":spec["definitionDigest"],"effect":{"state":"applied","account":{"platform":"macos","generatedUid":account},"role":"standard","mac":{"secureToken":"present","volumeOwner":"unknown","filevaultUnlock":"unknown"}}});
        ensure!(event(&f,&task,&c,result).await?.0==StatusCode::OK);
        let list=format!("/api/v1/devices/{device}/device-access");
        let pending=f.author.call(&f.router,Method::GET,&list,None).await?;
        ensure!(pending.1[0]["account"]["generatedUid"]==account.to_string() && pending.1[0]["appliedRevision"].is_null());
        let apply=claim(&f,&c).await?;let task=apply.1["task"].clone();
        ensure!(task["payload"]["task"]["action"]["kind"]=="apply","apply existing account {apply:?}");
        for kind in ["received","start"] {ensure!(event(&f,&task,&c,json!({"kind":kind})).await?.0==StatusCode::OK);}
        // Changing scope to a fresh empty scope exercises exclusion, not just Policy.enabled.
        let empty=Uuid::new_v4();f.scope(empty,json!([])).await?;
        let old=f.author.call(&f.router,Method::GET,&url,None).await?;
        let mut definition=old.1["definition"].clone();definition["scope"]=json!(empty);
        execution::post(&mut f.author,&f.router,&url,json!({"operationId":Uuid::new_v4(),"expectedRevision":old.1["revision"],"input":{"action":"put","enabled":true,"definition":definition}})).await?;
        ensure!(claim(&f,&c).await?.0==StatusCode::OK);
        let spec=&task["payload"]["task"];
        let late=json!({"kind":"device_access_result","bindingId":id,"bindingGeneration":spec["bindingGeneration"],"revision":spec["revision"],"definitionDigest":spec["definitionDigest"],"effect":{"state":"applied","account":{"platform":"macos","generatedUid":account},"role":"administrator","mac":{"secureToken":"present","volumeOwner":"unknown","filevaultUnlock":"unknown"}}});
        ensure!(event(&f,&task,&c,late).await?.0==StatusCode::OK);
        let revoked=f.author.call(&f.router,Method::GET,&list,None).await?;
        ensure!(revoked.1[0]["serverState"]=="revoked" && revoked.1[0]["appliedRevision"].is_null());
        let cleanup=claim(&f,&c).await?;
        ensure!(cleanup.1["task"]["payload"]["task"]["action"]["kind"]=="unbind","scope-exit cleanup {cleanup:?}");
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=device-access.http: binding administrator revocation independent of policy publisher"]
async fn revoked_binding_administrator_cannot_borrow_policy_publishers_authority() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let policy=setup(&mut f).await?;let c=context(2,Uuid::new_v4(),Uuid::new_v4());
        ensure!(claim(&f,&c).await?.0==StatusCode::OK);
        let mut manager=Browser::default();ensure!(manager.login(&f.router,"admin").await?==StatusCode::OK);
        let manager_id=browser_subject(&manager,&f.router).await?;
        crate::test_support::identity::set_grants(case_tenant(),&manager_id,crate::test_support::identity::device_grants(Some(execution::case_device_id()),&["account_write"])?).await?;
        let id=Uuid::new_v4();let path=format!("/api/v1/devices/{}/device-access/bindings/{id}",execution::case_device_id());
        let created=manager.call(&f.router,Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"action":{"kind":"put","instance":crate::test_support::identity::INSTANCE,"principal":f.author_id,"policy":policy,"account":{"kind":"create","platform":"macos","name":"delegated"}}}))).await?;
        ensure!(created.0==StatusCode::OK,"manager create {created:?}");
        let offer=claim(&f,&c).await?;let task=offer.1["task"].clone();ensure!(!task.is_null());
        ensure!(event(&f,&task,&c,json!({"kind":"received"})).await?.0==StatusCode::OK);
        crate::test_support::identity::set_grants(case_tenant(),&manager_id,vec![]).await?;
        ensure!(event(&f,&task,&c,json!({"kind":"start"})).await?.0==StatusCode::FORBIDDEN);
        let next=claim(&f,&c).await?;ensure!(next.0==StatusCode::OK && next.1["task"].is_null());
        let listed=f.author.call(&f.router,Method::GET,&format!("/api/v1/devices/{}/device-access",execution::case_device_id()),None).await?;
        ensure!(listed.0==StatusCode::OK && listed.1[0]["appliedRevision"].is_null(),"publisher remains authorized {listed:?}");
        Ok(())
    }).await
}
