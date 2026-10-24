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
use ring::signature::KeyPair;
use rss_mdm_agent_wire::runtime as wire;

fn context(revision: u64, session: Uuid, account: Uuid) -> Value {
    let mut c = crate::test_support::software_execution::context(
        crate::test_support::software_execution::Platform::MacOs,
    );
    c["revision"] = json!(revision);
    c["interactiveUser"] = json!({"windowsAuthority":null,"identity":"501","generatedUid":account,"sessionId":session,"administrator":false});
    c
}
async fn claim(f: &Fixture, c: &Value) -> Result<(StatusCode, Value)> {
    agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(execution::case_credential()),Some(json!({"wireVersion":1,"executionContext":c,"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":[],"operationId":Uuid::new_v4()}))).await
}
fn verification<'a>(
    f: &'a Fixture,
    registration: &'a Value,
    task: &wire::SignedTask,
    permit: wire::TaskPermit,
) -> Result<crate::test_support::task_signature::TaskVerification<'a>> {
    Ok(crate::test_support::task_signature::TaskVerification {
        key_id: "t2",
        public_key: f.key.public_key().as_ref(),
        tenant_id: Uuid::parse_str(case_tenant())?,
        device_id: registration["deviceId"]
            .as_str()
            .context("enrolled device")?,
        platform: if matches!(&task.payload,wire::TaskPayload::DeviceAccess(v) if v.platform == wire::TaskPlatform::Windows)
        {
            wire::TaskPlatform::Windows
        } else {
            wire::TaskPlatform::Macos
        },
        architecture: if matches!(&task.payload,wire::TaskPayload::DeviceAccess(v) if v.platform == wire::TaskPlatform::Windows)
        {
            wire::TaskArchitecture::X86_64
        } else {
            wire::TaskArchitecture::Aarch64
        },
        registration_id: serde_json::from_value(registration["registrationId"].clone())?,
        generation: registration["generation"]
            .as_u64()
            .context("enrolled generation")?,
        task_id: task.payload.task_id(),
        attempt_id: task.payload.attempt_id(),
        permit,
        now: crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?,
    })
}
async fn offer(f: &Fixture, c: &Value, registration: &Value) -> Result<(StatusCode, Value)> {
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let response = claim(f, c).await?;
            ensure!(response.0 == StatusCode::OK, "offer {response:?}");
            if !response.1["task"].is_null() {
                let signed: wire::SignedTask = serde_json::from_value(response.1["task"].clone())?;
                crate::test_support::task_signature::verify(
                    &signed,
                    &verification(f, registration, &signed, wire::TaskPermit::Offer)?,
                )?;
                return Ok(response);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
    match result {
        Ok(value) => value,
        Err(error) => {
            let bindings = pg(&format!(
                "SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'state',state,'revision',revision,'document',document)),'[]') FROM mdm_access.device_access_bindings WHERE tenant_id='{}'",
                case_tenant()
            ))?;
            let runs = pg(&format!(
                "SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'gatewayAccepted',gateway_accepted,'state',state,'source',source_kind)),'[]') FROM mdm_commands.action_runs WHERE tenant_id='{}'",
                case_tenant()
            ))?;
            anyhow::bail!("offer timeout: {error}; bindings={bindings}; runs={runs}")
        }
    }
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
async fn setup(f: &mut Fixture) -> Result<(Uuid, Value)> {
    setup_profile(f, false).await
}
async fn setup_profile(f: &mut Fixture, retiring: bool) -> Result<(Uuid, Value)> {
    setup_platform(f, retiring, false).await
}
async fn setup_platform(f: &mut Fixture, retiring: bool, windows: bool) -> Result<(Uuid, Value)> {
    let capabilities = if retiring {
        json!([
            "inventory.collect.v1",
            "device.unmanage.v1",
            "device_access.v1"
        ])
    } else {
        json!(["inventory.collect.v1", "device_access.v1"])
    };
    let registration = if windows {
        seed_profile(&f.base,f.execution.clone(),execution::case_credential(),execution::case_device_id(),
            json!({"capabilities":["inventory.collect.v1","task.execute.v1","credentials.windows.v1","device_access.v1"],"platform":"windows","architecture":"x86_64",
                "executionContext":windows_context()})).await?
    } else {
        f.register_profile(capabilities).await?
    };
    if retiring {
        f.grants
            .extend(crate::test_support::identity::device_grants(
                None,
                &["device_unmanage", "inventory_assign"],
            )?);
    }
    f.grants
        .extend(crate::test_support::identity::device_grants(
            None,
            &["account_write"],
        )?);
    crate::test_support::identity::seed_grants(case_tenant(), &f.author_id, f.grants.clone())
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
        json!([{"kind":"device","id":execution::case_device_id()}]),
    )
    .await?;
    let policy = Uuid::new_v4();
    execution::post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"device_access","mac":{"authentication":"secure_enclave","passwordProvider":null,"login":"local","unlock":"local","filevault":"local","offlineGraceSeconds":null,"registrationGraceSeconds":null,"maintenanceAccounts":[]},"windowsAccounts":["local"],"selfEnrollment":true,"role":null}}}})).await?;
    Ok((policy, registration))
}
async fn event(
    f: &Fixture,
    task: &Value,
    c: &Value,
    registration: &Value,
    event: Value,
) -> Result<(StatusCode, Value)> {
    let start = event["kind"] == "start";
    let response=agent_call(&f.router,Method::POST,&format!("/api/v1/agent/runtime/tasks/{}/events",task["payload"]["task"]["taskId"].as_str().context("task id")?),Some(execution::case_credential()),Some(json!({"wireVersion":1,"executionContext":c,"operationId":Uuid::new_v4(),"attemptId":task["payload"]["task"]["attemptId"],"event":event}))).await?;
    if start && response.0 == StatusCode::OK {
        let offered: wire::SignedTask = serde_json::from_value(task.clone())?;
        let ack: wire::TaskEventAck = serde_json::from_value(response.1.clone())?;
        let signed = ack.into_permit().context("start permit")?;
        crate::test_support::task_signature::verify(
            &signed,
            &verification(f, registration, &offered, wire::TaskPermit::Start)?,
        )?;
    }
    Ok(response)
}

#[tokio::test]
#[ignore = "MODULE=device-access.http: real HTTP/PG association ceremony, session switch and replay"]
async fn first_binding_requires_current_device_and_human_then_stays_admin_only() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let (policy,_registration)=setup(&mut f).await?;let account=Uuid::new_v4();let c=context(2,Uuid::new_v4(),account);
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
        ensure!(accepted.1["revoked"]==false && accepted.1["bindingGeneration"]==1 && accepted.1["factorGeneration"]==1 && accepted.1["appliedRevision"].is_null());
        let switched_again=context(4,Uuid::new_v4(),account);
        ensure!(claim(&f,&switched_again).await?.0==StatusCode::OK);
        ensure!(user_call(&f,"confirm",confirm,true).await?.1==accepted.1);
        ensure!(user_call(&f,"begin",json!({"operationId":Uuid::new_v4(),"policy":policy}),true).await?.0==StatusCode::CONFLICT);
        let id=accepted.1["id"].as_str().context("binding id")?;
        let path=format!("/api/v1/devices/{}/device-access/bindings/{id}",execution::case_device_id());
        let command=json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"unbind","disposition":"keep"}});
        let unbound=f.access_call(Method::PUT,&path,Some(command.clone())).await?;
        ensure!(unbound.0==StatusCode::OK && unbound.1["serverState"]=="revoked","unbind {unbound:?}");
        ensure!(unbound.1["appliedRevision"].is_null());
        ensure!(f.access_call(Method::PUT,&path,Some(command)).await?.1==unbound.1);
        ensure!(user_call(&f,"begin",json!({"operationId":Uuid::new_v4(),"policy":policy}),true).await?.0==StatusCode::CONFLICT);
        let count=pg(&format!("SELECT count(*) FROM mdm_access.device_access_bindings WHERE tenant_id='{}' AND device='{}'",case_tenant(),execution::case_device_id()))?;
        ensure!(count.trim()=="1");Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=device-access.http: real task delivery, separate applied state, policy invalidation"]
async fn ack_does_not_apply_and_mac_token_evidence_is_account_bound() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let (policy,registration)=setup(&mut f).await?;let account=Uuid::new_v4();let c=context(2,Uuid::new_v4(),account);
        ensure!(claim(&f,&c).await?.0==StatusCode::OK);
        let started=user_call(&f,"begin",json!({"operationId":Uuid::new_v4(),"policy":policy}),true).await?;
        ensure!(started.0==StatusCode::OK,"begin: {started:?}");
        let accepted=user_call(&f,"confirm",json!({"operationId":Uuid::new_v4(),"challenge":started.1["id"],"nonce":started.1["nonce"],"localSession":started.1["localSession"]}),true).await?;
        ensure!(accepted.0==StatusCode::OK,"confirm: {accepted:?}");
        let claimed=offer(&f,&c,&registration).await?;ensure!(claimed.0==StatusCode::OK,"claim {claimed:?}");
        let task=claimed.1["task"].clone();ensure!(task["payload"]["kind"]=="device_access","task {task}");
        let signed:wire::SignedTask=serde_json::from_value(task.clone())?;
        let trusted=verification(&f,&registration,&signed,wire::TaskPermit::Offer)?;
        let mut altered=signed.clone();
        let wire::TaskPayload::DeviceAccess(body)=&mut altered.payload else {anyhow::bail!("access task")};
        body.binding_generation+=1;
        ensure!(crate::test_support::task_signature::verify(&altered,&trusted).is_err(),"modified body passed signature");
        let mut foreign_registration=registration.clone();foreign_registration["registrationId"]=json!(Uuid::new_v4());
        ensure!(crate::test_support::task_signature::verify(&signed,&verification(&f,&foreign_registration,&signed,wire::TaskPermit::Offer)?).is_err(),"foreign registration accepted");
        ensure!(event(&f,&task,&c,&registration,json!({"kind":"received"})).await?.0==StatusCode::OK);
        let list=format!("/api/v1/devices/{}/device-access",execution::case_device_id());
        let received=f.author.call(&f.router,Method::GET,&list,None).await?;
        ensure!(received.0==StatusCode::OK && received.1["items"][0]["receivedRevision"]==1 && received.1["items"][0]["appliedRevision"].is_null(),"received {received:?}");
        ensure!(event(&f,&task,&c,&registration,json!({"kind":"start"})).await?.0==StatusCode::OK);
        let spec=&task["payload"]["task"];
        let mut result=json!({"kind":"device_access_result","bindingId":spec["bindingId"],"bindingGeneration":spec["bindingGeneration"],"revision":spec["revision"],"definitionDigest":spec["definitionDigest"],"effect":{"state":"applied","account":{"platform":"macos","generatedUid":account},"role":"standard","mac":{"passwordSync":"unknown","keychainSync":"unknown","secureToken":"present","volumeOwner":"unknown","filevaultUnlock":"unknown"}}});
        let mut wrong=result.clone();wrong["effect"]["account"]["generatedUid"]=json!(Uuid::new_v4());
        ensure!(event(&f,&task,&c,&registration,wrong).await?.0==StatusCode::CONFLICT);
        let applied=event(&f,&task,&c,&registration,result.take()).await?;ensure!(applied.0==StatusCode::OK,"applied {applied:?}");
        let ready=f.author.call(&f.router,Method::GET,&list,None).await?;
        ensure!(ready.1["items"][0]["serverState"]=="active" && ready.1["items"][0]["appliedRevision"]==1);
        let id=ready.1["items"][0]["id"].as_str().context("binding")?;
        let path=format!("/api/v1/devices/{}/device-access/bindings/{id}",execution::case_device_id());
        let grants=crate::test_support::identity::device_grants(Some(execution::case_device_id()),&["inventory_read"])?;
        crate::test_support::identity::change_grants(case_tenant(),&f.author_id,grants).await?;
        ensure!(f.access_call(Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"unbind","disposition":"keep"}}))).await?.0==StatusCode::FORBIDDEN);
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=device-access.http: administrator creation, pending Secure Token, late result after unlink"]
async fn administrator_creation_and_late_completion_cannot_revive_unlinked_binding() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let (policy,registration)=setup(&mut f).await?;let c=context(2,Uuid::new_v4(),Uuid::new_v4());
        ensure!(claim(&f,&c).await?.0==StatusCode::OK);
        let id=Uuid::new_v4();let device=execution::case_device_id();
        let path=format!("/api/v1/devices/{device}/device-access/bindings/{id}");
        let input=json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"action":{"kind":"put","instance":crate::test_support::identity::INSTANCE,"principal":f.author_id,"policy":policy,"account":{"kind":"create","platform":"macos","name":"workuser"}}});
        let mut foreign=input.clone();foreign["action"]["instance"]=json!(Uuid::new_v4());
        ensure!(f.access_call(Method::PUT,&path,Some(foreign)).await?.0==StatusCode::FORBIDDEN);
        let created=f.access_call(Method::PUT,&path,Some(input.clone())).await?;
        ensure!(created.0==StatusCode::OK && created.1["serverState"]=="pending" && created.1["account"].is_null(),"create {created:?}");
        ensure!(f.access_call(Method::PUT,&path,Some(input.clone())).await?.1==created.1);
        let mut replacement=input.clone();replacement["operationId"]=json!(Uuid::new_v4());replacement["expectedRevision"]=json!(1);
        replacement["action"]["account"]=json!({"kind":"existing","account":{"platform":"macos","generatedUid":Uuid::new_v4()}});
        ensure!(f.access_call(Method::PUT,&path,Some(replacement)).await?.0==StatusCode::CONFLICT);
        let op=format!("/api/v1/devices/{device}/device-access/operations/{}",input["operationId"].as_str().context("operation")?);
        ensure!(f.author.call(&f.router,Method::GET,&op,None).await?.1==created.1);
        let claimed=offer(&f,&c,&registration).await?;ensure!(claimed.0==StatusCode::OK,"claim {claimed:?}");let task=claimed.1["task"].clone();
        ensure!(task["payload"]["task"]["action"]["kind"]=="create");
        ensure!(event(&f,&task,&c,&registration,json!({"kind":"received"})).await?.0==StatusCode::OK);
        ensure!(event(&f,&task,&c,&registration,json!({"kind":"start"})).await?.0==StatusCode::OK);
        let spec=&task["payload"]["task"];let account=Uuid::new_v4();
        let mut result=json!({"kind":"device_access_result","bindingId":id,"bindingGeneration":1,"revision":1,"definitionDigest":spec["definitionDigest"],"effect":{"state":"applied","account":{"platform":"macos","generatedUid":account},"role":"standard","mac":{"passwordSync":"unknown","keychainSync":"unknown","secureToken":"needs_administrator","volumeOwner":"unknown","filevaultUnlock":"unknown"}}});
        let pending=event(&f,&task,&c,&registration,result.clone()).await?;ensure!(pending.0==StatusCode::OK,"pending token {pending:?}");
        let observed=f.author.call(&f.router,Method::GET,&format!("/api/v1/devices/{device}/device-access"),None).await?;
        ensure!(observed.1["items"][0]["serverState"]=="pending" && observed.1["items"][0]["appliedRevision"].is_null());
        let unbound=f.access_call(Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"unbind","disposition":"keep"}}))).await?;
        ensure!(unbound.0==StatusCode::OK && unbound.1["serverState"]=="revoked");
        result["effect"]["mac"]["secureToken"]=json!("present");
        let late=event(&f,&task,&c,&registration,result).await?;ensure!(late.0==StatusCode::OK,"late receipt {late:?}");
        let listed=f.author.call(&f.router,Method::GET,&format!("/api/v1/devices/{device}/device-access"),None).await?;
        ensure!(listed.1["items"][0]["serverState"]=="revoked" && listed.1["items"][0]["appliedRevision"].is_null());
        let cleanup=offer(&f,&c,&registration).await?;ensure!(cleanup.0==StatusCode::OK,"cleanup {cleanup:?}");
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
        let (policy,registration)=setup(&mut f).await?;
        let c=context(2,Uuid::new_v4(),Uuid::new_v4());
        ensure!(claim(&f,&c).await?.0==StatusCode::OK);
        let id=Uuid::new_v4();let device=execution::case_device_id();
        let path=format!("/api/v1/devices/{device}/device-access/bindings/{id}");
        let created=f.access_call(Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"action":{"kind":"put","instance":crate::test_support::identity::INSTANCE,"principal":f.author_id,"policy":policy,"account":{"kind":"create","platform":"macos","name":"lateuser"}}}))).await?;
        ensure!(created.0==StatusCode::OK,"create {created:?}");
        let offered=offer(&f,&c,&registration).await?;ensure!(offered.0==StatusCode::OK);
        let expired=offered.1["task"]["payload"]["task"]["taskId"].as_str().context("offered")?;
        pg(&format!("UPDATE mdm_commands.action_runs SET available_at=0,deadline=1,state=jsonb_set(state,'{{deadline}}','1') WHERE tenant_id='{}' AND id='{expired}'",case_tenant()))?;
        let renewed=offer(&f,&c,&registration).await?;ensure!(renewed.0==StatusCode::OK,"renew {renewed:?}");
        let task=renewed.1["task"].clone();ensure!(task["payload"]["task"]["taskId"]!=expired && !task.is_null());
        for kind in ["received","start"] {ensure!(event(&f,&task,&c,&registration,json!({"kind":kind})).await?.0==StatusCode::OK);}
        let url=format!("/api/v1/policies/{policy}");
        let old=f.author.call(&f.router,Method::GET,&url,None).await?;
        ensure!(old.0==StatusCode::OK,"read policy {old:?}");
        let mut definition=old.1["definition"].clone();definition["action"]["role"]=json!("administrator");
        execution::post(&mut f.author,&f.router,&url,json!({"operationId":Uuid::new_v4(),"expectedRevision":old.1["revision"],"input":{"action":"put","enabled":true,"definition":definition}})).await?;
        ensure!(claim(&f,&c).await?.1["task"].is_null(),"started creation must block another delivery");
        let revised=f.access_call(Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":2,"action":{"kind":"put","instance":crate::test_support::identity::INSTANCE,"principal":f.author_id,"policy":policy,"account":{"kind":"create","platform":"macos","name":"lateuser"}}}))).await?;
        ensure!(revised.0==StatusCode::OK && revised.1["bindingGeneration"]==1,"configuration preserves binding generation {revised:?}");
        let account=Uuid::new_v4();let spec=&task["payload"]["task"];
        let result=json!({"kind":"device_access_result","bindingId":id,"bindingGeneration":spec["bindingGeneration"],"revision":spec["revision"],"definitionDigest":spec["definitionDigest"],"effect":{"state":"applied","account":{"platform":"macos","generatedUid":account},"role":"standard","mac":{"passwordSync":"unknown","keychainSync":"unknown","secureToken":"present","volumeOwner":"unknown","filevaultUnlock":"unknown"}}});
        ensure!(event(&f,&task,&c,&registration,result).await?.0==StatusCode::OK);
        let list=format!("/api/v1/devices/{device}/device-access");
        let pending=f.author.call(&f.router,Method::GET,&list,None).await?;
        ensure!(pending.1["items"][0]["account"]["generatedUid"]==account.to_string() && pending.1["items"][0]["appliedRevision"].is_null());
        let apply=offer(&f,&c,&registration).await?;let task=apply.1["task"].clone();
        ensure!(task["payload"]["task"]["action"]["kind"]=="apply","apply existing account {apply:?}");
        for kind in ["received","start"] {ensure!(event(&f,&task,&c,&registration,json!({"kind":kind})).await?.0==StatusCode::OK);}
        // Changing scope to a fresh empty scope exercises exclusion, not just Policy.enabled.
        let empty=Uuid::new_v4();f.scope(empty,json!([])).await?;
        let old=f.author.call(&f.router,Method::GET,&url,None).await?;
        let mut definition=old.1["definition"].clone();definition["scope"]=json!(empty);
        execution::post(&mut f.author,&f.router,&url,json!({"operationId":Uuid::new_v4(),"expectedRevision":old.1["revision"],"input":{"action":"put","enabled":true,"definition":definition}})).await?;
        ensure!(claim(&f,&c).await?.0==StatusCode::OK);
        let spec=&task["payload"]["task"];
        let late=json!({"kind":"device_access_result","bindingId":id,"bindingGeneration":spec["bindingGeneration"],"revision":spec["revision"],"definitionDigest":spec["definitionDigest"],"effect":{"state":"applied","account":{"platform":"macos","generatedUid":account},"role":"administrator","mac":{"passwordSync":"unknown","keychainSync":"unknown","secureToken":"present","volumeOwner":"unknown","filevaultUnlock":"unknown"}}});
        ensure!(event(&f,&task,&c,&registration,late).await?.0==StatusCode::OK);
        let revoked=f.author.call(&f.router,Method::GET,&list,None).await?;
        ensure!(revoked.1["items"][0]["serverState"]=="revoked" && revoked.1["items"][0]["appliedRevision"].is_null());
        let cleanup=offer(&f,&c,&registration).await?;
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
        let (policy,registration)=setup(&mut f).await?;let c=context(2,Uuid::new_v4(),Uuid::new_v4());
        ensure!(claim(&f,&c).await?.0==StatusCode::OK);
        let mut manager=Browser::default();ensure!(manager.login(&f.router,"admin").await?==StatusCode::OK);
        let manager_id=browser_subject(&manager,&f.router).await?;
        crate::test_support::identity::seed_grants(case_tenant(),&manager_id,crate::test_support::identity::device_grants(Some(execution::case_device_id()),&["account_write"])?).await?;
        let id=Uuid::new_v4();let path=format!("/api/v1/devices/{}/device-access/bindings/{id}",execution::case_device_id());
        let saved_author=std::mem::replace(&mut f.author,manager);
        let saved_authenticator=f.access_authenticator.take();
        let created=f.access_call(Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"action":{"kind":"put","instance":crate::test_support::identity::INSTANCE,"principal":f.author_id,"policy":policy,"account":{"kind":"create","platform":"macos","name":"delegated"}}}))).await?;
        f.author=saved_author;f.access_authenticator=saved_authenticator;
        ensure!(created.0==StatusCode::OK,"manager create {created:?}");
        let offer=offer(&f,&c,&registration).await?;let task=offer.1["task"].clone();ensure!(!task.is_null());
        ensure!(event(&f,&task,&c,&registration,json!({"kind":"received"})).await?.0==StatusCode::OK);
        crate::test_support::identity::change_grants(case_tenant(),&manager_id,vec![]).await?;
        ensure!(event(&f,&task,&c,&registration,json!({"kind":"start"})).await?.0==StatusCode::FORBIDDEN);
        let next=claim(&f,&c).await?;ensure!(next.0==StatusCode::OK && next.1["task"].is_null());
        let listed=f.author.call(&f.router,Method::GET,&format!("/api/v1/devices/{}/device-access",execution::case_device_id()),None).await?;
        ensure!(listed.0==StatusCode::OK && listed.1["items"][0]["appliedRevision"].is_null(),"publisher remains authorized {listed:?}");
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=device-access.http: accepted retirement keeps cleanup polling open with an existing binding"]
async fn retirement_keeps_unmanage_polling_open_and_normal_access_closed() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let (policy,registration)=setup_profile(&mut f,true).await?;
        let account=Uuid::new_v4();let c=context(2,Uuid::new_v4(),account);
        ensure!(claim(&f,&c).await?.0==StatusCode::OK);
        let begun=user_call(&f,"begin",json!({"operationId":Uuid::new_v4(),"policy":policy}),true).await?;
        ensure!(begun.0==StatusCode::OK);
        let bound=user_call(&f,"confirm",json!({"operationId":Uuid::new_v4(),"challenge":begun.1["id"],"nonce":begun.1["nonce"],"localSession":begun.1["localSession"]}),true).await?;
        ensure!(bound.0==StatusCode::OK);
        let offered=offer(&f,&c,&registration).await?;let task=offered.1["task"].clone();
        for kind in ["received","start"] {ensure!(event(&f,&task,&c,&registration,json!({"kind":kind})).await?.0==StatusCode::OK);}
        let spec=&task["payload"]["task"];
        let result=json!({"kind":"device_access_result","bindingId":spec["bindingId"],"bindingGeneration":spec["bindingGeneration"],"revision":spec["revision"],"definitionDigest":spec["definitionDigest"],"effect":{"state":"applied","account":{"platform":"macos","generatedUid":account},"role":"standard","mac":{"passwordSync":"unknown","keychainSync":"unknown","secureToken":"present","volumeOwner":"unknown","filevaultUnlock":"unknown"}}});
        ensure!(event(&f,&task,&c,&registration,result).await?.0==StatusCode::OK);
        let scope=Uuid::new_v4();f.scope(scope,json!([{"kind":"device","id":execution::case_device_id()}])).await?;
        let exit=Uuid::new_v4();let path=format!("/api/v1/policies/{exit}");
        execution::post(&mut f.author,&f.router,&path,json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":scope,"action":{"kind":"unmanage_device","runLifetimeSeconds":300}}}})).await?;
        let now=crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
        execution::post(&mut f.author,&f.router,&format!("{path}/reruns"),json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"deadline":now+300}})).await?;
        let offered=offer(&f,&c,&registration).await?;let cleanup=offered.1["task"].clone();
        ensure!(cleanup["payload"]["kind"]=="unmanage","cleanup {offered:?}");
        let retired=pg(&format!("SELECT retirement IS NOT NULL FROM mdm_access.devices WHERE tenant_id='{}' AND id='{}'",case_tenant(),execution::case_device_id()))?;
        ensure!(retired.trim()=="t");
        let denied=f.access_call(Method::PUT,&format!("/api/v1/devices/{}/device-access/bindings/{}",execution::case_device_id(),bound.1["id"].as_str().context("binding id")?),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"unbind","disposition":"keep"}}))).await?;
        ensure!(denied.0==StatusCode::FORBIDDEN,"ordinary work crossed retirement {denied:?}");
        for kind in ["received","start"] {ensure!(event(&f,&cleanup,&c,&registration,json!({"kind":kind})).await?.0==StatusCode::OK);}
        ensure!(event(&f,&cleanup,&c,&registration,json!({"kind":"unmanage_result","outcome":"unknown"})).await?.0==StatusCode::OK);
        ensure!(claim(&f,&c).await?.0==StatusCode::OK,"uncertain unmanage must retain communication");
        Ok(())
    }).await
}

fn windows_context() -> Value {
    let mut c = crate::test_support::software_execution::context(
        crate::test_support::software_execution::Platform::Windows,
    );
    c["revision"] = json!(2);
    c["interactiveUser"] = json!({"windowsAuthority":{"kind":"local"},"identity":"S-1-5-21-100-200-300-1001","generatedUid":null,"sessionId":Uuid::from_u128(100),"administrator":false});
    c
}
async fn directory(f: &Fixture, user: bool, query: &str) -> Result<(StatusCode, Value)> {
    let mut r = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/v1/agent/runtime/device-access{query}"))
        .header("host", "mdm.example.test:9445")
        .extension(evidence(execution::case_credential()).unwrap());
    if user {
        r = r.header(
            "x-rss-user-session",
            &f.author.cookies["__Host-identity-session"],
        );
    }
    let response = f.router.clone().oneshot(r.body(Body::empty())?).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&bytes)?))
}
fn pending_binding(
    reply: &(StatusCode, Value),
    id: Uuid,
    account: &wire::AccessAccount,
) -> Result<()> {
    ensure!(reply.0 == StatusCode::OK, "directory failed: {}", reply.0);
    let bindings = reply
        .1
        .get("bindings")
        .and_then(Value::as_array)
        .context("binding list")?;
    let binding = bindings
        .iter()
        .find(|b| b.get("id") == Some(&json!(id)))
        .context("target binding")?;
    ensure!(
        binding.get("account") == Some(&serde_json::to_value(account)?),
        "account mismatch"
    );
    ensure!(
        binding.get("appliedRevision") == Some(&Value::Null),
        "not an explicit pending revision"
    );
    Ok(())
}
fn access_envelope(task: &wire::AccessTaskSpec, sid: &str) -> Result<wire::CredentialEnvelope> {
    use base64::{
        Engine,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use openssl::{encrypt::Encrypter, hash::MessageDigest, pkey::PKey, rsa::Padding};
    let Some(wire::AccessWindowsPlan::Initialize {
        recipient,
        expected_revision,
    }) = &task.windows
    else {
        anyhow::bail!("initialization required")
    };
    let subject = wire::CredentialSubject::RssLogin {
        binding: task.binding_id,
        binding_generation: task.binding_generation,
        sid: sid.into(),
    };
    let aad = task.material_aad(&subject, *expected_revision)?;
    let key = [71; 32];
    let nonce = [19; 12];
    let public = PKey::public_key_from_der(&STANDARD.decode(&recipient.public_key)?)?;
    let mut encrypt = Encrypter::new(&public)?;
    encrypt.set_rsa_padding(Padding::PKCS1_OAEP)?;
    encrypt.set_rsa_oaep_md(MessageDigest::sha256())?;
    encrypt.set_rsa_mgf1_md(MessageDigest::sha256())?;
    let mut wrapped = vec![0; encrypt.encrypt_len(&key)?];
    let size = encrypt.encrypt(&key, &mut wrapped)?;
    wrapped.truncate(size);
    let cipher = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key)
            .map_err(|_| anyhow::anyhow!("test key"))?,
    );
    let mut ciphertext = URL_SAFE_NO_PAD.encode([39; 32]).into_bytes();
    cipher
        .seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::from(aad),
            &mut ciphertext,
        )
        .map_err(|_| anyhow::anyhow!("test encryption"))?;
    Ok(wire::CredentialEnvelope {
        subject,
        expected_revision: *expected_revision,
        wrapped_key: STANDARD.encode(wrapped),
        nonce,
        ciphertext: STANDARD.encode(ciphertext),
    })
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=device-access.http: Windows initialization escrows and applies within one authenticated task"]
async fn windows_first_setup_is_one_recoverable_task() -> Result<()> {
    windows_setup(false, false).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=device-access.http: newly created SID is prepared without prematurely marking applied"]
async fn windows_created_account_is_prepared_before_escrow() -> Result<()> {
    windows_setup(true, false).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=device-access.http: withdrawn initialization settles custody without restoring access"]
async fn windows_withdrawn_setup_settles_only_its_attempt() -> Result<()> {
    windows_setup(false, true).await
}
async fn windows_setup(create: bool, withdraw: bool) -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let (policy,registration) = setup_platform(&mut f,false,true).await?;
        let c = windows_context();
        ensure!(claim(&f,&c).await?.0 == StatusCode::OK);
        ensure!(directory(&f,false, "").await?.0 == StatusCode::UNAUTHORIZED);
        let options = directory(&f,true, "").await?;
        ensure!(options.0 == StatusCode::OK && options.1["policies"].as_array().context("policies")?.iter().any(|p| p["policy"] == policy.to_string()),"directory {options:?}");
        let id = if create {
            let id = Uuid::new_v4();
            let path = format!("/api/v1/devices/{}/device-access/bindings/{id}",execution::case_device_id());
            let reply = f.access_call(Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"action":{"kind":"put","instance":crate::test_support::identity::INSTANCE,"principal":f.author_id,"policy":policy,"account":{"kind":"create","platform":"windows","name":"workuser"}}}))).await?;
            ensure!(reply.0 == StatusCode::OK,"create {reply:?}"); id
        } else {
            let begun = user_call(&f,"begin",json!({"operationId":Uuid::new_v4(),"policy":policy}),true).await?;
            ensure!(begun.0 == StatusCode::OK,"begin {begun:?}");
            let confirm = json!({"operationId":Uuid::new_v4(),"challenge":begun.1["id"],"nonce":begun.1["nonce"],"localSession":begun.1["localSession"]});
            let bound = user_call(&f,"confirm",confirm.clone(),true).await?;
            ensure!(bound.0 == StatusCode::OK,"confirm {bound:?}");
            ensure!(user_call(&f,"confirm",confirm,true).await? == bound);
            serde_json::from_value(bound.1["id"].clone())?
        };
        let offered = offer(&f,&c,&registration).await?.1["task"].clone();
        ensure!(event(&f,&offered,&c,&registration,json!({"kind":"received"})).await?.0 == StatusCode::OK);
        let start = event(&f,&offered,&c,&registration,json!({"kind":"start"})).await?;
        ensure!(start.0 == StatusCode::OK,"start {start:?}");
        let signed: wire::SignedTask = serde_json::from_value(start.1["permit"].clone())?;
        let wire::TaskPayload::DeviceAccess(task) = &signed.payload else { anyhow::bail!("access task") };
        let sid = if create { "S-1-5-21-100-200-300-1002" } else { "S-1-5-21-100-200-300-1001" };
        let account = wire::AccessAccount::Windows { sid:sid.into(), authority: rss_mdm_agent_wire::runtime::AccessWindowsAuthority::Local };
        let envelope = access_envelope(task,sid)?;
        let escrow = wire::TaskEvent::CredentialEscrow(wire::CredentialEscrow { definition_digest:task.definition_digest,materials:vec![envelope] });
        if create { ensure!(!event(&f,&offered,&c,&registration,serde_json::to_value(&escrow)?).await?.0.is_success()); }
        let prepared = wire::TaskEvent::DeviceAccessPrepared(wire::AccessPrepared { binding_id:id,binding_generation:task.binding_generation,revision:task.revision,definition_digest:task.definition_digest,account:account.clone() });
        let p = event(&f,&offered,&c,&registration,serde_json::to_value(&prepared)?).await?;
        ensure!(p.0 == StatusCode::OK,"prepared {p:?}");
        let pending = directory(&f,true, "").await?;
        pending_binding(&pending,id,&account)?;
        ensure!(pending_binding(&(StatusCode::OK,json!({"bindings":[]})),id,&account).is_err());
        ensure!(pending_binding(&(StatusCode::OK,json!({"bindings":[{"id":id,"account":account}]})),id,&account).is_err());
        let path = format!("/api/v1/agent/runtime/tasks/{}/events",task.task_id);
        let input = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"attemptId":task.attempt_id,"executionContext":c,"event":escrow});
        let ack = agent_call(&f.router,Method::POST,&path,Some(execution::case_credential()),Some(input.clone())).await?;
        ensure!(ack.0 == StatusCode::OK,"escrow {ack:?}");
        ensure!(agent_call(&f.router,Method::POST,&path,Some(execution::case_credential()),Some(input)).await? == ack);
        let ack: wire::TaskEventAck = serde_json::from_value(ack.1)?;
        ensure!(ack.credentials().len() == 1);
        let receipt = ack.credentials()[0].clone();
        pending_binding(&directory(&f,true, "").await?,id,&account)?;
        let result = wire::AccessResult { binding_id:id,binding_generation:task.binding_generation,revision:task.revision,definition_digest:task.definition_digest,
            effect:wire::AccessEffect::Applied { account:account.clone(),role:wire::AccessRole::Standard,mac:None,
                windows:Some(wire::AccessWindowsFacts { factor_generation:task.factor_generation,recovery:receipt.clone() }) } };
        let mut wrong = result.clone();
        if let wire::AccessEffect::Applied { windows:Some(facts),.. } = &mut wrong.effect { facts.recovery.version += 1; }
        ensure!(!event(&f,&offered,&c,&registration,serde_json::to_value(wire::TaskEvent::DeviceAccessResult(wrong))?).await?.0.is_success());
        if withdraw {
            let path = format!("/api/v1/devices/{}/device-access/bindings/{id}",execution::case_device_id());
            let reply = f.access_call(Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"unbind","disposition":"keep"}}))).await?;
            ensure!(reply.0 == StatusCode::OK,"unbind {reply:?}");
        }
        let done = event(&f,&offered,&c,&registration,serde_json::to_value(wire::TaskEvent::DeviceAccessResult(result))?).await?;
        ensure!(done.0 == StatusCode::OK,"applied {done:?}");
        if withdraw {
            let state = directory(&f,true, "").await?;
            ensure!(state.1["bindings"][0]["revoked"] == true && state.1["bindings"][0]["appliedRevision"].is_null());
            let pending = pg(&format!("SELECT count(*) FROM mdm_recovery.versions WHERE tenant_id='{}' AND operation='{}' AND pending",case_tenant(),task.task_id))?;
            ensure!(pending.trim() == "0","withdrawn task left pending materials: {pending}");
            let unbind = offer(&f,&c,&registration).await?.1["task"].clone();
            for kind in ["received","start"] { ensure!(event(&f,&unbind,&c,&registration,json!({"kind":kind})).await?.0 == StatusCode::OK); }
            let spec=&unbind["payload"]["task"];
            let mut cleared=json!({"kind":"device_access_result","bindingId":id,"bindingGeneration":spec["bindingGeneration"],"revision":spec["revision"],"definitionDigest":spec["definitionDigest"],"effect":{"state":"unknown"}});
            ensure!(event(&f,&unbind,&c,&registration,cleared.clone()).await?.0 == StatusCode::OK);
            let retained=pg(&format!("SELECT count(*) FROM mdm_recovery.versions WHERE tenant_id='{}' AND operation='{}' AND invalidated_at IS NULL AND sealed IS NOT NULL",case_tenant(),task.task_id))?;
            ensure!(retained.trim() == "1","Unknown must retain material");
            cleared["effect"]=json!({"state":"unbound","disposition":"keep"});
            ensure!(event(&f,&unbind,&c,&registration,cleared).await?.0 == StatusCode::OK);
            verify_unbound_retention(&f.base,&receipt).await?;
            return Ok(());
        }
        let ready = directory(&f,true, "").await?;
        ensure!(ready.1["bindings"][0]["appliedRevision"] == 1 && ready.1["policies"] == json!([]));
        // An ordinary configuration update preserves both identity and factors.
        let path = format!("/api/v1/devices/{}/device-access/bindings/{id}",execution::case_device_id());
        let changed = f.access_call(Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"put","instance":crate::test_support::identity::INSTANCE,"principal":f.author_id,"policy":policy,"account":{"kind":"existing","account":account}}}))).await?;
        ensure!(changed.0 == StatusCode::OK && changed.1["bindingGeneration"] == 1 && changed.1["factorGeneration"] == 1,"configure {changed:?}");
        let preserved = offer(&f,&c,&registration).await?.1["task"].clone();
        ensure!(preserved["payload"]["task"]["windows"]["kind"] == "preserve");
        let reset = f.access_call(Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":2,"action":{"kind":"reset_factors"}}))).await?;
        ensure!(reset.0 == StatusCode::OK && reset.1["bindingGeneration"] == 1 && reset.1["factorGeneration"] == 2,"reset {reset:?}");
        ensure!(event(&f,&preserved,&c,&registration,json!({"kind":"start"})).await?.0 == StatusCode::FORBIDDEN);
        Ok(())
    }).await
}

async fn verify_unbound_retention(base: &Value, receipt: &wire::CredentialReceipt) -> Result<()> {
    use rss_mdm_recovery_credentials::storage;
    use sqlx::Connection;
    let config: crate::config::Config = serde_json::from_value(base.clone())?;
    let mut connection = sqlx::PgConnection::connect_with(&config.access_options()?).await?;
    let mut c = connection.begin().await?;
    let tenant = Uuid::parse_str(case_tenant())?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *c)
        .await?;
    let invalidated:bool=sqlx::query_scalar("SELECT invalidated_at IS NOT NULL AND NOT pending AND sealed IS NOT NULL FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2 AND version=$3")
        .bind(tenant).bind(receipt.material).bind(receipt.version).fetch_one(&mut *c).await?;
    ensure!(invalidated, "native Unbound must start retention");
    ensure!(
        !storage::expired_in(&mut c, tenant)
            .await?
            .iter()
            .any(|m| m.id == receipt.material && m.version == receipt.version)
    );
    sqlx::query("UPDATE mdm_recovery.versions SET invalidated_at=floor(extract(epoch FROM clock_timestamp()))::bigint-7776001 WHERE tenant_id=$1 AND entry=$2 AND version=$3")
        .bind(tenant).bind(receipt.material).bind(receipt.version).execute(&mut *c).await?;
    ensure!(
        storage::expired_in(&mut c, tenant)
            .await?
            .iter()
            .any(|m| m.id == receipt.material && m.version == receipt.version)
    );
    storage::clear_expired_in(&mut c, tenant, receipt.material, receipt.version).await?;
    let erased:bool=sqlx::query_scalar("SELECT sealed IS NULL AND key_id IS NULL FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2 AND version=$3")
        .bind(tenant).bind(receipt.material).bind(receipt.version).fetch_one(&mut *c).await?;
    ensure!(erased, "expired material must be erased");
    c.commit().await?;
    connection.close().await?;
    Ok(())
}

// Exercise real HTTP and WebAuthn cryptography; no test-only proof issuance or SQL bypass.
impl Fixture {
    pub(crate) async fn access_call(
        &mut self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value)> {
        if let Some(response) = self.access_authorize(path, body.clone()).await? {
            return Ok(response);
        }
        self.author.call(&self.router, method, path, body).await
    }
    pub(crate) async fn access_authorize(
        &mut self,
        path: &str,
        body: Option<Value>,
    ) -> Result<Option<(StatusCode, Value)>> {
        use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
        let origin = url::Url::parse("https://mdm.example.test")?;
        let identity = format!("/api/v1/identity/tenants/{}/webauthn", case_tenant());
        if self.access_authenticator.is_none() {
            let mut key = WebauthnAuthenticator::new(SoftPasskey::new(true));
            self.author.cookies.remove("__Host-identity-operation");
            let (status, start) = self
                .author
                .call(
                    &self.router,
                    Method::POST,
                    &format!("{identity}/register/begin"),
                    Some(json!({"label":"DA test authenticator","recover":false})),
                )
                .await?;
            ensure!(
                status == StatusCode::OK,
                "registration begin {status}: {start}"
            );
            let response = key.do_registration(
                origin.clone(),
                serde_json::from_value(start["options"].clone())?,
            )?;
            let (status, result) = self
                .author
                .call(
                    &self.router,
                    Method::POST,
                    &format!("{identity}/register/finish"),
                    Some(json!({"id":start["id"],"response":response})),
                )
                .await?;
            ensure!(
                status == StatusCode::OK,
                "registration finish {status}: {result}"
            );
            self.access_authenticator = Some(key);
        }
        let (status, start) = self
            .author
            .call(
                &self.router,
                Method::POST,
                &format!("{path}/step-up"),
                body.clone(),
            )
            .await?;
        if status != StatusCode::OK {
            return Ok(Some((status, start)));
        }
        let response = self
            .access_authenticator
            .as_mut()
            .context("registered authenticator")?
            .do_authentication(origin, serde_json::from_value(start["options"].clone())?)?;
        let (status, result) = self
            .author
            .call(
                &self.router,
                Method::POST,
                &format!("{identity}/authenticate/finish"),
                Some(json!({"id":start["id"],"response":response})),
            )
            .await?;
        ensure!(
            status == StatusCode::OK,
            "authentication finish {status}: {result}"
        );
        Ok(None)
    }
}

#[tokio::test]
#[ignore = "MODULE=device-access.http: operation proof concurrency, replay and rollback"]
async fn step_up_is_atomic_with_receipts_and_concurrent_duplicates() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let (policy, _) = setup(&mut f).await?;
        let id = Uuid::new_v4();
        let path = format!("/api/v1/devices/{}/device-access/bindings/{id}", execution::case_device_id());
        let input = json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"action":{"kind":"put","instance":crate::test_support::identity::INSTANCE,"principal":f.author_id,"policy":policy,"account":{"kind":"existing","account":{"platform":"macos","generatedUid":Uuid::new_v4()}}}});
        ensure!(f.access_authorize(&path, Some(input.clone())).await?.is_none());
        let first = f.author.clone();
        let duplicate = first.clone();
        let (a,b)=concurrent_access_calls(&f.router,first,duplicate,Method::PUT,&path,input.clone()).await?;
        ensure!(a.0==StatusCode::OK && b==a,"same proof concurrent: {a:?} {b:?}");
        f.author.cookies.remove("__Host-identity-operation");
        ensure!(f.author.call(&f.router,Method::PUT,&path,Some(input.clone())).await?==a,"committed retry must not require another proof");
        let mut changed=input.clone();changed["action"]["account"]["account"]["generatedUid"]=json!(Uuid::new_v4());
        ensure!(f.author.call(&f.router,Method::PUT,&path,Some(changed)).await?.0==StatusCode::CONFLICT);
        let next=json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"unbind","disposition":"disable"}});
        ensure!(f.access_authorize(&path,Some(next.clone())).await?.is_none());
        let one=f.author.clone();
        ensure!(f.access_authorize(&path,Some(next.clone())).await?.is_none());
        let two=f.author.clone();
        let before=pg(&format!("SELECT count(*) FROM identity_authority.step_up_grants WHERE tenant_id='{}' AND principal_id='{}'",case_tenant(),f.author_id))?.trim().parse::<i64>()?;
        let (a,b)=concurrent_access_calls(&f.router,one,two,Method::PUT,&path,next.clone()).await?;
        ensure!(a.0==StatusCode::OK && b==a,"different proofs concurrent: {a:?} {b:?}");
        let after=pg(&format!("SELECT count(*) FROM identity_authority.step_up_grants WHERE tenant_id='{}' AND principal_id='{}'",case_tenant(),f.author_id))?.trim().parse::<i64>()?;
        ensure!(before-after==1,"duplicate operation consumed an extra proof");
        ensure!(a.1["accountDisposition"]=="disable" && a.1["appliedRevision"].is_null());
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=device-access.http: HTTP binding commit holds Identity guard through business settlement"]
async fn binding_commit_serializes_session_revocation() -> Result<()> {
    binding_settlement_serializes_revocation(false).await
}

#[tokio::test]
#[ignore = "MODULE=device-access.http: failed confirmation rolls back and releases Identity guard"]
async fn binding_rollback_releases_session_guard() -> Result<()> {
    binding_settlement_serializes_revocation(true).await
}

async fn binding_settlement_serializes_revocation(wrong_nonce: bool) -> Result<()> {
    use sqlx::{Connection, PgConnection};
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let (policy, _) = setup(&mut f).await?;
        ensure!(claim(&f, &context(2, Uuid::new_v4(), Uuid::new_v4())).await?.0 == StatusCode::OK);
        let started = user_call(&f, "begin", json!({"operationId":Uuid::new_v4(),"policy":policy}), true).await?;
        ensure!(started.0 == StatusCode::OK, "begin {started:?}");
        let challenge: Uuid = serde_json::from_value(started.1["id"].clone())?;
        let operation = Uuid::new_v4();
        let input = json!({"operationId":operation,"challenge":challenge,
            "nonce":if wrong_nonce { Value::String("A".repeat(43)) } else { started.1["nonce"].clone() },
            "localSession":started.1["localSession"]});
        let (identity, identity_resources) = crate::test_support::identity::identity(case_tenant()).await?;
        identity_resources.finish(async {
            let session = identity.authority.inspect_session(identity.tenant,
                rss_identity_core::session::SessionSecret::parse(f.author.cookies["__Host-identity-session"].clone())?,
                crate::identity::deadline()).await?;
            let options = crate::device::test_support::options("postgres")?;
            let mut root = PgConnection::connect_with(&options).await?;
            let mut observer = PgConnection::connect_with(&options).await?;
            let mut hold = root.begin().await?;
            let blocker:i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *hold).await?;
            sqlx::query("SELECT id FROM mdm_access.device_access_ceremonies WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
                .bind(case_tenant()).bind(challenge).fetch_one(&mut *hold).await?;
            let router = f.router.clone();
            let token = f.author.cookies["__Host-identity-session"].clone();
            let confirm = tokio::spawn(async move {
                let request = Request::builder().method(Method::POST)
                    .uri("/api/v1/agent/runtime/device-access/confirm")
                    .header("host", "mdm.example.test:9445").header("content-type", "application/json")
                    .header("x-rss-user-session", token)
                    .extension(evidence(execution::case_credential()).unwrap())
                    .body(Body::from(serde_json::to_vec(&input)?))?;
                let response = router.oneshot(request).await?;
                let status = response.status();
                let bytes = response.into_body().collect().await?.to_bytes();
                Ok::<_,anyhow::Error>((status, serde_json::from_slice::<Value>(&bytes)?))
            });
            let waiting = wait_sql_blocker(&mut observer, blocker, "%FROM mdm_access.device_access_ceremonies%FOR UPDATE%").await;
            let revoke = if let Ok(consumer) = waiting.as_ref() {
                let authority = identity.authority.clone();
                let task = tokio::spawn(async move { authority.revoke_current_session(session,crate::identity::deadline()).await });
                let blocked = wait_sql_blocker(&mut observer,*consumer,"%FROM identity_authority.guard%FOR UPDATE%").await;
                Some((task, blocked))
            } else { None };
            // Always release the fixture lock before propagating failures or joining requests.
            hold.rollback().await?;
            let result = confirm.await??;
            let revoked = match revoke {
                Some((task, blocked)) => { let result=task.await?; blocked?; result?; true },
                None => false,
            };
            waiting?;
            ensure!(revoked);
            let consumed:bool=sqlx::query_scalar("SELECT consumed IS NOT NULL FROM mdm_access.device_access_ceremonies WHERE tenant_id=$1::uuid AND id=$2")
                .bind(case_tenant()).bind(challenge).fetch_one(&mut observer).await?;
            let receipt:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_access.registration_operations WHERE tenant_id=$1::uuid AND operation_id=$2)")
                .bind(case_tenant()).bind(operation).fetch_one(&mut observer).await?;
            ensure!(consumed != wrong_nonce && receipt != wrong_nonce, "settlement {result:?}");
            if wrong_nonce { ensure!(!result.0.is_success(),"wrong nonce accepted"); }
            else { ensure!(result.0==StatusCode::OK,"confirm {result:?}"); }
            let mut guard=observer.begin().await?;
            sqlx::query("SET LOCAL lock_timeout='1s'").execute(&mut *guard).await?;
            sqlx::query("SELECT tenant_id FROM identity_authority.guard WHERE tenant_id=$1::uuid FOR UPDATE")
                .bind(case_tenant()).fetch_one(&mut *guard).await?;
            guard.rollback().await?;
            ensure!(user_call(&f,"begin",json!({"operationId":Uuid::new_v4(),"policy":policy}),true).await?.0==StatusCode::UNAUTHORIZED);
            observer.close().await?; root.close().await?;
            Ok(())
        }).await
    }).await
}
async fn wait_sql_blocker(c: &mut sqlx::PgConnection, blocker: i32, query: &str) -> Result<i32> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let pid:Option<i32>=sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND query LIKE $2 AND $1=ANY(pg_blocking_pids(pid)) LIMIT 1")
                .bind(blocker).bind(query).fetch_optional(&mut *c).await?;
            if let Some(pid)=pid {return Ok::<_,anyhow::Error>(pid);}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.context("expected real transaction blocker relationship")?
}

#[path = "device_access/enterprise.rs"]
mod enterprise;

#[path = "device_access/lifecycle.rs"]
mod lifecycle;
mod queries;

/// Observe both requests competing before releasing the actual product publication fence.
async fn concurrent_access_calls(
    router: &Router,
    mut first: Browser,
    mut second: Browser,
    method: Method,
    path: &str,
    input: Value,
) -> Result<((StatusCode, Value), (StatusCode, Value))> {
    use sqlx::Connection;
    let options = crate::device::test_support::options("postgres")?;
    let mut root = sqlx::PgConnection::connect_with(&options).await?;
    let mut observer = sqlx::PgConnection::connect_with(&options).await?;
    let mut hold = root.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *hold)
        .await?;
    sqlx::query("SELECT mdm.lock_asset_watermark($1::uuid)")
        .bind(case_tenant())
        .execute(&mut *hold)
        .await?;
    let root_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *hold)
        .await?;
    let (router_a, path_a, method_a, input_a) = (
        router.clone(),
        path.to_owned(),
        method.clone(),
        input.clone(),
    );
    let a = tokio::spawn(async move {
        first
            .call(&router_a, method_a, &path_a, Some(input_a))
            .await
    });
    let waiting = wait_sql_blocker(&mut observer, root_pid, "%lock_asset_watermark%").await;
    let (router_b, path_b) = (router.clone(), path.to_owned());
    let b = tokio::spawn(async move { second.call(&router_b, method, &path_b, Some(input)).await });
    let competing = match &waiting {
        Ok(pid) => wait_sql_blocker(&mut observer, *pid, "%identity_authority.guard%FOR UPDATE%")
            .await
            .map(|_| ()),
        Err(_) => Ok(()),
    };
    hold.rollback().await?;
    let (a, b) = (a.await??, b.await??);
    waiting?;
    competing?;
    root.close().await?;
    observer.close().await?;
    Ok((a, b))
}
