//! Server HTTP/PG evidence using authenticated native observations; no Windows execution.
use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=device-access.http: Hello has no escrow and pending enrollment/retirement is recoverable"]
async fn native_hello_configuration_registration_and_retirement_are_distinct() -> Result<()> {
    let mut f = fixture().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let worker = crate::test_support::software_execution::worker(&f.base, f.execution.clone()).await?;
        let outcome = async {
            let (policy, registration) = setup_mechanism(&mut f, false, true, true).await?;
            let c = hello_context();
            ensure!(claim(&f, &c).await?.0 == StatusCode::OK);
            let begun = user_call(&f, "begin", json!({"operationId":Uuid::new_v4(),"policy":policy}), true).await?;
            ensure!(begun.0 == StatusCode::OK, "begin {begun:?}");
            let bound = user_call(&f, "confirm", json!({"operationId":Uuid::new_v4(),"challenge":begun.1["id"],"nonce":begun.1["nonce"],"localSession":begun.1["localSession"]}), true).await?;
            ensure!(bound.0 == StatusCode::OK, "confirm {bound:?}");
            let id: Uuid = serde_json::from_value(bound.1["id"].clone())?;
            let offered = offer(&f, &c, &registration).await?.1["task"].clone();
            for kind in ["received", "start"] {
                ensure!(event(&f,&offered,&c,&registration,json!({"kind":kind})).await?.0 == StatusCode::OK);
            }
            let signed: wire::SignedTask = serde_json::from_value(offered.clone())?;
            let wire::TaskPayload::DeviceAccess(task) = signed.payload else { anyhow::bail!("access task"); };
            ensure!(matches!(task.windows, Some(wire::AccessWindowsPlan::Whfb { retire:false, .. })));
            let wire::AccessAction::Apply { account, .. } = &task.action else { anyhow::bail!("apply"); };
            let mut facts = wire::AccessWhfbFacts {
                factor_generation: task.factor_generation, tenant_id:Uuid::from_u128(40), object_id:Uuid::from_u128(41),
                policy:wire::AccessObservation::Present, registration:wire::AccessObservation::Absent,
                hardware_key:wire::AccessObservation::Unknown, key_id:None, observed_at:crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?,
            };
            let report = |facts| wire::TaskEvent::DeviceAccessResult(wire::AccessResult {
                binding_id:id,binding_generation:task.binding_generation,revision:task.revision,definition_digest:task.definition_digest,
                effect:wire::AccessEffect::Applied { account:account.clone(),role:wire::AccessRole::Standard,mac:None,windows:Some(wire::AccessWindowsFacts::Whfb(facts)) },
            });
            let pending = event(&f,&offered,&c,&registration,serde_json::to_value(report(facts.clone()))?).await?;
            ensure!(pending.0 == StatusCode::OK, "pending {pending:?}");
            let path = format!("/api/v1/devices/{}/device-access/bindings/{id}",execution::case_device_id());
            let state = f.author.call(&f.router,Method::GET,&path,None).await?;
            ensure!(state.0 == StatusCode::OK && state.1["appliedRevision"].is_null(), "pending state {state:?}");
            facts.registration=wire::AccessObservation::Present; facts.hardware_key=wire::AccessObservation::Present; facts.key_id=Some(Uuid::from_u128(42));
            let mut wrong=facts.clone(); wrong.object_id=Uuid::from_u128(99);
            ensure!(!event(&f,&offered,&c,&registration,serde_json::to_value(report(wrong))?).await?.0.is_success());
            let done=event(&f,&offered,&c,&registration,serde_json::to_value(report(facts.clone()))?).await?;
            ensure!(done.0==StatusCode::OK,"native configured {done:?}");
            let state=f.author.call(&f.router,Method::GET,&path,None).await?;
            ensure!(state.1["appliedRevision"]==1,"applied {state:?}");
            let custody=pg(&format!("SELECT count(*) FROM mdm_recovery.versions WHERE tenant_id='{}' AND operation='{}'",case_tenant(),task.task_id))?;
            ensure!(custody.trim()=="0","Hello must not create RSS recovery material");
            let unbind=f.access_call(Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"unbind","disposition":"keep"}}))).await?;
            ensure!(unbind.0==StatusCode::OK,"unbind {unbind:?}");
            let cleanup=offer(&f,&c,&registration).await?.1["task"].clone();
            for kind in ["received","start"] { ensure!(event(&f,&cleanup,&c,&registration,json!({"kind":kind})).await?.0==StatusCode::OK); }
            let spec=&cleanup["payload"]["task"];
            ensure!(spec["windows"]["retire"]==true);
            facts.policy=wire::AccessObservation::Absent;
            let retired=|facts| json!({"kind":"device_access_result","bindingId":id,"bindingGeneration":spec["bindingGeneration"],"revision":spec["revision"],"definitionDigest":spec["definitionDigest"],"effect":{"state":"whfb_retired","account":account,"disposition":"keep","facts":facts}});
            ensure!(event(&f,&cleanup,&c,&registration,retired(facts.clone())).await?.0==StatusCode::OK);
            let state=f.author.call(&f.router,Method::GET,&path,None).await?;
            ensure!(state.1["appliedRevision"]!=state.1["revision"],"policy disable must not complete credential retirement");
            facts.registration=wire::AccessObservation::Absent;facts.hardware_key=wire::AccessObservation::Absent;facts.key_id=None;
            let done=event(&f,&cleanup,&c,&registration,retired(facts)).await?;
            ensure!(done.0==StatusCode::OK,"retired {done:?}");
            let state=f.author.call(&f.router,Method::GET,&path,None).await?;
            ensure!(state.1["appliedRevision"]==state.1["revision"] && state.1["serverState"]=="revoked","retired state {state:?}");
            Ok(())
        }.await;
        outcome.and(crate::test_support::runtime::stop_worker(worker).await)
    }).await
}
