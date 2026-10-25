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
            // An incomplete reset observation cannot erase the previously verified key fence.
            for revision in [1, 2] {
                let reset=f.access_call(Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"action":{"kind":"reset_factors"}}))).await?;
                ensure!(reset.0==StatusCode::OK,"reset {reset:?}");
                let attempt=offer(&f,&c,&registration).await?.1["task"].clone();
                for kind in ["received","start"] { ensure!(event(&f,&attempt,&c,&registration,json!({"kind":kind})).await?.0==StatusCode::OK); }
                let spec=&attempt["payload"]["task"];
                ensure!(spec["windows"]["previousKey"]==Uuid::from_u128(42).to_string(),"last verified key was lost: {spec}");
                let mut observed=facts.clone(); observed.factor_generation=revision+1;
                let result=|effect| json!({"kind":"device_access_result","bindingId":id,"bindingGeneration":spec["bindingGeneration"],"revision":spec["revision"],"definitionDigest":spec["definitionDigest"],"effect":effect});
                let applied=|facts| json!({"state":"applied","account":account,"role":"standard","mac":null,"windows":wire::AccessWindowsFacts::Whfb(facts)});
                ensure!(!event(&f,&attempt,&c,&registration,result(applied(observed.clone()))).await?.0.is_success(),"old key accepted for new generation");
                if revision==1 {
                    observed.registration=wire::AccessObservation::Absent; observed.hardware_key=wire::AccessObservation::Unknown; observed.key_id=None;
                    ensure!(event(&f,&attempt,&c,&registration,result(applied(observed))).await?.0==StatusCode::OK);
                    ensure!(event(&f,&attempt,&c,&registration,result(json!({"state":"failed","reason":"needs_user"}))).await?.0==StatusCode::OK);
                } else {
                    observed.key_id=Some(Uuid::from_u128(43));
                    ensure!(event(&f,&attempt,&c,&registration,result(applied(observed.clone()))).await?.0==StatusCode::OK);
                    facts=observed;
                }
            }
            // Publishing a new mechanism cannot use reset_factors as an implicit migration.
            let current=f.author.call(&f.router,Method::GET,&format!("/api/v1/policies/{policy}"),None).await?;
            let mut definition=current.1["definition"].clone(); definition["action"]["windows"]=json!({"kind":"rss_factor","accounts":["entra"]});
            execution::post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":current.1["revision"],"input":{"action":"put","enabled":true,"definition":definition}})).await?;
            ensure!(f.access_call(Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":3,"action":{"kind":"reset_factors"}}))).await?.0==StatusCode::CONFLICT);
            f.author=crate::test_support::authority::Authority::prepared_browser("admin")?; f.access_authenticator=None;
            let operator=prepared_subject(&f.author)?;
            let mut grants=f.grants.clone(); grants.push(crate::authorization::Grant{operation:crate::authorization::Permission::IdentityAccountsManage,scope:crate::authorization::Scope::Tenant});
            crate::test_support::identity::seed_grants(case_tenant(),&operator,grants).await?;
            f.author=crate::test_support::authority::Authority::prepared_browser("admin")?;
            let offboarding=Uuid::new_v4();
            let progress_path=format!("/api/v1/devices/{}/device-access/operations/{offboarding}/offboarding",execution::case_device_id());
            let unbind=f.access_call(Method::PUT,&path,Some(json!({"operationId":offboarding,"expectedRevision":3,"action":{"kind":"offboard","disposition":"keep"}}))).await?;
            ensure!(unbind.0==StatusCode::OK,"unbind {unbind:?}");
            let replacement=Uuid::new_v4();
            let replacement_path=format!("/api/v1/devices/{}/device-access/bindings/{replacement}",execution::case_device_id());
            let replacement_action=json!({"kind":"put","instance":INSTANCE,"principal":operator,"policy":policy,"account":{"kind":"existing","account":account}});
            ensure!(f.access_call(Method::PUT,&replacement_path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"action":replacement_action}))).await?.0==StatusCode::CONFLICT);
            let cleanup=offer(&f,&c,&registration).await?.1["task"].clone();
            for kind in ["received","start"] { ensure!(event(&f,&cleanup,&c,&registration,json!({"kind":kind})).await?.0==StatusCode::OK); }
            let spec=&cleanup["payload"]["task"];
            ensure!(spec["windows"]["retire"]==true);
            facts.factor_generation=spec["factorGeneration"].as_i64().context("retirement factor generation")?;
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
            let progress=f.author.call(&f.router,Method::GET,&progress_path,None).await?;
            ensure!(progress.0==StatusCode::OK && progress.1["devices"][0]["phase"]=="confirmed","native offboarding progress {progress:?}");
            let replacement=f.access_call(Method::PUT,&replacement_path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"action":replacement_action}))).await?;
            ensure!(replacement.0==StatusCode::OK,"replacement after retirement {replacement:?}");
            Ok(())
        }.await;
        outcome.and(crate::test_support::runtime::stop_worker(worker).await)
    }).await
}
