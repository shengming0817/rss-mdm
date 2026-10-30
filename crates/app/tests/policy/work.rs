//! Real Policy worker fencing, partial progress and transaction provenance.
use super::events::{batch_path, endpoint, get, policy, request, setup};
use crate::test_support::{agent_execution::*, process::pg, runtime::case_tenant, *};
use rss_reconcile::{Completion, DurableStore};

fn state(batch: Uuid) -> Result<Value> {
    Ok(serde_json::from_str(&pg(&format!(
        "SELECT jsonb_build_object('members',(SELECT jsonb_agg(jsonb_build_array(id,decision) ORDER BY id) FROM mdm_policy.event_members WHERE tenant_id='{tenant}' AND batch='{batch}'),'work',(SELECT jsonb_build_array(completed,cursor,failure) FROM mdm_policy.work WHERE tenant_id='{tenant}' AND id='{batch}'),'runs',(SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{tenant}'))",
        tenant = case_tenant()
    ))?)?)
}
fn definitions(ids: &[Uuid]) -> Result<Value> {
    let ids = ids
        .iter()
        .map(|id| format!("'{id}'"))
        .collect::<Vec<_>>()
        .join(",");
    Ok(serde_json::from_str(&pg(&format!(
        "SELECT jsonb_agg(jsonb_build_array(p.id,p.definition,p.revision,p.current_version,v.frozen) ORDER BY p.id) FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id='{}' AND p.id IN ({ids})",
        case_tenant()
    ))?)?)
}
#[tokio::test]
#[ignore = "make t2 MODULE=policy.work"]
async fn expired_claim_and_wrong_runtime_cannot_advance_members_and_restart_keeps_original_ids()
-> Result<()> {
    let mut f = setup().await?;
    let scheduler = crate::scheduler::SchedulerStorage::open(
        crate::device::test_support::options("mdm_scheduler_runtime")?.password("runtime-fixture"),
    )
    .await?;
    f.resources.resource(scheduler.clone());
    let mut resources = std::mem::take(&mut f.resources);
    let other = crate::planning::test_support::owner(
        f.planning.policy.audit_store.clone(),
        f.planning.tenant,
        "mdm_policy_runtime",
        &mut resources,
    )
    .await;
    resources.finish(async {
        let(resource,_,_)=f.resource().await?;
        let first=policy(&mut f,resource,"worker_fencing",case_task_scope()).await?;
        let second=policy(&mut f,resource,"worker_fencing",case_task_scope()).await?;
        let before_definition=definitions(&[first,second])?;
        let input=request("worker_fencing");
        let batch=post(&mut f.author,&f.router,&endpoint(),input.clone()).await?;
        let id=Uuid::parse_str(batch["batchId"].as_str().unwrap())?;
        ensure!(batch["members"]==2,"two real members required: {batch}");
        let work=rss_mdm_policy_service::worker::PolicyWork::new(f.planning.policy.clone(),f.events.clone(),scheduler.store.clone());
        let timer=rss_mdm_policy_service::clock::Timer::new();let cancel=tokio_util::sync::CancellationToken::new();
        let control=rss_reconcile::Control::new(&timer,Duration::from_secs(120),&cancel);
        let target=rss_mdm_policy_service::worker::jobs::event_target(f.planning.tenant,id);
        work.wake(&target,&control).await?;
        let scope=rss_reconcile::Scope::new(f.planning.tenant,rss_mdm_policy_service::worker::jobs::EVENT_SCOPE)?;
        let old=work.claim_due(&scope,1,Duration::from_secs(300),&control).await?.pop().ok_or_else(||anyhow::anyhow!("missing event claim"))?;
        ensure!(work.claim_due(&scope,1,Duration::from_secs(300),&control).await?.is_empty(),"unexpired claim was stolen");
        pg(&format!("UPDATE rss_reconcile.targets SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id='{}' AND reconciler='mdm.policy-events' AND entity='event:{id}' AND epoch={}",case_tenant(),old.epoch()))?;
        let current=work.claim_due(&scope,1,Duration::from_secs(300),&control).await?.pop().ok_or_else(||anyhow::anyhow!("expired event was not reclaimable"))?;
        ensure!(current.epoch()>old.epoch());
        let before=state(id)?;
        let audit_before=crate::audit_test_support::audit_count(|r|r.action()=="policy_event_member").await?;
        let observed=work.observe(&old,&control).await?;
        ensure!(work.apply(&old,observed,&control).await.unwrap_err().kind()==rss_reconcile::ErrorKind::Fenced);
        ensure!(work.finish(&old,Completion::Suspended{failures:1},&control).await.unwrap_err().kind()==rss_reconcile::ErrorKind::Fenced);
        ensure!(state(id)?==before,"stale worker changed business state");

        let participant=Arc::new(rss_mdm_execution_service::policy_events::PolicyEvents::bind(other.runtime.clone(),f.planning.tenant,other.audit,f.materials.clone()).await?);
        let wrong=Arc::new(rss_mdm_policy_service::events::Events{application:f.planning.policy.clone(),execution:participant});
        let wrong_work=rss_mdm_policy_service::worker::PolicyWork::new(f.planning.policy.clone(),wrong,scheduler.store.clone());
        let observed=wrong_work.observe(&current,&control).await?;
        ensure!(wrong_work.apply(&current,observed,&control).await.is_err(),"an unrelated runtime was accepted");
        ensure!(state(id)?==before,"wrong-runtime attempt partially committed");

        ensure!(crate::audit_test_support::audit_count(|r|r.action()=="policy_event_member").await?==audit_before);
        work.apply(&current,work.observe(&current,&control).await?,&control).await?;
        let partial=state(id)?;
        ensure!(partial["members"].as_array().unwrap().iter().filter(|r|r[1]["state"]=="accepted").count()==1,"first step must commit exactly one member: {partial}");
        work.release(&current,&control).await?;
        drop(work);
        let resumed=rss_mdm_policy_service::worker::PolicyWork::new(f.planning.policy.clone(),f.events.clone(),scheduler.store.clone());
        let claim=resumed.claim_due(&scope,1,Duration::from_secs(300),&control).await?.pop().ok_or_else(||anyhow::anyhow!("partial event was not recoverable"))?;
        for _ in 0..2 {resumed.apply(&claim,resumed.observe(&claim,&control).await?,&control).await?;}
        resumed.finish(&claim,Completion::Converged,&control).await?;
        let completed=state(id)?;
        ensure!(completed["work"][0]==true && completed["members"].as_array().unwrap().iter().all(|r|r[1]["state"]=="accepted"),"{completed}");
        ensure!(completed["members"][0][0]==before["members"][0][0] && completed["members"][1][0]==before["members"][1][0]);
        ensure!(run_count(first)?.trim()=="1" && run_count(second)?.trim()=="1");
        ensure!(crate::audit_test_support::audit_count(|r|r.action()=="policy_event_member").await?==audit_before+2);
        ensure!(definitions(&[first,second])?==before_definition,"worker rewrote authored publication");
        ensure!(post(&mut f.author,&f.router,&endpoint(),input).await?==batch);
        ensure!(get(&mut f,&batch_path(&batch)).await?["id"]==batch["batchId"]);
        Ok(())
    }).await
}
