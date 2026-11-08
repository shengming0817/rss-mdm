use super::*;
#[tokio::test]
#[ignore = "T2: current Script executor qualification is checked between Offer and Start"]
async fn start_rechecks_current_profile_without_creating_another_attempt() -> Result<()> {
    let h = Harness::open().await?;
    let (_, version) = h.policy("script-start").await?;
    let id = h.run(version, "script-start", now() + 300).await?;
    let offer = h.claim().await?;
    assert_eq!(offer.payload.task_id(), id);
    h.event(&offer, w::TaskEvent::Received).await?;
    let input = w::TaskClaimRequest::new(Uuid::new_v4(), vec![], context())?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_agent.bindings SET announcement = $3 WHERE tenant_id = CAST($1 AS uuid) AND device = $2").bind(h.c.tenant.to_string()).bind(h.p.device()).bind(serde_json::to_value(input)?).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(h.event(&offer, w::TaskEvent::Start).await.is_err());
    assert_eq!(h.state(id).await?["execution"], "not_started");
    let restored = w::TaskClaimRequest::new(
        Uuid::new_v4(),
        vec![w::ExecutorProfile::PowerShell7],
        context(),
    )?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_agent.bindings SET announcement = $3 WHERE tenant_id = CAST($1 AS uuid) AND device = $2").bind(h.c.tenant.to_string()).bind(h.p.device()).bind(serde_json::to_value(restored)?).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        h.event(&offer, w::TaskEvent::Start)
            .await?
            .permit()
            .is_some()
    );
    assert_eq!(h.state(id).await?["execution"], "running");
    h.close().await
}
#[tokio::test]
#[ignore = "T2: durable Unknown resource barrier survives service reconstruction and original-attempt late evidence"]
async fn unknown_survives_restart_and_only_original_attempt_can_settle_it() -> Result<()> {
    let mut h = Harness::open().await?;
    let (policy, version) = h.policy("script-unknown").await?;
    let deadline = now() + 15;
    let id = h.run(version, "script-unknown", deadline).await?;
    let offer = h.claim().await?;
    assert_eq!(offer.payload.task_id(), id);
    h.event(&offer, w::TaskEvent::Received).await?;
    h.event(&offer, w::TaskEvent::Start).await?;
    let executed = now();
    tokio::time::sleep(std::time::Duration::from_secs(
        (deadline - now() + 1).max(0) as u64,
    ))
    .await;
    script::transaction::run(
        &h.audit,
        &h.a.resources.storage.runtime,
        h.c.tenant,
        &request(&h.c),
        (&h.a.scripts, id),
        |ctx, tx| Box::pin(async move { script::recovery::recover_one(ctx.0, tx, ctx.1).await }),
    )
    .await?;
    assert_eq!(h.state(id).await?["execution"], "unknown");
    let a = Fixture::open(&h.c, true).await?;
    let (audit, delivery) = delivery(&h.c, &a).await?;
    drop(std::mem::replace(&mut h.delivery, delivery));
    drop(std::mem::replace(&mut h.audit, audit));
    Fixture::close(std::mem::replace(&mut h.a, a)).await?;
    let (other_policy, other_version) = h.policy("script-unknown").await?;
    let target = script::Target {
        device: h.p.device().into(),
    };
    let pending = |resource: &str| {
        let resource = resource.to_owned();
        let target = target.clone();
        script::transaction::inspect(
            &h.a.resources.storage.runtime,
            h.c.tenant,
            (target, resource),
            move |ctx, tx| {
                Box::pin(async move {
                    script::storage::pending_in(
                        tx,
                        other_policy,
                        other_version,
                        &ctx.0,
                        &ctx.1,
                        now(),
                    )
                    .await
                })
            },
        )
    };
    assert!(pending("script-unknown").await?.0);
    assert!(!pending("another-resource").await?.0);
    let blocked = Uuid::new_v4();
    assert!(matches!(
        h.admit(other_version, blocked).await?,
        w::PolicyEventDecision::Rejected { .. }
    ));
    let absent:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_script.runs WHERE tenant_id=$1::uuid AND id=$2) AND NOT EXISTS(SELECT 1 FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$3)").bind(h.c.tenant.to_string()).bind(blocked).bind(format!("script.{blocked}")).fetch_one(&h.c.operator).await?;
    assert!(absent);
    let (_, independent) = h.policy("another-resource").await?;
    assert!(matches!(
        h.admit(independent, Uuid::new_v4()).await?,
        w::PolicyEventDecision::Accepted { .. }
    ));

    let result = w::TaskResult::new(
        Some(0),
        w::OutputQuality::Complete,
        json!({"ok":true}),
        w::TaskDiagnostics::new(
            "private stdout".into(),
            "private stderr".into(),
            1,
            executed,
            None,
        )?,
        executed,
    )?;
    let wrong = w::TaskEventRequest::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        w::TaskEvent::Result(result.clone()),
        context(),
    )?;
    assert!(
        h.delivery
            .event(&h.p, id, &wrong, &request(&h.c))
            .await
            .is_err()
    );
    assert_eq!(h.state(id).await?["execution"], "unknown");
    h.event(&offer, w::TaskEvent::Result(result)).await?;
    assert_eq!(h.state(id).await?["execution"], "succeeded");
    assert!(!pending("script-unknown").await?.0);
    assert!(matches!(
        h.admit(other_version, Uuid::new_v4()).await?,
        w::PolicyEventDecision::Accepted { .. }
    ));

    use rss_mdm_authorization_service::Permission;
    use rss_mdm_management_http::execution::task_reads::{RUNS_SCHEMA, Reads};
    let account =
        h.c.account(&[Permission::PolicyRead, Permission::OperationRead])
            .await?;
    let proof = std::sync::Arc::new(h.c.authenticate(&account).await?);
    let page = RUNS_SCHEMA.page(Some(10), None, 4096)?;
    let codec = rss_mdm_query::cursor::CursorCodec::new(&[3; 32])?;
    let summaries = Reads::runs(
        h.a.task_reads.as_ref(),
        &h.c.read_auth(proof.clone()),
        &h.c.request(&proof)?,
        policy,
        &page,
        &codec,
    )
    .await?;
    assert_eq!(summaries.items.len(), 1);
    let summary = serde_json::to_value(&summaries.items[0])?;
    assert_eq!(summary["kind"], "script");
    assert!(summary["result"].get("output").is_none());
    assert!(summary["result"]["diagnostics"].get("stdout").is_none());
    assert!(summary["result"]["diagnostics"].get("stderr").is_none());
    h.close().await
}

#[tokio::test]
#[ignore = "T2: periodic assignment separates historical success, current trigger evidence and scoped read permission without writes"]
async fn periodic_assignment_keeps_history_separate_from_current_admission() -> Result<()> {
    use rss_mdm_authorization_service::Permission;
    use rss_mdm_management_http::execution::task_reads::Reads;
    let h = Harness::open().await?;
    let result=async {
        let (policy,version)=h.policy("periodic-assignment").await?;
        let task=h.run(version,"periodic-assignment",now()+300).await?;
        let offer=h.claim().await?;
        h.event(&offer,w::TaskEvent::Received).await?;
        h.event(&offer,w::TaskEvent::Start).await?;
        let at=now();
        h.event(&offer,w::TaskEvent::Result(w::TaskResult::new(Some(0),w::OutputQuality::Complete,json!({"ok":true}),w::TaskDiagnostics::new("private stdout".into(),"private stderr".into(),1,at,None)?,at)?)).await?;
        let account=h.c.account(&[Permission::PolicyRead,Permission::InventoryRead,Permission::OperationRead]).await?;
        let proof=std::sync::Arc::new(h.c.authenticate(&account).await?);
        let query=rss_mdm_policy::pages::ASSIGNMENTS_SCHEMA.page(Some(10),None,4096)?;
        let codec=rss_mdm_query::cursor::CursorCodec::new(&[9;32])?;
        let read=||async {
            Ok::<Value,anyhow::Error>(serde_json::to_value(Reads::assignments(h.a.task_reads.as_ref(),&h.c.read_auth(proof.clone()),&h.c.request(&proof)?,policy,&query,&codec).await?)?)
        };
        let first=read().await?;
        assert_eq!(first["items"].as_array().unwrap().len(),1);
        let row=&first["items"][0];
        assert!(row.get("operationIds").is_none());
        assert_eq!(row["taskAdmission"]["state"],"waiting_trigger");
        assert_eq!(row["execution"]["latestRun"]["taskId"],task.to_string());
        assert_eq!(row["execution"]["latestRun"]["state"]["execution"],"succeeded");
        assert_eq!(row["execution"]["currentRecord"]["state"],"unknown");
        assert!(!first.to_string().contains("private stdout"));
        let (d,f):(Value,Value)=sqlx::query_as("SELECT p.definition,v.frozen FROM mdm_policy.policies p JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.id=$2").bind(h.c.tenant.to_string()).bind(policy).fetch_one(&h.c.operator).await?;
        let mut d:rss_mdm_policy::Definition=serde_json::from_value(d)?;
        let script::policy::Published::Execution{mut action,frequency}=serde_json::from_value(f)?;
        let schedule=super::mixed::interval();
        if let rss_mdm_policy::Action::Execution{schedule:s,..}=&mut d.action {*s=schedule.clone();}else{unreachable!()}
        action.input.schedule=schedule;
        let current=super::mixed::publish(&h,policy,2,d,serde_json::to_value(script::policy::Published::Execution{action,frequency})?).await?;
        let before:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_script.runs WHERE tenant_id=$1::uuid),(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid)").bind(h.c.tenant.to_string()).fetch_one(&h.c.operator).await?;
        let next=read().await?;
        assert_eq!(next["items"][0]["taskAdmission"]["state"],"waiting_check_in");
        assert_eq!(next["items"][0]["execution"]["currentRecord"]["state"],"absent");
        assert_eq!(next["items"][0]["execution"]["latestRun"]["versionId"],version.to_string());
        assert_ne!(version,current);
        let restricted=h.c.account(&[Permission::PolicyRead,Permission::InventoryRead]).await?;
        let restricted=std::sync::Arc::new(h.c.authenticate(&restricted).await?);
        let restricted=serde_json::to_value(Reads::assignments(h.a.task_reads.as_ref(),&h.c.read_auth(restricted.clone()),&h.c.request(&restricted)?,policy,&query,&codec).await?)?;
        assert_eq!(restricted["items"][0]["execution"],json!({"kind":"restricted"}));
        assert!(restricted["items"][0]["taskAdmission"].is_null());
        assert_eq!(restricted["items"][0]["availability"],next["items"][0]["availability"]);
        let after:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_script.runs WHERE tenant_id=$1::uuid),(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid)").bind(h.c.tenant.to_string()).fetch_one(&h.c.operator).await?;
        assert_eq!(before,after);
        let mut tx=command::seed_transaction(&h.c).await?;
        sqlx::query("UPDATE mdm_script.runs SET state=jsonb_set(state,'{execution}','\"unknown\"') WHERE tenant_id=$1::uuid AND id=$2").bind(h.c.tenant.to_string()).bind(task).execute(&mut *tx).await?;
        tx.commit().await?;
        assert_eq!(read().await?["items"][0]["taskAdmission"]["state"],"effect_unknown");
        let target=rss_mdm_registration_service::device::endpoints::PrimaryRegistration{device:Uuid::new_v4().to_string(),channel:rss_mdm_inventory::Channel::Agent,};
        let mut tx=command::seed_transaction(&h.c).await?;
        assert!(script::queries::latest_assignment_on(&mut tx,h.c.tenant,policy,&target).await?.is_none());
        tx.rollback().await?;
        Ok(())
    }.await;
    h.close().await?;
    result
}
