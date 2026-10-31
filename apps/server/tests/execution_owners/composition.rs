use super::*;
#[tokio::test]
#[ignore = "T2: one device capacity fence includes all three business owners"]
async fn shared_capacity_counts_each_owner_and_isolates_other_devices() -> Result<()> {
    use script::DeviceCapacity;
    let h = Harness::open().await?;
    let (_, version) = h.policy("capacity").await?;
    let id = h.run(version, "capacity", now() + 300).await?;
    let mut tx = command::seed_transaction(&h.c).await?;
    // 63 remaining Execution tasks, 63 Inventory tasks, and one Script task = 127.
    sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,origin,source_objects,device,registration,generation,occurrence,created_at,available_at,deadline,state,dispatch_fingerprint) SELECT tenant_id,gen_random_uuid(),policy_version,origin,source_objects,device,registration,generation,'capacity:'||n,created_at,available_at,deadline,state,dispatch_fingerprint FROM mdm_script.runs CROSS JOIN generate_series(1,63) n WHERE tenant_id=$1::uuid AND id=$2").bind(h.c.tenant.to_string()).bind(id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_inventory.collection_tasks(tenant_id,id,policy_version,channel,origin,source_objects,device,registration,generation,occurrence,created_at,available_at,deadline,agent_state,dispatch_fingerprint) SELECT tenant_id,gen_random_uuid(),policy_version,'agent',origin,source_objects,device,registration,generation,'capacity:'||n,created_at,available_at,deadline,state,dispatch_fingerprint FROM mdm_script.runs CROSS JOIN generate_series(1,63) n WHERE tenant_id=$1::uuid AND id=$2").bind(h.c.tenant.to_string()).bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    let capacity = |device: String| {
        script::transaction::inspect(&h.a.runtime, h.c.tenant, device, |device, tx| {
            Box::pin(async move {
                script::storage::lock_device(tx, device).await?;
                super::super::capacity::Capacity
                    .available_in(tx, device, now())
                    .await
            })
        })
    };
    assert!(capacity(h.p.device().into()).await?);
    h.run(version, "capacity", now() + 300).await?;
    assert!(!capacity(h.p.device().into()).await?);
    assert!(capacity("another-device".into()).await?);
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_inventory.collection_tasks SET agent_state=jsonb_set(agent_state,'{cancellation}','\"confirmed\"') WHERE tenant_id=$1::uuid AND id=(SELECT id FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid LIMIT 1)").bind(h.c.tenant.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(capacity(h.p.device().into()).await?);
    h.close().await
}
#[tokio::test]
#[ignore = "T2: cross-owner receipt lookup precedes current Policy classification and rejects changed requests"]
async fn original_self_service_receipt_replays_after_policy_kind_changes() -> Result<()> {
    use rss_mdm_agent_channel::participants::SelfService;
    let h = Harness::open().await?;
    let (policy, version) = h.policy("receipt").await?;
    let run = h.run(version, "receipt", now() + 300).await?;
    let mut input = w::SelfServiceInvoke {
        operation_id: Uuid::new_v4(),
        policy_id: policy,
        source: w::SelfServiceCaller::Human,
        confirmed: false,
        parameters: Default::default(),
    };
    let accepted = w::SelfServiceAccepted {
        request_id: input.operation_id,
        run_id: run,
        policy_id: policy,
        policy_revision: 1,
        policy_version: version,
    };
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("INSERT INTO mdm_script.receipts(tenant_id,actor,id,fingerprint,response) VALUES($1::uuid,$2,$3,$4,$5)").bind(h.c.tenant.to_string()).bind(format!("self-service:device:{}:{}",h.p.registration(),h.p.generation())).bind(input.operation_id).bind(script::transaction::fingerprint(&input)?).bind(serde_json::to_value(&accepted)?).execute(&mut *tx).await?;
    // A currently forbidden action makes a classify-first implementation observably fail.
    let changed: rss_mdm_policy::Definition = serde_json::from_value(
        json!({"scope":h.scope,"action":{"kind":"unmanage_device","runLifetimeSeconds":300,"schedule":{"trigger":{"kind":"manual"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null}}}),
    )?;
    sqlx::query("UPDATE mdm_policy.policies SET revision=revision+1,definition=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(h.c.tenant.to_string()).bind(policy).bind(serde_json::to_value(changed)?).execute(&mut *tx).await?;
    tx.commit().await?;
    let tasks = super::super::agent_tasks::AgentTasks {
        requests: h.a.self_service.clone(),
        execution: h.a.service.clone(),
        scripts: h.a.scripts.clone(),
        collections: h.a.collections.clone(),
    };
    let replay = tasks.invoke(&h.p, None, &input, &request(&h.c)).await?;
    assert_eq!(
        serde_json::to_value(replay)?,
        serde_json::to_value(accepted)?
    );
    input.confirmed = true;
    assert!(
        tasks
            .invoke(&h.p, None, &input, &request(&h.c))
            .await
            .is_err()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm_script.runs WHERE tenant_id=$1::uuid")
            .bind(h.c.tenant.to_string())
            .fetch_one(&h.c.operator)
            .await?;
    assert_eq!(count, 1);
    drop(tasks);
    h.close().await
}
