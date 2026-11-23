use super::*;
use anyhow::Context as _;
use rss_mdm_registration_service::device::endpoints::PrimaryRegistration;
use rss_transactional_messaging::fence::ExecutionBinding;
use std::time::Duration;

async fn fail_run(f: &Fixture, binding: ExecutionBinding, id: Uuid) -> Result<()> {
    let runtime = &f.resources.storage.runtime;
    let profile = rss_mdm_install_support::StorageProfile::Mdm;
    let reader = rss_mdm_policy_postgres::PolicyReader::bind(profile, runtime.clone());
    let messaging =
        rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), binding, owner::deadline())
            .await?;
    owner::transaction::inspect(
        runtime,
        binding,
        (reader, messaging),
        move |(reader, messaging), tx| {
            Box::pin(async move {
                let mut run = owner::actions::storage::load_run(tx, id).await?;
                run.state.execution = rss_mdm_task_state::Execution::Failed;
                owner::actions::storage::save_run(reader, messaging, tx, &run).await
            })
        },
    )
    .await?;
    Ok(())
}
async fn assign(
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    scope_result: Uuid,
    binding: ExecutionBinding,
    policy: Uuid,
    version: Uuid,
    target: PrimaryRegistration,
) -> Result<()> {
    let profile = rss_mdm_install_support::StorageProfile::Mdm;
    let reader = rss_mdm_policy_postgres::PolicyReader::bind(profile, runtime.clone());
    let messaging =
        rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), binding, owner::deadline())
            .await?;
    let assignment = rss_mdm_policy_postgres::assignments::Assignment {
        policy,
        version,
        object: rss_mdm_agent_wire::ObjectRef::Endpoint(target.device),
        channel: target.channel.as_str().into(),
        input: serde_json::to_value(&target)?,
        available: true,
        reason: None,
        target: Some(serde_json::to_value(&target)?),
        scope_result,
        entry_revision: 1,
    };
    let result = owner::transaction::inspect(
        &runtime,
        binding,
        (reader, messaging),
        move |(reader, messaging), tx| {
            Box::pin(async move {
                rss_mdm_policy_postgres::assignments::upsert_in(profile, tx, assignment).await?;
                owner::actions::scheduled::VerifiedSoftwareVersion::verify_in(reader, tx, version)
                    .await?
                    .ok_or(owner::Error::NotFound)?
                    .wake_assignment_in(messaging, tx, &target)
                    .await
            })
        },
    )
    .await;
    runtime.close().await;
    Ok(result?)
}
#[tokio::test]
#[ignore = "T2: a failed run keeps its original generation while a new assignment schedules the same device and policy version"]
async fn scheduled_assignment_survives_a_prior_epoch_run() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let (target, _, scope, _, _) = endpoints(&c).await?;
    let resource = software(&c, "mixed-generation").await?;
    let mut trigger = schedule();
    trigger.trigger = rss_mdm_policy::schedule::Trigger::Registration;
    let (policy, version) = policy_with_schedule(
        &c,
        &resource,
        scope,
        rss_mdm_policy::SoftwareChannel::Agent,
        vec![],
        trigger,
    )
    .await?;
    let fixture = open(&c).await?;
    let old = Uuid::new_v4();
    assert!(accepted(&accept(&c, &fixture, policy, &target, old).await?));
    fail_run(&fixture, c.execution(), old)
        .await
        .context("settle original run and wake its device")?;
    let key = |epoch| format!("scheduled:{epoch}:{version}:{}", target.device);
    let frozen: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND entity=$2)",
    )
    .bind(c.tenant.to_string())
    .bind(key(1))
    .fetch_one(&c.operator)
    .await?;
    assert!(frozen, "a run-only wake is durable");
    let runtime = planning::owner(&c, "mdm_policy_runtime").await?.runtime;
    let scope_result = sqlx::query_scalar(
        "SELECT resolution FROM mdm_scope.scopes WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(scope)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(sqlx::query("UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid AND epoch=1").bind(c.tenant.to_string()).execute(&c.operator).await?.rows_affected(),1);
    let current = ExecutionBinding::new(
        c.execution().storage(),
        c.tenant,
        c.execution().epoch().next()?,
    );
    assert!(
        fail_run(&fixture, current, old).await.is_err(),
        "a current writer cannot wake a historical run"
    );
    assign(
        runtime,
        scope_result,
        current,
        policy,
        version,
        PrimaryRegistration {
            device: target.device,
            channel: rss_mdm_inventory::Channel::Agent,
        },
    )
    .await
    .context("publish the new assignment and its wake in the Policy transaction")?;
    let signals = owner::worker_wake::Signals::default();
    let stop = tokio_util::sync::CancellationToken::new();
    let (worker, observed) = tokio::join!(
        fixture
            .software
            .service
            .run_worker(fixture.resources.background.commands, &stop, &signals),
        async {
            let observed = tokio::time::timeout(Duration::from_secs(45),async{
                loop {
                    let complete:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND policy_version=$2 AND device=$3 AND expected_epoch=2) AND EXISTS(SELECT FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND id=$4 AND expected_epoch=1 AND state->>'execution'='failed')").bind(c.tenant.to_string()).bind(version).bind(target.device.into_uuid()).bind(old).fetch_one(&c.operator).await?;
                    if complete {return Ok::<_,anyhow::Error>(());}
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }).await;
            stop.cancel();
            observed
        }
    );
    fixture.close().await?;
    c.close().await;
    worker?;
    observed?
}
