//! Software's surviving transaction risks: alias/channel exclusion, durable Unknown, rollout snapshot.
mod fixture;
use crate::{
    authority_t2_support::Context, command_runtime_t2_support as command,
    device_material_support as material, planning_t2_support as planning,
};
use anyhow::Result;
use fixture::Fixture;
use rss_mdm_agent_wire::runtime as w;
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_software_service::deployment as owner;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;
pub(super) mod support;
use support::*;
async fn open(c: &Context) -> Result<Fixture> {
    let protection = material::protection(c)?;
    material::seed_trust(
        c,
        &protection,
        &[rss_mdm_agent_wire::task_trust::KeyState::Active],
    )
    .await?;
    Fixture::open_with(c, true, |config| {
        config["software_distribution"]["mdm_enabled"] = json!(true)
    })
    .await
}
fn accepted(decision: &w::PolicyEventDecision) -> bool {
    matches!(decision,w::PolicyEventDecision::Accepted{operations} if !operations.is_empty())
}
async fn count(c: &Context) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid",
    )
    .bind(c.tenant.to_string())
    .fetch_one(&c.operator)
    .await?)
}

#[tokio::test]
#[ignore = "T2: independent input owners commit their first suspension and distinct audit facts in the same tenant"]
async fn input_suspension_has_a_distinct_software_audit_identity() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let a = Fixture::open(&c, false).await?;
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(10));
    let store = c
        .audit
        .on_runtime(
            a.resources.storage.runtime.clone(),
            c.tenant,
            &budget.control(),
        )
        .await?;
    let request = audit(&c);
    rss_mdm_device_service::control::transaction::run(
        &store,
        &a.resources.storage.runtime,
        c.tenant,
        &request,
        &store,
        |store, tx| {
            Box::pin(async move {
                rss_mdm_device_service::control::source_changes::fail_in(tx, store).await
            })
        },
    )
    .await?;
    request.finalize(None);
    for _ in 0..2 {
        let request = audit(&c);
        owner::transaction::run(
            &store,
            &a.resources.storage.runtime,
            c.tenant,
            &request,
            &store,
            |store, tx| Box::pin(async move { owner::source_changes::fail_in(tx, store).await }),
        )
        .await?;
        request.finalize(None);
    }
    let states: Vec<(String, i64)> = sqlx::query_as(
        "SELECT failure,failure_generation FROM mdm_devices.control_source_dispatch WHERE tenant_id=$1::uuid UNION ALL SELECT failure,failure_generation FROM mdm_software_deployment.device_source_dispatch WHERE tenant_id=$1::uuid",
    ).bind(c.tenant.to_string()).fetch_all(&c.operator).await?;
    assert_eq!(states, vec![("automation_suspended".into(), 1); 2]);
    let facts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id='mdm.business'",
    ).bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(facts, 2);
    Fixture::close(a).await?;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: concurrent Agent/MDM aliases on associated endpoints share one Software effect fence"]
async fn associated_aliases_admit_exactly_one_effect_across_channels() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let (agent, native, agent_scope, native_scope) = endpoints(&c).await?;
    let original = software(&c, "editor-agent").await?;
    let alias = software(&c, "editor-native").await?;
    let (ap, _) = policy(
        &c,
        &original,
        agent_scope,
        rss_mdm_policy::SoftwareChannel::Agent,
        vec![stage(agent_scope)],
    )
    .await?;
    let (mp, _) = policy(
        &c,
        &alias,
        native_scope,
        rss_mdm_policy::SoftwareChannel::Mdm,
        vec![stage(native_scope)],
    )
    .await?;
    let a = open(&c).await?;
    for (policy, target) in [(ap, &agent), (mp, &native)] {
        assert!(accepted(
            &decision(&c, &a, policy, target, Uuid::new_v4(), true, None).await?
        ));
    }
    assert_eq!(count(&c).await?, 0);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let (left, right) = tokio::join!(
        decision(
            &c,
            &a,
            ap,
            &agent,
            Uuid::new_v4(),
            false,
            Some(barrier.clone())
        ),
        decision(&c, &a, mp, &native, Uuid::new_v4(), false, Some(barrier))
    );
    // The nonblocking effect fence may reject the competing transaction for retry.
    // Both candidates were independently admitted above; every other error still fails.
    for result in [&left, &right] {
        if let Err(error) = result {
            assert!(
                matches!(
                    error.downcast_ref::<owner::Error>(),
                    Some(owner::Error::Unavailable(owner::Failure::CommandStorage))
                ),
                "unexpected admission failure: {error:?}"
            );
        }
    }
    assert_eq!(
        [&left, &right]
            .into_iter()
            .filter(|v| v.as_ref().is_ok_and(accepted))
            .count(),
        1,
        "exactly one admitted effect: {left:?} {right:?}"
    );
    assert_eq!(count(&c).await?, 1);
    for (p, target) in [(ap, &agent), (mp, &native)] {
        assert!(!accepted(&accept(&c, &a, p, target, Uuid::new_v4()).await?));
    }
    assert_eq!(count(&c).await?, 1);
    let outbox:i64=sqlx::query_scalar("SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id LIKE 'action.%'").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(outbox, 1);
    Fixture::close(a).await?;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: original durable Unknown blocks new Software identity/channel/revision after service reconstruction"]
async fn unknown_blocks_new_alias_policy_and_task_after_reconstruction() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let (agent, native, agent_scope, native_scope) = endpoints(&c).await?;
    let original = software(&c, "editor").await?;
    let alias = software(&c, "editor-alias").await?;
    let (ap, _) = policy(
        &c,
        &original,
        agent_scope,
        rss_mdm_policy::SoftwareChannel::Agent,
        vec![stage(agent_scope)],
    )
    .await?;
    let (mp, _) = policy(
        &c,
        &alias,
        native_scope,
        rss_mdm_policy::SoftwareChannel::Mdm,
        vec![stage(native_scope)],
    )
    .await?;
    let a = open(&c).await?;
    assert!(accepted(
        &decision(&c, &a, mp, &native, Uuid::new_v4(), true, None).await?
    ));
    let id = Uuid::new_v4();
    assert!(accepted(&accept(&c, &a, ap, &agent, id).await?));
    let attempt = Uuid::new_v4();
    let mut state = rss_mdm_task_state::RunState::new(now() + 300, now())?;
    state.claim(attempt, now())?;
    state.received(attempt, now())?;
    state.start(attempt, now())?;
    state.uncertain_result(attempt)?;
    let mut tx = command::seed_transaction(&c).await?;
    sqlx::query("UPDATE mdm_software_deployment.action_runs SET state=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(id).bind(serde_json::to_value(&state)?).execute(&mut *tx).await?;
    tx.commit().await?;
    Fixture::close(a).await?;
    let a = Fixture::open_with(&c, true, |v| {
        v["software_distribution"]["mdm_enabled"] = json!(true)
    })
    .await?;
    for p in [
        ap,
        policy(
            &c,
            &original,
            agent_scope,
            rss_mdm_policy::SoftwareChannel::Agent,
            vec![stage(agent_scope)],
        )
        .await?
        .0,
    ] {
        assert!(!accepted(&accept(&c, &a, p, &agent, Uuid::new_v4()).await?));
    }
    assert!(!accepted(
        &accept(&c, &a, mp, &native, Uuid::new_v4()).await?
    ));
    assert_eq!(count(&c).await?, 1);
    let stored: Value = sqlx::query_scalar(
        "SELECT state FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(id)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(stored, serde_json::to_value(&state)?);
    // A new owner takes the Policy, while the original Software run retains its uncertainty.
    let next = Uuid::new_v4();
    let actor = rss_mdm_authorization_service::Actor::Account {
        user: c.user(Uuid::new_v4()),
    };
    let frozen = serde_json::to_value(
        rss_mdm_device_service::control::frozen::Frozen::UnmanageDevice {
            schedule: schedule(),
            run_lifetime_seconds: 300,
            actor,
        },
    )?;
    let mut changed = command::seed_transaction(&c).await?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,frozen,fingerprint) VALUES($1::uuid,$2,$3,2,'unmanage_device',$4,$5)").bind(c.tenant.to_string()).bind(next).bind(ap).bind(&frozen).bind(Sha256::digest(serde_json::to_vec(&frozen)?).to_vec()).execute(&mut *changed).await?;
    let action = serde_json::to_value(rss_mdm_policy::Action::UnmanageDevice {
        schedule: schedule(),
        run_lifetime_seconds: 300,
    })?;
    sqlx::query("UPDATE mdm_policy.policies SET current_version=$3,version_number=2,revision=revision+1,definition=jsonb_set(definition,'{action}',$4) WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(ap).bind(next).bind(action).execute(&mut *changed).await?;
    changed.commit().await?;
    owner::transaction::inspect(
        &a.resources.storage.runtime,
        c.tenant,
        a.software.service.as_ref(),
        move |service, tx| {
            Box::pin(async move { owner::actions::recovery::recover_one(service, tx, id).await })
        },
    )
    .await?;
    let recovered:rss_mdm_task_state::RunState=serde_json::from_value(sqlx::query_scalar("SELECT state FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?)?;
    assert_eq!(recovered.execution, rss_mdm_task_state::Execution::Unknown);
    assert_eq!(
        recovered.cancellation,
        rss_mdm_task_state::Cancellation::Requested
    );
    assert_eq!(recovered.attempt(), state.attempt());
    // The same exit also retains waiting-for-reboot evidence rather than manufacturing success.
    let mut reboot = rss_mdm_task_state::RunState::new(now() + 300, now())?;
    reboot.claim(attempt, now())?;
    reboot.received(attempt, now())?;
    reboot.start(attempt, now())?;
    reboot.waiting_reboot(attempt)?;
    let mut tx = command::seed_transaction(&c).await?;
    sqlx::query("UPDATE mdm_software_deployment.action_runs SET state=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(id).bind(serde_json::to_value(reboot)?).execute(&mut *tx).await?;
    tx.commit().await?;
    owner::transaction::inspect(
        &a.resources.storage.runtime,
        c.tenant,
        a.software.service.as_ref(),
        move |service, tx| {
            Box::pin(async move { owner::actions::recovery::recover_one(service, tx, id).await })
        },
    )
    .await?;
    let recovered:rss_mdm_task_state::RunState=serde_json::from_value(sqlx::query_scalar("SELECT state FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?)?;
    assert_eq!(
        recovered.execution,
        rss_mdm_task_state::Execution::WaitingReboot
    );
    assert_eq!(
        recovered.cancellation,
        rss_mdm_task_state::Cancellation::Requested
    );
    Fixture::close(a).await?;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: rollout denominator and verified effects use the same published generation; stale revisions close the next gate"]
async fn rollout_snapshot_invalidates_counts_before_opening_next_stage() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let (agent, _, scope, second) = endpoints(&c).await?;
    let resource = software(&c, "rollout").await?;
    let (p, v) = policy(
        &c,
        &resource,
        scope,
        rss_mdm_policy::SoftwareChannel::Agent,
        vec![
            stage(scope),
            rss_mdm_policy::SoftwareRolloutStage {
                scope: second,
                opens_at: 1,
                minimum_verified_percent: Some(100),
            },
        ],
    )
    .await?;
    let a = open(&c).await?;
    let id = Uuid::new_v4();
    assert!(accepted(&accept(&c, &a, p, &agent, id).await?));
    let account = c
        .account(&[
            rss_mdm_authorization_service::Permission::PolicyRead,
            rss_mdm_authorization_service::Permission::OperationRead,
        ])
        .await?;
    let proof = c.authenticate(&account).await?;
    let before = serde_json::to_value(
        a.software
            .queries
            .software_rollout(&proof, p, &c.request(&proof)?)
            .await?,
    )?;
    assert_eq!(before["stages"][1]["open"], false);
    reduce(&c, &a, p, v).await?;
    let current = serde_json::to_value(
        a.software
            .queries
            .software_rollout(&proof, p, &c.request(&proof)?)
            .await?,
    )?;
    assert_eq!(current["stages"][0]["ready"], true);
    assert_eq!(current["stages"][0]["totalTargets"], 1);
    assert_eq!(current["stages"][0]["verifiedSuccess"], 0);
    assert_eq!(current["stages"][1]["open"], false);
    let dispatch_before:i64=sqlx::query_scalar("SELECT dispatch_revision FROM mdm_software_deployment.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2").bind(c.tenant.to_string()).bind(p).fetch_one(&c.operator).await?;
    // The actual reducer consumes one legal completed original effect.
    verified(&c, &a, &resource, id).await?;
    reduce(&c, &a, p, v).await?;
    let verified = serde_json::to_value(
        a.software
            .queries
            .software_rollout(&proof, p, &c.request(&proof)?)
            .await?,
    )?;
    assert_eq!(verified["stages"][0]["verifiedSuccess"], 1);
    assert_eq!(verified["stages"][1]["open"], true);
    let dispatch_after:i64=sqlx::query_scalar("SELECT dispatch_revision FROM mdm_software_deployment.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2").bind(c.tenant.to_string()).bind(p).fetch_one(&c.operator).await?;
    assert!(
        dispatch_after > dispatch_before,
        "a gate transition must durably reopen dispatch even without a notification receiver"
    );
    // Hold the stats relation so the reader has already read Scope before a new revision commits.
    let mut change = command::seed_transaction(&c).await?;
    sqlx::query("LOCK TABLE mdm_software_deployment.software_stage_stats IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *change)
        .await?;
    let audit = c.request(&proof)?;
    let (snapshot, changed) = tokio::join!(
        a.software.queries.software_rollout(&proof, p, &audit),
        async {
            tokio::time::timeout(std::time::Duration::from_secs(3),async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='mdm_software_deployment.software_stage_stats'::regclass AND NOT granted)").fetch_one(&c.operator).await?;
                if waiting {break;}
                tokio::task::yield_now().await;
            }
            Ok::<_,anyhow::Error>(())
        }).await??;
            sqlx::query("UPDATE mdm_scope.scope_projection_runs SET agent_revision=agent_revision+1 WHERE tenant_id=$1::uuid AND scope=$2 AND phase='published'").bind(c.tenant.to_string()).bind(scope).execute(&mut *change).await?;
            change.commit().await?;
            Ok::<_, anyhow::Error>(())
        }
    );
    changed?;
    let snapshot = serde_json::to_value(snapshot?)?;
    assert_eq!(snapshot["stages"], verified["stages"]);
    let stale = serde_json::to_value(
        a.software
            .queries
            .software_rollout(&proof, p, &c.request(&proof)?)
            .await?,
    )?;
    assert_eq!(stale["stages"][0]["ready"], false);
    assert_eq!(stale["stages"][0]["verifiedSuccess"], 0);
    assert_eq!(stale["stages"][1]["open"], false);
    Fixture::close(a).await?;
    c.close().await;
    Ok(())
}
async fn reduce(c: &Context, a: &Fixture, policy_id: Uuid, version: Uuid) -> Result<()> {
    use std::time::Duration;
    let messaging = rss_reconcile_postgres::PgMessagingStore::new(
        a.resources.storage.runtime.clone(),
        c.tenant,
        owner::deadline(),
    )
    .await?;
    owner::transaction::inspect(
        &a.resources.storage.runtime,
        c.tenant,
        messaging,
        move |m, tx| {
            Box::pin(
                async move { owner::sources::storage::wake_execution_in(m, tx, policy_id).await },
            )
        },
    )
    .await?;
    let timer = owner::recovery::Timer::new();
    let force = tokio_util::sync::CancellationToken::new();
    let stop = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(20), &force);
    let notify = tokio::sync::Notify::new();
    let policy = rss_reconcile::Policy::try_from(rss_reconcile::PolicyConfig {
        concurrency: 1,
        lease_ttl: Duration::from_secs(30),
        attempt_timeout: Duration::from_secs(6),
        scan_interval: Duration::from_millis(20),
        idle_scan_interval: Duration::from_secs(1),
        initial_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_secs(1),
        max_attempts: 100,
    })?;
    let scope = owner::recovery_scope(c.tenant);
    let (report, observed) = tokio::join!(
        a.software
            .service
            .run_recovery(&scope, policy, &control, &stop, &notify),
        async {
            let result=tokio::time::timeout(Duration::from_secs(15),async{loop{let ready:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_software_deployment.software_stage_stats WHERE tenant_id=$1::uuid AND version=$2 AND stage=0 AND ready AND membership_complete AND (input->>'results')::bigint=(SELECT stats_revision FROM mdm_software_deployment.policy_recovery r WHERE r.tenant_id=$1::uuid AND r.policy=$3))").bind(c.tenant.to_string()).bind(version).bind(policy_id).fetch_one(&c.operator).await?;if ready{break;}tokio::time::sleep(Duration::from_millis(20)).await;}Ok::<_,anyhow::Error>(())}).await;
            stop.cancel();
            result
        }
    );
    observed??;
    assert_eq!(report?.execution_failed, 0);
    Ok(())
}
