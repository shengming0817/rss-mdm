use super::*;
use lifecycle::Peer;
use sqlx::Connection;
impl Fixture {
    pub(super) async fn queue_fairness(&mut self, peer: &Peer) -> Result<()> {
        self.policy_grants().await?;
        let definition = self.collection_template().await?;
        let expired = self.pending_collections(&definition, 65, peer).await?;
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
            .bind(case_tenant())
            .execute(&mut pg)
            .await?;
        // Yield while the running Flow worker finishes its transaction.
        sqlx::query("UPDATE mdm_access.collection_runs SET deadline=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND id=ANY($2) AND sealed_at IS NULL")
            .bind(case_tenant()).bind(&expired).execute(&mut pg).await?;
        let ineligible: i64 = sqlx::query_scalar("SELECT count(DISTINCT c.id) FROM mdm_access.collection_runs c JOIN mdm_apple.attempts a ON(a.tenant_id,a.collection)=(c.tenant_id,c.id) WHERE c.tenant_id=$1::uuid AND c.id=ANY($2) AND c.deadline<clock_timestamp() AND a.deadline>clock_timestamp() AND a.state='pending'")
            .bind(case_tenant()).bind(&expired).fetch_one(&mut pg).await?;
        ensure!(
            ineligible == 65,
            "expired runs must still occupy live attempt candidate pages"
        );
        let (_, run) = self.queue_collection(&definition, peer).await?;
        sqlx::query("UPDATE mdm_apple.channels SET next_push=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND registration IN (SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2)")
        .bind(case_tenant()).bind(case_device())
            .execute(&mut pg)
            .await?;
        let mut wake = None;
        for _ in 0..3 {
            sqlx::query("UPDATE mdm_apple.channels SET next_push=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid").bind(case_tenant()).execute(&mut pg).await?;
            wake = self
                .app
                .execution
                .apple_wake(&self.app.apple()?.channel.push_fixture().configuration)
                .await?;
            if wake.is_some() {
                break;
            }
        }
        let wake =
            wake.ok_or_else(|| anyhow::anyhow!("expired queue starved a current collection"))?;
        self.app
            .execution
            .apple_pushed(
                &wake,
                Some(200),
                rss_mdm_execution_service::channels::PushOutcome::Accepted,
            )
            .await?;
        // Make old entries due again to independently exercise the native 32-item scan.
        sqlx::query("UPDATE mdm_apple.attempts SET next_attempt=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND collection IS NOT NULL AND state='pending'").bind(case_tenant()).execute(&mut pg).await?;
        pg.close().await?;
        let (id, _) = peer.next_collection().await?;
        ensure!(
            id == run,
            "expired queue page starved current native request"
        );
        peer.manage(
            "Acknowledged",
            Some(run),
            Some((
                "QueryResponses",
                plist::Value::Dictionary(protocol::dictionary([
                    ("Model", "Mac14,7".into()),
                    ("OSVersion", "14.7".into()),
                ])),
            )),
        )
        .await?;
        let mut db =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let settled: bool = sqlx::query_scalar("SELECT state->>'execution'='succeeded' AND result->>'collectionRun'=$2::text FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2")
                    .bind(case_tenant()).bind(run).fetch_one(&mut db).await?;
                if settled { return Ok::<_, anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await.map_err(|_| anyhow::anyhow!("live backlog prevented the tail report from settling its ActionRun"))??;
        db.close().await?;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "MODULE=apple.fairness: native protocol and durable state"]
async fn expired_queue_does_not_starve_current_collection() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let owner = f.policy_worker().await?;
    let result = f.queue_fairness(&peer).await;
    crate::test_support::runtime::stop_worker(Some(owner)).await?;
    result?;
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.fairness: durable check-in cursor and per-item commit"]
async fn checkin_sweep_coalesces_and_resumes_after_interrupted_item() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    f.policy_grants().await?;
    let definition = f.collection_template().await?;
    let owner = f.policy_worker().await?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let (registration, generation): (Uuid, i64) = sqlx::query_as("SELECT id,generation FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND state='active'")
        .bind(case_tenant()).bind(case_device()).fetch_one(&mut pg).await?;
    let entity = format!("native-checkin:{registration}:{generation}");
    // Hold only this target's lease. Protocol requests still use real authentication and transactions.
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut pg)
        .await?;
    sqlx::query("SELECT rss_reconcile.wake($1::uuid,'mdm.commands.v1',$2)")
        .bind(case_tenant())
        .bind(&entity)
        .execute(&mut pg)
        .await?;
    sqlx::query("UPDATE rss_reconcile.targets SET token=gen_random_uuid(),epoch=epoch+1,lease_until=clock_timestamp()+interval '1 hour' WHERE tenant_id=$1::uuid AND entity=$2")
        .bind(case_tenant()).bind(&entity).execute(&mut pg).await?;
    let mut policies = Vec::new();
    for _ in 0..65 {
        let policy = Uuid::new_v4();
        f.policy_post(
            &format!("/api/v1/policies/{policy}"),
            0,
            json!({"action":"put","enabled":true,"definition":definition}),
        )
        .await?;
        policies.push(policy);
    }
    policies.sort();
    peer.manage("Idle", None, None).await?;
    // Persist the transition that a worker makes when starting a sweep, then retain it
    // while later real signed check-ins arrive. No business run or cursor is fabricated.
    sqlx::query("UPDATE mdm_commands.native_checkins SET active_event=pending_event,active_at=pending_at,pending_event=NULL,pending_at=NULL,policy_after=NULL WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
        .bind(case_tenant()).bind(registration).bind(generation).execute(&mut pg).await?;
    let active: Uuid = sqlx::query_scalar("SELECT active_event FROM mdm_commands.native_checkins WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
        .bind(case_tenant()).bind(registration).bind(generation).fetch_one(&mut pg).await?;
    peer.manage("Idle", None, None).await?;
    let first_pending: Uuid = sqlx::query_scalar("SELECT pending_event FROM mdm_commands.native_checkins WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
        .bind(case_tenant()).bind(registration).bind(generation).fetch_one(&mut pg).await?;
    peer.manage("Idle", None, None).await?;
    let state: (Uuid, Uuid, Option<Uuid>) = sqlx::query_as("SELECT active_event,pending_event,policy_after FROM mdm_commands.native_checkins WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
        .bind(case_tenant()).bind(registration).bind(generation).fetch_one(&mut pg).await?;
    ensure!(
        state.0 == active && state.1 != first_pending && state.2.is_none(),
        "new check-in reset active work or failed to coalesce"
    );
    // A valid empty-facts trust receipt is distinct from its exact replay.
    let trust: Uuid = sqlx::query_scalar("SELECT id FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND phase='trust_install' AND received_at IS NOT NULL ORDER BY received_at DESC LIMIT 1")
        .bind(case_tenant()).bind(registration).bind(generation).fetch_one(&mut pg).await?;
    peer.manage("Acknowledged", Some(trust), None).await?;
    let replay_state: (Uuid, Uuid, Option<Uuid>) = sqlx::query_as("SELECT active_event,pending_event,policy_after FROM mdm_commands.native_checkins WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
        .bind(case_tenant()).bind(registration).bind(generation).fetch_one(&mut pg).await?;
    ensure!(
        replay_state == state,
        "trust receipt replay manufactured a new native check-in"
    );
    let mut blocker =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let mut held = blocker.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *held)
        .await?;
    sqlx::query("SELECT id FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
        .bind(case_tenant())
        .bind(policies[32])
        .execute(&mut *held)
        .await?;
    sqlx::query("UPDATE rss_reconcile.targets SET lease_until=NULL,token=NULL,next_run=clock_timestamp() WHERE tenant_id=$1::uuid AND entity=$2")
        .bind(case_tenant()).bind(&entity).execute(&mut pg).await?;
    let interrupted = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let failed: bool = sqlx::query_scalar("SELECT failures>0 FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND entity=$2")
                .bind(case_tenant()).bind(&entity).fetch_one(&mut pg).await?;
            if failed { return Ok::<_, anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await;
    held.rollback().await?;
    interrupted??;
    let after: Option<Uuid> = sqlx::query_scalar("SELECT policy_after FROM mdm_commands.native_checkins WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
        .bind(case_tenant()).bind(registration).bind(generation).fetch_one(&mut pg).await?;
    ensure!(
        after.is_some_and(|id| id >= policies[0] && id < policies[32]),
        "interrupted item lost committed progress: {after:?}"
    );
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let (runs, targets, events): (i64,i64,i64) = sqlx::query_as("SELECT count(*),count(t.entity),count(r.triggered_at) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) LEFT JOIN rss_reconcile.targets t ON t.tenant_id=r.tenant_id AND t.reconciler='mdm.commands.v1' AND t.entity='native-run:'||r.id::text WHERE r.tenant_id=$1::uuid AND v.policy=ANY($2)")
                .bind(case_tenant()).bind(&policies).fetch_one(&mut pg).await?;
            let drained: bool = sqlx::query_scalar("SELECT active_event IS NULL AND pending_event IS NULL FROM mdm_commands.native_checkins WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
                .bind(case_tenant()).bind(registration).bind(generation).fetch_one(&mut pg).await?;
            ensure!(runs <= 65, "coalesced check-ins duplicated occurrences");
            if drained && runs == 65 && targets == 65 && events == 65 { return Ok::<_, anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await??;
    blocker.close().await?;
    pg.close().await?;
    crate::test_support::runtime::stop_worker(Some(owner)).await?;
    drop(device);
    f.close().await
}
