use super::*;
use lifecycle::Peer;
use sqlx::Connection;
impl Fixture {
    pub(super) async fn queue_fairness(&mut self, peer: &Peer) -> Result<()> {
        self.policy_grants().await?;
        let definition = self.collection_template().await?;
        let expired = self.pending_collections(&definition, 65).await?;
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
        let (_, run) = self.queue_collection(&definition).await?;
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
    crate::test_support::stop_worker(Some(owner)).await?;
    result?;
    drop(device);
    f.close().await
}
