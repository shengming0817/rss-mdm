use super::*;
use crate::apple::push;
use lifecycle::Peer;
use sqlx::Connection;
impl Fixture {
    pub(super) async fn queue_fairness(&mut self, peer: &Peer) -> Result<()> {
        let path = format!("/api/v1/devices/{DEVICE}/collection-runs");
        self.pending_collections(65).await?;
        // Replacing the admission rule invalidates all previously frozen approvals.
        crate::test_support::identity::set_grants(
            TENANT,
            crate::test_support::identity::ADMIN,
            crate::test_support::identity::device_grants(
                Some(DEVICE),
                &[
                    "enrollment",
                    "credentials",
                    "inventory_read",
                    "inventory_collect",
                    "firewall_write",
                    "operation_read",
                    "operation_cancel",
                ],
            )?,
        )
        .await?;
        let fresh = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &path,
                Some(json!({"source":"mdm.apple","requestId":Uuid::new_v4()})),
            )
            .await?;
        ensure!(fresh.0 == StatusCode::ACCEPTED);
        let run = Uuid::parse_str(fresh.1["runId"].as_str().unwrap())?;
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
            .bind(TENANT)
            .execute(&mut pg)
            .await?;
        sqlx::query("UPDATE mdm_apple.devices SET next_push=clock_timestamp()-interval '1 second'")
            .execute(&mut pg)
            .await?;
        ensure!(
            self.app
                .execution
                .apple_wake(&self.app.apple()?.push.configuration)
                .await?
                .is_none()
        );
        sqlx::query("UPDATE mdm_apple.devices SET next_push=clock_timestamp()-interval '1 second'")
            .execute(&mut pg)
            .await?;
        let wake = self
            .app
            .execution
            .apple_wake(&self.app.apple()?.push.configuration)
            .await?
            .ok_or_else(|| anyhow::anyhow!("blocked queue page starved approved wake"))?;
        self.app
            .execution
            .apple_pushed(&wake, Some(200), push::Outcome::Accepted)
            .await?;
        // Make old entries due again to independently exercise the native 32-item scan.
        sqlx::query("UPDATE mdm_apple.attempts SET next_attempt=clock_timestamp()-interval '1 second' WHERE collection IS NOT NULL AND state='pending'").execute(&mut pg).await?;
        pg.close().await?;
        let (id, _) = peer.next("DeviceInformation").await?;
        ensure!(
            id == run,
            "blocked queue page starved approved native request"
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
async fn blocked_queue_does_not_starve_approved_work() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    f.queue_fairness(&peer).await?;
    drop(device);
    f.close().await
}
