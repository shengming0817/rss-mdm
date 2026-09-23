//! Real durable lease → HTTP/2 send → persisted result, without command evidence.
use super::*;
use sqlx::{Connection, PgConnection};
async fn due(pg: &mut PgConnection) -> Result<()> {
    sqlx::query("UPDATE mdm_apple.devices SET next_push=clock_timestamp()-interval '1 second'")
        .execute(pg)
        .await?;
    Ok(())
}
async fn state(pg: &mut PgConnection) -> Result<serde_json::Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('state',state,'token',token IS NOT NULL,'magic',magic IS NOT NULL,'lease',push_lease_until IS NOT NULL,'status',push_status,'outcome',push_outcome,'failures',push_failures,'delay',extract(epoch FROM next_push-clock_timestamp())::double precision) FROM mdm_apple.devices WHERE state<>'retired'").fetch_one(pg).await?)
}
impl Fixture {
    pub async fn push_cycle(&mut self, peer: &lifecycle::Peer) -> Result<()> {
        let operation = self
            .create_operation(json!({"kind":"profile_install","enabled":true}))
            .await?;
        let mut pg =
            PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
            .bind(TENANT)
            .execute(&mut pg)
            .await?;
        let participant =
            push::tests::Participant::start(vec![429, 503, 400, 200, 410], vec![42; 32]).await?;
        for (status, failures, minimum) in [(429, 1, 25.0), (503, 2, 55.0), (400, 0, 25.0)] {
            due(&mut pg).await?;
            push::wake(&participant.push, &self.app.commands).await?;
            let receipt = state(&mut pg).await?;
            ensure!(
                receipt["status"] == status
                    && receipt["failures"] == failures
                    && receipt["lease"] == false
                    && receipt["state"] == "active"
                    && receipt["token"] == true,
                "APNs durable receipt {receipt}"
            );
            ensure!(
                receipt["delay"].as_f64().unwrap() >= minimum,
                "APNs retry is not delayed {receipt}"
            );
            ensure!(self.operation(operation).await?["commandStatus"] == "published");
        }
        due(&mut pg).await?;
        push::wake(&participant.push, &self.app.commands).await?;
        ensure!(
            state(&mut pg).await?["status"] == 400,
            "permanent rejection was retried without recovery"
        );
        ensure!(
            self.app
                .commands
                .apple_wake(&participant.push.configuration)
                .await?
                .is_none()
        );
        // A genuinely reissued certificate reopens only the old certificate's pause.
        let rotated =
            push::tests::Participant::start_with_rotation(vec![400, 200], vec![42; 32], true)
                .await?;
        ensure!(rotated.push.configuration != participant.push.configuration);
        push::wake(&rotated.push, &self.app.commands).await?;
        ensure!(state(&mut pg).await?["outcome"] == "rejected");
        ensure!(
            self.app
                .commands
                .apple_wake(&rotated.push.configuration)
                .await?
                .is_none()
        );
        // TokenUpdate is the explicit recovery transition for a paused token.
        peer.token().await?;
        push::wake(&rotated.push, &self.app.commands).await?;
        ensure!(state(&mut pg).await?["outcome"] == "accepted");
        rotated.close().await?;
        due(&mut pg).await?;
        push::wake(&participant.push, &self.app.commands).await?;
        ensure!(state(&mut pg).await?["outcome"] == "accepted");
        ensure!(self.operation(operation).await?["commandStatus"] == "published");
        due(&mut pg).await?;
        push::wake(&participant.push, &self.app.commands).await?;
        let unregistered = state(&mut pg).await?;
        ensure!(
            unregistered["state"] == "pending_token"
                && unregistered["token"] == false
                && unregistered["magic"] == false
                && unregistered["lease"] == false
        );
        let denied = peer
            .send(
                "/mdm",
                protocol::dictionary([("Status", "Idle".into()), ("UDID", "rss-apple-t2".into())]),
            )
            .await?;
        ensure!(denied.0 == StatusCode::UNAUTHORIZED);
        participant.close().await?;
        peer.token().await?;
        let unavailable = push::tests::Participant::unavailable_push().await?;
        push::wake(&unavailable, &self.app.commands).await?;
        let failed = state(&mut pg).await?;
        ensure!(
            failed["status"].is_null()
                && failed["outcome"] == "retryable"
                && failed["lease"] == false
                && failed["failures"] == 1
        );
        ensure!(self.operation(operation).await?["commandStatus"] == "published");
        due(&mut pg).await?;
        let recovered = push::tests::Participant::start(vec![200], vec![42; 32]).await?;
        push::wake(&recovered.push, &self.app.commands).await?;
        ensure!(state(&mut pg).await?["failures"] == 0);
        recovered.close().await?;
        pg.close().await?;
        let operation_state = self.operation(operation).await?;
        let cancelled=self.browser.call(&self.router,Method::POST,&format!("/api/v2/devices/{DEVICE}/operations/{operation}/cancel"),Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":operation_state["revision"]}))).await?;
        ensure!(cancelled.0 == StatusCode::OK);
        Ok(())
    }
}
