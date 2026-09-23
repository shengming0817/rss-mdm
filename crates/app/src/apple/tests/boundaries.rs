//! Refusal paths must not create native authority or terminal success.
use super::*;
use lifecycle::{Peer, command};
use sqlx::Connection;
pub(super) async fn unbound_leaf_and_replay(
    f: &Fixture,
    device: &scep::Device,
    request: &[u8],
    attempt: Uuid,
) -> Result<()> {
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
    let row: (String, bool) = sqlx::query_as(
        "SELECT state,fingerprint IS NULL FROM mdm_apple.scep_attempts WHERE id=$1::uuid",
    )
    .bind(attempt.to_string())
    .fetch_one(&mut pg)
    .await?;
    ensure!(
        row == ("consumed".into(), true),
        "lost notify fabricated a certificate binding"
    );
    ensure!(
        device
            .enroll(&f.client()?, &f.app.apple()?.config.scep_url, request)
            .await
            .is_err(),
        "identical SCEP request reauthorized"
    );
    pg.close().await?;
    Ok(())
}
impl Fixture {
    pub async fn before_token(&mut self, peer: &Peer) -> Result<()> {
        let reply = peer
            .send(
                "/mdm",
                protocol::dictionary([("Status", "Idle".into()), ("UDID", "rss-apple-t2".into())]),
            )
            .await?;
        ensure!(
            reply.0 == StatusCode::UNAUTHORIZED,
            "pending_token admitted management"
        );
        let reply = peer
            .send(
                "/checkin",
                protocol::dictionary([
                    ("MessageType", "UserAuthenticate".into()),
                    ("UDID", "rss-apple-t2".into()),
                ]),
            )
            .await?;
        ensure!(reply.0 == StatusCode::GONE);
        let reply = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &format!("/api/v1/devices/{DEVICE}/collection-runs"),
                Some(json!({"source":"mdm.apple","requestId":Uuid::new_v4()})),
            )
            .await?;
        ensure!(reply.0 == StatusCode::CONFLICT);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                self.root.join("ca.crt"),
            )?)?)
            .build()?;
        ensure!(
            client
                .put(format!("{}/mdm", peer.origin))
                .body("<plist/>")
                .send()
                .await
                .is_err(),
            "missing mTLS certificate admitted"
        );
        Ok(())
    }
    pub async fn native_boundaries(&mut self, peer: &Peer) -> Result<()> {
        let wrong = peer
            .send(
                "/mdm",
                protocol::dictionary([
                    ("Status", "Idle".into()),
                    ("UDID", "another-device".into()),
                ]),
            )
            .await?;
        ensure!(wrong.0 == StatusCode::UNAUTHORIZED);
        self.approval_and_timeout(peer).await?;
        self.profile_mismatch(peer).await?;
        let rejected = self
            .create_operation(json!({"kind":"profile_install","enabled":false}))
            .await?;
        let (id, _) = peer.next("InstallProfile").await?;
        peer.manage("CommandFormatError", Some(id), None).await?;
        ensure!(self.operation(rejected).await?["commandStatus"] == "rejected");
        // Token revision fences a late APNs 410 from an earlier token.
        let queued = self
            .create_operation(json!({"kind":"profile_install","enabled":true}))
            .await?;
        peer.token().await?;
        let old = self
            .app
            .commands
            .apple_wake()
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing wake"))?;
        peer.token().await?;
        self.app
            .commands
            .apple_pushed(&old, Some(410), push::Outcome::Unregistered)
            .await?;
        ensure!(
            !peer.manage("Idle", None, None).await?.is_empty(),
            "stale APNs receipt retired new token"
        );
        ensure!(self.operation(queued).await?["commandStatus"] == "published");
        let reply = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &format!("/api/v1/devices/{DEVICE}/collection-runs"),
                Some(json!({"source":"mdm.apple","requestId":Uuid::new_v4()})),
            )
            .await?;
        ensure!(reply.0 == StatusCode::ACCEPTED);
        let run = reply.1["runId"].as_str().unwrap();
        let checkout = peer
            .send(
                "/checkin",
                protocol::dictionary([
                    ("MessageType", "CheckOut".into()),
                    ("UDID", "rss-apple-t2".into()),
                ]),
            )
            .await?;
        ensure!(checkout.0 == StatusCode::OK);
        let stale = peer
            .send(
                "/mdm",
                protocol::dictionary([("Status", "Idle".into()), ("UDID", "rss-apple-t2".into())]),
            )
            .await?;
        ensure!(stale.0 == StatusCode::UNAUTHORIZED);
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        let result:(String,String,bool)=sqlx::query_as("SELECT result,reason,sealed_at IS NOT NULL FROM mdm_access.collection_runs WHERE id=$1::uuid").bind(run).fetch_one(&mut pg).await?;
        ensure!(
            result == ("failed".into(), "revoked".into(), true),
            "retirement left collection pending"
        );
        let active: i64 =
            sqlx::query_scalar("SELECT count(*) FROM mdm_apple.devices WHERE state='active'")
                .fetch_one(&mut pg)
                .await?;
        ensure!(active == 0);
        pg.close().await?;
        Ok(())
    }
    async fn profile_mismatch(&mut self, peer: &Peer) -> Result<()> {
        let op = self
            .create_operation(json!({"kind":"profile_install","enabled":true}))
            .await?;
        let (id, _) = peer.next("InstallProfile").await?;
        let wrong = peer
            .send(
                "/mdm",
                protocol::dictionary([
                    ("Status", "Acknowledged".into()),
                    ("UDID", "rss-apple-t2".into()),
                    ("CommandUUID", Uuid::new_v4().to_string().into()),
                ]),
            )
            .await?;
        ensure!(wrong.0 == StatusCode::CONFLICT);
        let next = peer.manage("Acknowledged", Some(id), None).await?;
        let (observe, _) = command(&next, "ProfileList")?;
        let wrong = plist::Value::Array(vec![plist::Value::Dictionary(protocol::dictionary([
            (
                "PayloadIdentifier",
                profile::identifier(TENANT, DEVICE).into(),
            ),
            ("PayloadUUID", Uuid::new_v4().to_string().into()),
        ]))]);
        peer.manage("Acknowledged", Some(observe), Some(("ProfileList", wrong)))
            .await?;
        let state = self.operation(op).await?;
        ensure!(
            state["commandStatus"] == "received" && state["observation"]["result"] == "mismatched",
            "mismatch became Applied {state}"
        );
        let path = format!("/api/v2/devices/{DEVICE}/operations");
        let overlap=self.browser.call(&self.router,Method::POST,&path,Some(json!({"operationId":Uuid::new_v4(),"task":{"kind":"profile_install","enabled":false},"deadline":self.app.clock.unix_seconds()?+300}))).await?;
        ensure!(
            overlap.0 == StatusCode::CONFLICT,
            "overlapping profile ownership admitted"
        );
        let cancelled = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &format!("{path}/{op}/cancel"),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":state["revision"]})),
            )
            .await?;
        ensure!(
            cancelled.0 == StatusCode::OK,
            "cancel mismatched profile {cancelled:?}"
        );
        Ok(())
    }
}

impl Fixture {
    pub async fn replace(&mut self, old: &Peer, old_device: &scep::Device) -> Result<Peer> {
        let (enrollment, attempt, password) = self.enrollment().await?;
        let reused = scep::Device::with_key(enrollment, attempt, &password, Some(&old_device.key))?;
        let apple = self.app.apple()?;
        let request = reused.request(
            &self.root.join("apple-issuer.pem"),
            &Uuid::new_v4().to_string(),
            self.app.clock.unix_seconds()?,
        )?;
        ensure!(
            reused
                .enroll(&self.client()?, &apple.config.scep_url, &request)
                .await
                .is_err(),
            "active SPKI reused by a new issuance attempt"
        );
        let device = scep::Device::new(enrollment, attempt, &password)?;
        let request = device.request(
            &self.root.join("apple-issuer.pem"),
            &Uuid::new_v4().to_string(),
            self.app.clock.unix_seconds()?,
        )?;
        let der = device
            .enroll(&self.client()?, &apple.config.scep_url, &request)
            .await?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .identity(device.identity(&der)?)
            .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                self.root.join("ca.crt"),
            )?)?)
            .build()?;
        let peer = Peer {
            client,
            oracle: oracle::Oracle::new(&der)?,
            origin: apple.config.management.origin.clone(),
            topic: apple.config.apns_topic.clone(),
        };
        let reply = peer
            .send(
                "/checkin",
                protocol::dictionary([
                    ("MessageType", "Authenticate".into()),
                    ("UDID", "rss-apple-t2".into()),
                    ("Topic", peer.topic.clone().into()),
                ]),
            )
            .await?;
        ensure!(
            reply.0 == StatusCode::OK,
            "replacement Authenticate {}",
            reply.0
        );
        peer.token().await?;
        let stale = old
            .send(
                "/mdm",
                protocol::dictionary([("Status", "Idle".into()), ("UDID", "rss-apple-t2".into())]),
            )
            .await?;
        ensure!(
            stale.0 == StatusCode::UNAUTHORIZED,
            "replaced leaf remained authorized"
        );
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        let rows:Vec<(i64,String)>=sqlx::query_as("SELECT generation,state FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 ORDER BY generation").bind(TENANT).bind(DEVICE).fetch_all(&mut pg).await?;
        ensure!(
            rows == vec![(1, "superseded".into()), (2, "active".into())],
            "registration generations {rows:?}"
        );
        pg.close().await?;
        Ok(peer)
    }
}

impl Fixture {
    async fn approval_and_timeout(&mut self, peer: &Peer) -> Result<()> {
        let op = self
            .create_operation(json!({"kind":"profile_install","enabled":true}))
            .await?;
        let path = format!("/api/v1/devices/{DEVICE}/collection-runs");
        let reply = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &path,
                Some(json!({"source":"mdm.apple","requestId":Uuid::new_v4()})),
            )
            .await?;
        ensure!(reply.0 == StatusCode::ACCEPTED);
        let run = reply.1["runId"].as_str().unwrap();
        crate::identity_fixture::set_grants(
            TENANT,
            crate::identity_fixture::ADMIN,
            crate::identity_fixture::device_grants(
                Some(DEVICE),
                &[
                    "enrollment",
                    "credentials",
                    "inventory_read",
                    "operation_read",
                    "operation_cancel",
                ],
            )?,
        )
        .await?;
        ensure!(
            peer.manage("Idle", None, None).await?.is_empty(),
            "revoked approval dispatched native work"
        );
        ensure!(self.operation(op).await?["authorization"] == "blocked");
        ensure!(
            self.app.commands.apple_wake().await?.is_none(),
            "revoked approval triggered APNs"
        );
        let cancelled = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &format!("/api/v2/devices/{DEVICE}/operations/{op}/cancel"),
                Some(json!({"requestId":Uuid::new_v4(),"expectedRevision":1})),
            )
            .await?;
        ensure!(cancelled.0 == StatusCode::OK);
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
            .bind(TENANT)
            .execute(&mut pg)
            .await?;
        // Provider time injection, not a fabricated device response or result.
        sqlx::query("UPDATE mdm_access.collection_runs SET apple_deadline=clock_timestamp()-interval '1 second' WHERE id=$1::uuid").bind(run).execute(&mut pg).await?;
        let mut terminal = false;
        for _ in 0..100 {
            let row:(String,Option<String>,bool)=sqlx::query_as("SELECT result,reason,batch IS NULL FROM mdm_access.collection_runs WHERE id=$1::uuid").bind(run).fetch_one(&mut pg).await?;
            if row == ("failed".into(), Some("timeout".into()), true) {
                terminal = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        ensure!(
            terminal,
            "unreported collection did not expire without an Observation report"
        );
        pg.close().await?;
        crate::identity_fixture::set_grants(
            TENANT,
            crate::identity_fixture::ADMIN,
            crate::identity_fixture::device_grants(
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
        Ok(())
    }
}
