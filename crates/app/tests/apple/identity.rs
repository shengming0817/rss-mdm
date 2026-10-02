use super::*;
use crate::apple::push;
use lifecycle::Peer;
use sqlx::Connection;
impl Fixture {
    pub async fn before_token(&mut self, peer: &Peer) -> Result<()> {
        for path in [
            format!("/api/v3/enrollments/{}/profile", Uuid::new_v4()),
            format!(
                "/api/v1/devices/{DEVICE}/collection-runs",
                DEVICE = case_device()
            ),
        ] {
            for body in [
                json!(null),
                json!({}),
                json!({"source":"mdm.apple","requestId":Uuid::new_v4(),"password":"invalid","unknown":true}),
            ] {
                let reply = self
                    .browser
                    .call(&self.router, Method::POST, &path, Some(body))
                    .await?;
                ensure!(
                    reply.0 == StatusCode::BAD_REQUEST
                        && reply.1 == json!({"code":"malformed_request"}),
                    "noncanonical Apple JSON rejection: {reply:?}"
                );
            }
        }
        let reply = peer
            .send(
                "/mdm",
                protocol::dictionary([
                    ("Status", "Idle".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                ]),
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
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                ]),
            )
            .await?;
        ensure!(reply.0 == StatusCode::GONE);
        let reply = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &format!(
                    "/api/v1/devices/{DEVICE}/collection-runs",
                    DEVICE = case_device()
                ),
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
    pub async fn replace(&mut self, old: &Peer, old_device: &scep_client::Device) -> Result<Peer> {
        let (enrollment, attempt, password) = self.enrollment().await?;
        let reused =
            scep_client::Device::with_key(enrollment, attempt, &password, Some(&old_device.key))?;
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
        let device = scep_client::Device::new(enrollment, attempt, &password)?;
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
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
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
                protocol::dictionary([
                    ("Status", "Idle".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                ]),
            )
            .await?;
        ensure!(
            stale.0 == StatusCode::UNAUTHORIZED,
            "replaced leaf remained authorized"
        );
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let rows:Vec<(i64,String)>=sqlx::query_as("SELECT generation,state FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 ORDER BY generation").bind(case_tenant()).bind(case_device()).fetch_all(&mut pg).await?;
        ensure!(
            rows == vec![(1, "superseded".into()), (2, "active".into())],
            "registration generations {rows:?}"
        );
        pg.close().await?;
        Ok(peer)
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
        let rejected = self.create_operation(|id| profile_task(id, false)).await?;
        let (id, _) = peer.next("InstallProfile").await?;
        peer.manage("CommandFormatError", Some(id), None).await?;
        ensure!(self.operation(rejected).await?["commandStatus"] == "rejected");
        // Token revision fences a late APNs 410 from an earlier token.
        let queued = self.create_operation(|id| profile_task(id, true)).await?;
        peer.token_value(43).await?;
        let mut token_observer =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let revision: i64 =
            sqlx::query_scalar("SELECT token_revision FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration IN (SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2) AND state='active'")
                .bind(case_tenant()).bind(case_device()).fetch_one(&mut token_observer)
                .await?;
        let facts_before = crate::audit_test_support::read(&mut token_observer)
            .await?
            .into_iter()
            .filter(|r| r.source() == "mdm.business" && r.action() == "apple_checkin")
            .count();
        peer.token_value(43).await?;
        ensure!(
            sqlx::query_scalar::<_, i64>(
                "SELECT token_revision FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration IN (SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2) AND state='active'"
            )
            .bind(case_tenant()).bind(case_device()).fetch_one(&mut token_observer)
            .await?
                == revision
        );
        ensure!(
            crate::audit_test_support::read(&mut token_observer)
                .await?
                .into_iter()
                .filter(|r| r.source() == "mdm.business" && r.action() == "apple_checkin")
                .count()
                == facts_before,
            "unchanged TokenUpdate duplicated business facts"
        );
        token_observer.close().await?;
        let old = self
            .app
            .execution
            .apple_wake(&self.app.apple()?.channel.push_fixture().configuration)
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing wake"))?;
        peer.token_value(44).await?;
        self.app
            .execution
            .apple_pushed(&old, Some(410), push::Outcome::Unregistered)
            .await?;
        ensure!(
            !peer.manage("Idle", None, None).await?.is_empty(),
            "stale APNs receipt retired new token"
        );
        ensure!(self.operation(queued).await?["commandStatus"] == "published");
        self.pending_collections(65).await?;
        let reply = self
            .browser
            .call(
                &self.router,
                Method::POST,
                &format!(
                    "/api/v1/devices/{DEVICE}/collection-runs",
                    DEVICE = case_device()
                ),
                Some(json!({"source":"mdm.apple","requestId":Uuid::new_v4()})),
            )
            .await?;
        ensure!(reply.0 == StatusCode::ACCEPTED);
        let run = reply.1["runId"].as_str().unwrap();
        let mut pending_reader =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let pending: Vec<String> = sqlx::query_scalar("SELECT id::text FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND sealed_at IS NULL AND registration IN (SELECT d.registration FROM mdm_apple.devices d JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(d.tenant_id,d.registration) WHERE d.tenant_id=$1::uuid AND r.device=$2 AND d.state='active')").bind(case_tenant()).bind(case_device()).fetch_all(&mut pending_reader).await?;
        ensure!(
            pending.len() >= 65,
            "retirement must exercise the real accumulated collection backlog"
        );
        let checkout = peer
            .send(
                "/checkin",
                protocol::dictionary([
                    ("MessageType", "CheckOut".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                ]),
            )
            .await?;
        ensure!(checkout.0 == StatusCode::OK);
        let facts = crate::audit_test_support::read(&mut pending_reader).await?;
        for id in pending {
            ensure!(
                facts
                    .iter()
                    .filter(|record| record.source() == "mdm.business"
                        && record.action() == "collection_finish"
                        && record.operation() == Some(id.as_str()))
                    .count()
                    == 1,
                "each retired collection requires exactly one terminal fact"
            );
        }
        pending_reader.close().await?;
        let stale = peer
            .send(
                "/mdm",
                protocol::dictionary([
                    ("Status", "Idle".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                ]),
            )
            .await?;
        ensure!(stale.0 == StatusCode::UNAUTHORIZED);
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let result:(String,String,bool)=sqlx::query_as("SELECT result,reason,sealed_at IS NOT NULL FROM mdm_access.collection_runs WHERE id=$1::uuid").bind(run).fetch_one(&mut pg).await?;
        ensure!(
            result == ("failed".into(), "revoked".into(), true),
            "retirement left collection pending"
        );
        let terminal = crate::audit_test_support::read(&mut pg).await?;
        ensure!(terminal.iter().any(|r| r.action() == "collection_finish"
            && r.operation() == Some(run.to_string().as_str())
            && r.actor() == Some("service:collection-finalizer")));
        let active: i64 =
            sqlx::query_scalar("SELECT count(*) FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration IN (SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2) AND state='active'").bind(case_tenant()).bind(case_device())
                .fetch_one(&mut pg)
                .await?;
        ensure!(active == 0);
        pg.close().await?;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "MODULE=apple.identity: native protocol and durable state"]
async fn replacement_token_fencing_and_retirement() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_scep_peer().await?;
    let replacement = f.replace(&peer, &device).await?;
    f.native_boundaries(&replacement).await?;
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.identity: pending token and native authority admission"]
async fn token_is_required_before_management() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (device, der) = f.scep_leaf().await?;
    let peer = f.authenticate_peer(&device, &der).await?;
    f.before_token(&peer).await?;
    peer.token().await?;
    let reply = peer
        .send(
            "/mdm",
            protocol::dictionary([
                ("Status", "Idle".into()),
                (
                    "UDID",
                    crate::test_support::case::name("rss-t2-apple").into(),
                ),
            ]),
        )
        .await?;
    ensure!(reply.0 == StatusCode::OK);
    ensure!(
        crate::test_support::audit_count(|r| r.action() == "apple_management"
            && r.status() == 200
            && r.actor()
                == r.payload["registration"]
                    .as_str()
                    .map(|id| format!("device:{id}"))
                    .as_deref())?
            >= 1,
        "successful management audit must identify the verified device registration"
    );
    f.close().await
}
