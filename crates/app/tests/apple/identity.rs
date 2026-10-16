use super::*;
use lifecycle::Peer;
use sqlx::Connection;
impl Fixture {
    pub async fn before_token(&mut self, peer: &Peer) -> Result<()> {
        self.policy_grants().await?;
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
        ensure!(reply.0 == StatusCode::BAD_REQUEST);
        let definition = self.collection_template().await?;
        let owner = self.policy_worker().await?;
        let preview = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let response = self
                    .browser
                    .call(
                        &self.router,
                        Method::POST,
                        "/api/v1/policies/previews",
                        Some(json!({"definition":definition})),
                    )
                    .await?;
                if response.0 == StatusCode::OK {
                    return Ok::<_, anyhow::Error>(response.1);
                }
                ensure!(
                    response.0 == StatusCode::CONFLICT,
                    "pending-token preview: {response:?}"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        crate::test_support::stop_worker(Some(owner)).await?;
        let preview = preview??;
        let items = preview["items"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("missing preview objects: {preview:?}"))?;
        ensure!(
            items.len() == 1 && items[0]["availability"] == "unavailable",
            "pending token admitted template or omitted its object: {preview:?}"
        );
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let effects: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid)+(SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid)").bind(case_tenant()).fetch_one(&mut pg).await?;
        ensure!(
            effects == 0,
            "preview published collection work before TokenUpdate"
        );
        pg.close().await?;
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
                .enroll(&self.client()?, &apple.channel.scep_fixture()?.0, &request)
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
            .enroll(&self.client()?, &apple.channel.scep_fixture()?.0, &request)
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
            installed_trust: Default::default(),
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
        self.native_context(peer).await?;
        self.grant_native_actions(&["device_control"]).await?;
        let rejected = self.create_restart().await?;
        let (id, _) = peer.next("RestartDevice").await?;
        peer.manage("CommandFormatError", Some(id), None).await?;
        ensure!(self.operation(rejected).await?["commandStatus"] == "rejected");
        // Token revision fences a late APNs 410 from an earlier token.
        let queued = self.create_restart().await?;
        peer.token_value(43).await?;
        let mut token_observer =
            sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
                .await?;
        let revision: i64 =
            sqlx::query_scalar("SELECT token_revision FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND registration IN (SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2) AND state='active'")
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
                "SELECT token_revision FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND registration IN (SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2) AND state='active'"
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
            .apple_pushed(
                &old,
                Some(410),
                rss_mdm_execution_service::channels::PushOutcome::Unregistered,
            )
            .await?;
        ensure!(
            !peer.manage("Idle", None, None).await?.is_empty(),
            "stale APNs receipt retired new token"
        );
        ensure!(self.operation(queued).await?["commandStatus"] == "published");
        self.policy_grants().await?;
        let definition = self.collection_template().await?;
        let owner = self.policy_worker().await?;
        let queued = self.pending_collections(&definition, 66).await;
        crate::test_support::stop_worker(Some(owner)).await?;
        let runs = queued?;
        let run = runs[65];
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
    let (device, der) = f.seed_local_identity().await?;
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
