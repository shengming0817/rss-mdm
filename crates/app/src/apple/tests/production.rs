//! The production serve path owns listeners, automatic APNs work, health and shutdown.
use super::*;
use sqlx::{Connection, Row};
impl Fixture {
    pub async fn production(mut self) -> Result<()> {
        // Finish a new real enrollment while the fixed CA's TLS webhook fixture is available.
        let (enrollment, attempt, password) = self.enrollment().await?;
        let device = scep::Device::new(enrollment, attempt, &password)?;
        let request = device.request(
            &self.root.join("apple-issuer.pem"),
            &Uuid::new_v4().to_string(),
            self.app.clock.unix_seconds()?,
        )?;
        let der = device
            .enroll(
                &self.client()?,
                &self.app.apple()?.config.scep_url,
                &request,
            )
            .await?;
        let peer = lifecycle::Peer {
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(15))
                .identity(device.identity(&der)?)
                .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                    self.root.join("ca.crt"),
                )?)?)
                .build()?,
            origin: self.app.apple()?.config.management.origin.clone(),
            topic: self.app.apple()?.config.apns_topic.clone(),
            oracle: oracle::Oracle::new(&der)?,
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
        ensure!(reply.0 == StatusCode::OK);
        peer.token().await?;
        let operation = self
            .create_operation(json!({"kind":"profile_install","enabled":true}))
            .await?;
        let participant = push::tests::Participant::start(vec![200], vec![42; 32]).await?;
        let mut config = crate::identity_fixture::config(TENANT)?;
        let port = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        config.listen = port.local_addr()?;
        drop(port);
        config.native_protocols.windows = None;
        let mut apple: config::Config =
            serde_json::from_slice(&std::fs::read(self.root.join("apple.json"))?)?;
        apple.management.listen = self.app.apple()?.config.management.listen;
        apple.management.origin = peer.origin.clone();
        apple.test_push_transport = Some((participant.origin(), self.root.join("ca.crt")));
        config.native_protocols.apple = Some(apple);
        let address = config.listen;
        let empty = rss_runtime::ShutdownStack::try_new(
            rss_runtime::TotalDrainBudget::new(Duration::from_secs(20))?,
            Arc::new(crate::lifecycle::RuntimeTimer),
        )?;
        let manual = std::mem::replace(&mut self.owner, empty);
        ensure!(manual.shutdown().join().await?.is_clean());
        let stop = tokio_util::sync::CancellationToken::new();
        let stopped = stop.clone();
        let server = tokio::spawn(crate::lifecycle::serve(
            config,
            async move {
                stopped.cancelled().await;
                Ok(())
            },
            fixture_clock(),
        ));
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()?;
        let ready = |client: reqwest::Client| async move {
            client
                .get(format!("http://{address}/readyz"))
                .header("host", "mdm.example.test")
                .send()
                .await
                .map(|r| r.status())
        };
        let mut online = false;
        for _ in 0..100 {
            if ready(client.clone()).await.ok() == Some(StatusCode::OK) {
                online = true;
                break;
            }
            if server.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !online {
            stop.cancel();
            anyhow::bail!(
                "production Apple startup did not become ready: {:?}",
                server.await?
            );
        }
        // Hits the listener bound by serve, without resetting an already accepted push.
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
        ensure!(reply.0 == StatusCode::OK);
        let mut pg =
            sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?).await?;
        let mut accepted = false;
        for _ in 0..100 {
            let row = sqlx::query(
                "SELECT push_status,push_outcome FROM mdm_apple.devices WHERE state='active'",
            )
            .fetch_one(&mut pg)
            .await?;
            if row.try_get::<Option<i32>, _>("push_status")? == Some(200)
                && row.try_get::<Option<String>, _>("push_outcome")?.as_deref() == Some("accepted")
            {
                accepted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        ensure!(
            accepted,
            "production APNs worker never delivered pending work"
        );
        ensure!(self.operation(operation).await?["commandStatus"] == "published");
        // APNs-only table failure must affect readiness even while general DB checks still work.
        sqlx::query("REVOKE SELECT ON mdm_apple.devices FROM mdm_command_runtime")
            .execute(&mut pg)
            .await?;
        let mut unhealthy = false;
        for _ in 0..120 {
            if ready(client.clone()).await.ok() == Some(StatusCode::SERVICE_UNAVAILABLE) {
                unhealthy = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        sqlx::query("GRANT SELECT ON mdm_apple.devices TO mdm_command_runtime")
            .execute(&mut pg)
            .await?;
        ensure!(
            unhealthy,
            "persistent APNs storage failure left readiness green"
        );
        let mut recovered = false;
        for _ in 0..180 {
            if ready(client.clone()).await.ok() == Some(StatusCode::OK) {
                recovered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        ensure!(
            recovered,
            "APNs worker did not restore readiness after storage recovery"
        );
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(45), server).await???;
        participant.close().await?;
        ensure!(
            tokio::net::TcpStream::connect(address).await.is_err(),
            "browser listener survived shutdown"
        );
        ensure!(
            tokio::net::TcpStream::connect(self.app.apple()?.config.management.listen)
                .await
                .is_err(),
            "native listener survived shutdown"
        );
        ensure!(self.owner.shutdown().join().await?.is_clean());
        pg.close().await?;
        Ok(())
    }
}
