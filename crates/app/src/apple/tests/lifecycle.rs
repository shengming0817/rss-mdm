//! Native responses drive product receipts; database inspection never manufactures evidence.
use super::*;
use serde_json::Value;
use sqlx::Connection;

pub(super) struct Peer {
    pub client: reqwest::Client,
    pub origin: String,
    pub topic: String,
    pub oracle: oracle::Oracle,
}
impl Peer {
    pub async fn send(&self, path: &str, d: plist::Dictionary) -> Result<(StatusCode, Vec<u8>)> {
        let request = protocol::xml(d)?;
        let response = self
            .client
            .put(format!("{}{path}", self.origin))
            .header("content-type", "application/xml")
            .body(request.clone())
            .send()
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?.to_vec();
        if status == StatusCode::OK {
            self.oracle.compare(path, &request, &bytes).await?;
        }
        Ok((status, bytes))
    }
    pub async fn token(&self) -> Result<()> {
        let reply = self
            .send(
                "/checkin",
                protocol::dictionary([
                    ("MessageType", "TokenUpdate".into()),
                    ("UDID", "rss-apple-t2".into()),
                    ("Topic", self.topic.clone().into()),
                    ("Token", plist::Value::Data(vec![42; 32])),
                    ("PushMagic", "fixture-magic".into()),
                ]),
            )
            .await?;
        ensure!(reply.0 == StatusCode::OK, "TokenUpdate: {}", reply.0);
        Ok(())
    }
    pub async fn manage(
        &self,
        status: &str,
        id: Option<Uuid>,
        extra: Option<(&str, plist::Value)>,
    ) -> Result<Vec<u8>> {
        let mut d =
            protocol::dictionary([("Status", status.into()), ("UDID", "rss-apple-t2".into())]);
        if let Some(id) = id {
            d.insert("CommandUUID".into(), id.to_string().into());
        }
        if let Some((key, value)) = extra {
            d.insert(key.into(), value);
        }
        let reply = self.send("/mdm", d).await?;
        ensure!(
            reply.0 == StatusCode::OK,
            "native {status}: {} {}",
            reply.0,
            String::from_utf8_lossy(&reply.1)
        );
        Ok(reply.1)
    }
    pub async fn next(&self, kind: &str) -> Result<(Uuid, plist::Dictionary)> {
        for _ in 0..100 {
            let bytes = self.manage("Idle", None, None).await?;
            if !bytes.is_empty() {
                return command(&bytes, kind);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        anyhow::bail!("native {kind} dispatch deadline")
    }
}
pub(super) fn command(bytes: &[u8], kind: &str) -> Result<(Uuid, plist::Dictionary)> {
    let d = protocol::decode(bytes)?;
    let id = Uuid::parse_str(protocol::text(&d, "CommandUUID")?)?;
    let payload = d["Command"].as_dictionary().unwrap().clone();
    ensure!(
        payload["RequestType"].as_string() == Some(kind),
        "unexpected command: {payload:?}"
    );
    Ok((id, payload))
}
impl Fixture {
    pub(super) async fn operation(&mut self, id: Uuid) -> Result<Value> {
        let reply = self
            .browser
            .call(
                &self.router,
                Method::GET,
                &format!("/api/v2/devices/{DEVICE}/operations/{id}"),
                None,
            )
            .await?;
        ensure!(reply.0 == StatusCode::OK, "operation read: {reply:?}");
        Ok(reply.1)
    }
    pub(super) async fn create_operation(&mut self, task: Value) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let body =
            json!({"operationId":id,"task":task,"deadline":self.app.clock.unix_seconds()?+300});
        let path = format!("/api/v2/devices/{DEVICE}/operations");
        let reply = self
            .browser
            .call(&self.router, Method::POST, &path, Some(body.clone()))
            .await?;
        ensure!(reply.0 == StatusCode::ACCEPTED, "create profile: {reply:?}");
        ensure!(
            self.browser
                .call(&self.router, Method::POST, &path, Some(body))
                .await?
                == reply
        );
        for _ in 0..100 {
            if self.operation(id).await?["commandStatus"] == "published" {
                return Ok(id);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        anyhow::bail!("profile publication deadline")
    }
    pub async fn collection_cycle(&mut self, peer: &Peer) -> Result<()> {
        for (model, version, result) in [
            ("Mac14,7", Some("14.7"), "snapshot"),
            ("Mac14,8", None, "partial"),
        ] {
            let request = Uuid::new_v4();
            let body = json!({"source":"mdm.apple","requestId":request});
            let path = format!("/api/v1/devices/{DEVICE}/collection-runs");
            let reply = self
                .browser
                .call(&self.router, Method::POST, &path, Some(body.clone()))
                .await?;
            ensure!(
                reply.0 == StatusCode::ACCEPTED,
                "collection create: {reply:?}"
            );
            ensure!(
                self.browser
                    .call(&self.router, Method::POST, &path, Some(body))
                    .await?
                    == reply
            );
            let run = Uuid::parse_str(reply.1["runId"].as_str().unwrap())?;
            let (id, payload) = peer.next("DeviceInformation").await?;
            ensure!(
                id == run
                    && payload["Queries"].as_array().unwrap()
                        == &vec![plist::Value::from("Model"), plist::Value::from("OSVersion")]
            );
            let mut values = protocol::dictionary([("Model", model.into())]);
            if let Some(version) = version {
                values.insert("OSVersion".into(), version.into());
            }
            let extra = Some(("QueryResponses", plist::Value::Dictionary(values)));
            ensure!(
                peer.manage("Acknowledged", Some(id), extra.clone())
                    .await?
                    .is_empty()
            );
            ensure!(
                peer.manage("Acknowledged", Some(id), extra)
                    .await?
                    .is_empty()
            );
            let read = self
                .browser
                .call(
                    &self.router,
                    Method::GET,
                    &format!("{path}/{run}?source=mdm.apple"),
                    None,
                )
                .await?;
            ensure!(
                read.0 == StatusCode::OK && read.1["run"]["result"] == result,
                "collection read {read:?}"
            );
            ensure!(
                read.1["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|f| f["status"].is_null()),
                "Apple created SyncML status"
            );
            let mut pg =
                sqlx::PgConnection::connect_with(&crate::device::tests::options("postgres")?)
                    .await?;
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM rss_device_command.commands WHERE command_id=$1",
            )
            .bind(run.to_string())
            .fetch_one(&mut pg)
            .await?;
            ensure!(count == 0, "DeviceInformation became a device command");
            // Read actual Inventory projection, waiting only for the real worker.
            let mut projected = false;
            for _ in 0..100 {
                let rows:Vec<(String,Option<String>)>=sqlx::query_as("SELECT field,value FROM mdm.inventory WHERE tenant_id=$1::uuid AND source='mdm.apple' ORDER BY field").bind(TENANT).fetch_all(&mut pg).await?;
                if rows
                    == vec![
                        ("device.model".into(), Some("Mac14,7".into())),
                        ("device.os.version".into(), Some("14.7".into())),
                    ]
                {
                    projected = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if !projected {
                let read = self
                    .browser
                    .call(
                        &self.router,
                        Method::GET,
                        &format!("{path}/{run}?source=mdm.apple"),
                        None,
                    )
                    .await?;
                let rows:Vec<(String,Option<String>)>=sqlx::query_as("SELECT field,value FROM mdm.inventory WHERE tenant_id=$1::uuid AND source='mdm.apple' ORDER BY field").bind(TENANT).fetch_all(&mut pg).await?;
                anyhow::bail!("Inventory did not preserve partial response: {read:?}; {rows:?}")
            }
            pg.close().await?;
        }
        Ok(())
    }
    pub async fn profile_cycle(&mut self, peer: &Peer) -> Result<()> {
        let installed = self
            .create_operation(json!({"kind":"profile_install","enabled":true}))
            .await?;
        let (execute, payload) = peer.next("InstallProfile").await?;
        ensure!(payload["Payload"].as_data().is_some());
        // Push acceptance is a wake-up receipt and cannot turn Published into Received.
        let wake = self
            .app
            .commands
            .apple_wake()
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing durable APNs wake"))?;
        self.app
            .commands
            .apple_pushed(&wake, Some(200), push::Outcome::Accepted)
            .await?;
        ensure!(self.operation(installed).await?["commandStatus"] == "published");
        ensure!(peer.manage("NotNow", Some(execute), None).await?.is_empty());
        ensure!(self.operation(installed).await?["commandStatus"] == "published");
        let bytes = peer.manage("Acknowledged", Some(execute), None).await?;
        let (observe, _) = command(&bytes, "ProfileList")?;
        ensure!(self.operation(installed).await?["commandStatus"] == "received");
        let profiles = plist::Value::Array(vec![plist::Value::Dictionary(protocol::dictionary([
            (
                "PayloadIdentifier",
                profile::identifier(TENANT, DEVICE).into(),
            ),
            ("PayloadUUID", installed.to_string().into()),
            ("PayloadVersion", 1.into()),
        ]))]);
        ensure!(
            peer.manage(
                "Acknowledged",
                Some(observe),
                Some(("ProfileList", profiles.clone()))
            )
            .await?
            .is_empty()
        );
        ensure!(
            peer.manage(
                "Acknowledged",
                Some(observe),
                Some(("ProfileList", profiles))
            )
            .await?
            .is_empty()
        );
        let read = self.operation(installed).await?;
        ensure!(
            read["commandStatus"] == "applied"
                && read["observation"]["result"] == "matched"
                && read["observation"]["effect"] == "unknown",
            "profile presence receipt {read}"
        );
        let removed = self
            .create_operation(json!({"kind":"profile_remove","profile":installed}))
            .await?;
        let (execute, payload) = peer.next("RemoveProfile").await?;
        ensure!(
            payload["Identifier"].as_string() == Some(profile::identifier(TENANT, DEVICE).as_str())
        );
        let bytes = peer.manage("Acknowledged", Some(execute), None).await?;
        let (observe, _) = command(&bytes, "ProfileList")?;
        ensure!(self.operation(removed).await?["commandStatus"] == "received");
        peer.manage(
            "Acknowledged",
            Some(observe),
            Some(("ProfileList", plist::Value::Array(vec![]))),
        )
        .await?;
        ensure!(self.operation(removed).await?["commandStatus"] == "applied");
        Ok(())
    }
}
