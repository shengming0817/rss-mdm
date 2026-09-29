use super::*;
use lifecycle::Peer;
use sqlx::Connection;
impl Fixture {
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
            let mut pg = sqlx::PgConnection::connect_with(&crate::device::test_support::options(
                "postgres",
            )?)
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
                let delivered: bool = sqlx::query_scalar(
                    "SELECT NOT delivery_pending FROM mdm_access.collection_runs WHERE id=$1::uuid",
                )
                .bind(run.to_string())
                .fetch_one(&mut pg)
                .await?;
                if delivered
                    && rows
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
            let asset = self
                .browser
                .call(
                    &self.router,
                    Method::GET,
                    &format!("/api/v2/devices/{DEVICE}/inventory"),
                    None,
                )
                .await?;
            ensure!(
                asset.0 == StatusCode::OK,
                "Apple asset read failed: {asset:?}"
            );
            ensure!(
                asset.1["asset"]["device"]["fields"]["device.model"]["state"]["value"]["value"]
                    == "Mac14,7"
            );
            ensure!(
                asset.1["asset"]["device"]["fields"]["device.os.version"]["state"]["value"]["value"]
                    == "14.7"
            );
        }
        Ok(())
    }
}

#[tokio::test]
#[ignore = "MODULE=apple.collection: native protocol and durable state"]
async fn collection_lifecycle() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (peer, device) = f.ready_local_peer().await?;
    f.collection_cycle(&peer).await?;
    drop(device);
    f.close().await
}
