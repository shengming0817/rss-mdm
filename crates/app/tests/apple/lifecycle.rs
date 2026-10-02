//! Native responses drive product receipts; database inspection never manufactures evidence.
use super::*;
use serde_json::Value;

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
        self.token_value(42).await
    }
    pub async fn token_value(&self, value: u8) -> Result<()> {
        let reply = self
            .send(
                "/checkin",
                protocol::dictionary([
                    ("MessageType", "TokenUpdate".into()),
                    (
                        "UDID",
                        crate::test_support::case::name("rss-t2-apple").into(),
                    ),
                    ("Topic", self.topic.clone().into()),
                    ("Token", plist::Value::Data(vec![value; 32])),
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
        let mut d = protocol::dictionary([
            ("Status", status.into()),
            (
                "UDID",
                crate::test_support::case::name("rss-t2-apple").into(),
            ),
        ]);
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
        command(&self.next_bytes(kind).await?, kind)
    }
    pub async fn next_bytes(&self, kind: &str) -> Result<Vec<u8>> {
        for _ in 0..100 {
            let mut bytes = self.manage("Idle", None, None).await?;
            for _ in 0..128 {
                if bytes.is_empty() {
                    break;
                }
                let dictionary = protocol::decode(&bytes)?;
                let id = Uuid::parse_str(protocol::text(&dictionary, "CommandUUID")?)?;
                let payload = dictionary["Command"].as_dictionary().unwrap();
                let actual = protocol::text(payload, "RequestType")?;
                if actual == kind {
                    return Ok(bytes);
                }
                let response = match actual {
                    "DeviceInformation"
                        if payload.get("Queries")
                            == Some(&plist::Value::Array(vec![
                                "OSVersion".into(),
                                "IsSupervised".into(),
                            ])) =>
                    {
                        (
                            "QueryResponses",
                            plist::Value::Dictionary(protocol::dictionary([
                                ("OSVersion", "15.0".into()),
                                ("IsSupervised", true.into()),
                            ])),
                        )
                    }
                    "SecurityInfo" => (
                        "SecurityInfo",
                        plist::Value::Dictionary(protocol::dictionary([(
                            "ManagementStatus",
                            plist::Value::Dictionary(protocol::dictionary([
                                ("EnrolledViaDEP", false.into()),
                                ("UserApprovedEnrollment", true.into()),
                                ("IsUserEnrollment", false.into()),
                            ])),
                        )])),
                    ),
                    _ => {
                        command(&bytes, kind)?;
                        return Ok(bytes);
                    }
                };
                bytes = self
                    .manage("Acknowledged", Some(id), Some(response))
                    .await?;
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
                &format!(
                    "/api/v3/devices/{DEVICE}/operations/{id}",
                    DEVICE = case_device()
                ),
                None,
            )
            .await?;
        ensure!(reply.0 == StatusCode::OK, "operation read: {reply:?}");
        Ok(reply.1)
    }
    pub(super) async fn create_operation(
        &mut self,
        task: impl FnOnce(Uuid) -> Value,
    ) -> Result<Uuid> {
        self.create_operation_at(Uuid::new_v4(), task).await
    }
    pub(super) async fn create_operation_at(
        &mut self,
        id: Uuid,
        task: impl FnOnce(Uuid) -> Value,
    ) -> Result<Uuid> {
        let body = json!({"operationId":id,"inputVersion":"1","target":{"kind":"device"},"task":task(id),"deadline":self.app.clock.unix_seconds()?+300});
        let path = format!(
            "/api/v3/devices/{DEVICE}/operations",
            DEVICE = case_device()
        );
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
}
