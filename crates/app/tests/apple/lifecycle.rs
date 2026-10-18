//! Native responses drive product receipts; database inspection never manufactures evidence.
use super::*;
use serde_json::Value;

pub(super) struct Peer {
    pub client: reqwest::Client,
    pub origin: String,
    pub topic: String,
    pub oracle: oracle::Oracle,
    pub installed_trust: tokio::sync::Mutex<Option<plist::Dictionary>>,
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
    async fn manage_raw(
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
    /// Simulated native storage installs the exact independent trust Profile and
    /// returns its complete ProfileList before exposing business commands.
    pub async fn manage(
        &self,
        status: &str,
        id: Option<Uuid>,
        mut extra: Option<(&str, plist::Value)>,
    ) -> Result<Vec<u8>> {
        if let Some(("ProfileList", plist::Value::Array(profiles))) = extra.as_mut()
            && let Some(installed) = self.installed_trust.lock().await.as_ref()
        {
            profiles.push(plist::Value::Dictionary(installed.clone()));
        }
        use x509_cert::der::{Decode, asn1::OctetString};
        let mut bytes = self.manage_raw(status, id, extra).await?;
        for _ in 0..4 {
            if bytes.is_empty() {
                return Ok(bytes);
            }
            let message = protocol::decode(&bytes)?;
            let payload = message["Command"].as_dictionary().unwrap();
            if payload.get("RequestType").and_then(plist::Value::as_string)
                != Some("InstallProfile")
            {
                return Ok(bytes);
            }
            let data = payload["Payload"]
                .as_data()
                .ok_or_else(|| anyhow::anyhow!("signed Profile required"))?;
            let cms = cms::content_info::ContentInfo::from_der(data)?
                .content
                .decode_as::<cms::signed_data::SignedData>()?;
            let content = cms
                .encap_content_info
                .econtent
                .ok_or_else(|| anyhow::anyhow!("Profile content required"))?
                .decode_as::<OctetString>()?;
            let installed = protocol::decode(content.as_bytes())?;
            if !protocol::text(&installed, "PayloadIdentifier")?.starts_with("com.rss-mdm.pki.") {
                return Ok(bytes);
            }
            // ProfileList reports installed identities, not the configuration
            // payload's DER certificate data or installation-only fields.
            let mut summary = plist::Dictionary::new();
            for key in ["PayloadIdentifier", "PayloadUUID", "PayloadVersion"] {
                summary.insert(key.into(), installed[key].clone());
            }
            let children = installed["PayloadContent"]
                .as_array()
                .unwrap()
                .iter()
                .map(|child| {
                    let child = child.as_dictionary().unwrap();
                    let mut item = plist::Dictionary::new();
                    for key in [
                        "PayloadIdentifier",
                        "PayloadUUID",
                        "PayloadType",
                        "PayloadVersion",
                    ] {
                        item.insert(key.into(), child[key].clone());
                    }
                    plist::Value::Dictionary(item)
                })
                .collect();
            summary.insert("PayloadContent".into(), plist::Value::Array(children));
            *self.installed_trust.lock().await = Some(summary.clone());
            let id = Uuid::parse_str(protocol::text(&message, "CommandUUID")?)?;
            let query = self.manage_raw("Acknowledged", Some(id), None).await?;
            let (read_id, _) = command(&query, "ProfileList")?;
            let manifest = plist::Value::Array(vec![plist::Value::Dictionary(summary)]);
            bytes = self
                .manage_raw(
                    "Acknowledged",
                    Some(read_id),
                    Some(("ProfileList", manifest)),
                )
                .await?;
        }
        anyhow::bail!("trust Profile exchange exceeded the fixture bound")
    }
    pub async fn next(&self, kind: &str) -> Result<(Uuid, plist::Dictionary)> {
        command(&self.next_bytes(kind).await?, kind)
    }
    pub async fn next_security(&self) -> Result<(Uuid, plist::Dictionary)> {
        command(
            &self.next_bytes_mode("SecurityInfo", true).await?,
            "SecurityInfo",
        )
    }
    pub async fn next_collection(&self) -> Result<(Uuid, plist::Dictionary)> {
        command(
            &self.next_bytes_mode("DeviceInformation", true).await?,
            "DeviceInformation",
        )
    }
    pub async fn next_bytes(&self, kind: &str) -> Result<Vec<u8>> {
        self.next_bytes_mode(kind, false).await
    }
    async fn next_bytes_mode(&self, kind: &str, collection: bool) -> Result<Vec<u8>> {
        let mut resolving = false;
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
                let prerequisite_device = actual == "DeviceInformation"
                    && payload.get("Queries")
                        == Some(&plist::Value::Array(vec![
                            "OSVersion".into(),
                            "IsSupervised".into(),
                            "IsAppleSilicon".into(),
                        ]));
                if actual == kind
                    && (!collection
                        || !(prerequisite_device || actual == "SecurityInfo" && resolving))
                {
                    return Ok(bytes);
                }
                if prerequisite_device {
                    resolving = true;
                } else if actual == "SecurityInfo" {
                    resolving = false;
                }
                let response = match actual {
                    "DeviceInformation"
                        if payload.get("Queries")
                            == Some(&plist::Value::Array(vec![
                                "OSVersion".into(),
                                "IsSupervised".into(),
                                "IsAppleSilicon".into(),
                            ])) =>
                    {
                        (
                            "QueryResponses",
                            plist::Value::Dictionary(protocol::dictionary([
                                ("OSVersion", "15.0".into()),
                                ("IsSupervised", true.into()),
                                ("IsAppleSilicon", true.into()),
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
            // Keep idle polling below the native peer admission rate (four requests/second).
            tokio::time::sleep(Duration::from_millis(300)).await;
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
                    "/api/v1/devices/{DEVICE}/operations/{id}",
                    DEVICE = case_device()
                ),
                None,
            )
            .await?;
        ensure!(reply.0 == StatusCode::OK, "operation read: {reply:?}");
        Ok(reply.1)
    }
    pub(super) async fn create_restart(&mut self) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let body = json!({"operationId":id,"action":{"kind":"restart"},"deadline":self.app.clock.unix_seconds()?+300});
        let path = format!("/api/v1/devices/{}/operations", case_device());
        let reply = self
            .browser
            .call(&self.router, Method::POST, &path, Some(body.clone()))
            .await?;
        ensure!(reply.0 == StatusCode::ACCEPTED, "restart: {reply:?}");
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
        anyhow::bail!("restart publication deadline")
    }
}
