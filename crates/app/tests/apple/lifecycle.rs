//! Native responses drive product receipts; database inspection never manufactures evidence.
use super::*;
use serde_json::Value;

pub(super) struct Peer {
    pub client: reqwest::Client,
    pub origin: String,
    pub topic: String,
    pub oracle: oracle::Oracle,
    pub pending_replies: tokio::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
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
            let summary = installed_profile(payload)?;
            if !protocol::text(&summary, "PayloadIdentifier")?.starts_with("com.rss-mdm.pki.") {
                return Ok(bytes);
            }
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
    pub async fn confirm_managed_profile(
        &self,
        id: Uuid,
        payload: &plist::Dictionary,
    ) -> Result<Vec<u8>> {
        let summary = installed_profile(payload)?;
        let query = self.manage("Acknowledged", Some(id), None).await?;
        if !query.is_empty() {
            self.pending_replies.lock().await.push_back(query);
        }
        let (read_id, _) = Box::pin(self.next("ProfileList")).await?;
        self.manage(
            "Acknowledged",
            Some(read_id),
            Some(("ProfileList", plist::Value::Array(vec![summary.into()]))),
        )
        .await
    }
    pub async fn next(&self, kind: &str) -> Result<(Uuid, plist::Dictionary)> {
        command(&self.next_bytes(kind).await?, kind)
    }
    pub async fn next_security(&self) -> Result<(Uuid, plist::Dictionary)> {
        command(
            &self.next_bytes_mode("SecurityInfo", true, None).await?,
            "SecurityInfo",
        )
    }
    pub async fn next_collection(&self) -> Result<(Uuid, plist::Dictionary)> {
        command(
            &self
                .next_bytes_mode("DeviceInformation", true, None)
                .await?,
            "DeviceInformation",
        )
    }
    pub async fn next_bytes(&self, kind: &str) -> Result<Vec<u8>> {
        self.next_bytes_mode(kind, false, None).await
    }
    pub async fn next_managed(
        &self,
        kind: &str,
        bootstrap: &mut Option<plist::Dictionary>,
    ) -> Result<(Uuid, plist::Dictionary)> {
        command(
            &self.next_bytes_mode(kind, false, Some(bootstrap)).await?,
            kind,
        )
    }
    async fn next_bytes_mode(
        &self,
        kind: &str,
        collection: bool,
        mut bootstrap: Option<&mut Option<plist::Dictionary>>,
    ) -> Result<Vec<u8>> {
        let mut resolving = false;
        for _ in 0..100 {
            let pending = self.pending_replies.lock().await.pop_front();
            let mut bytes = match pending {
                Some(bytes) => bytes,
                None => self.manage("Idle", None, None).await?,
            };
            for _ in 0..128 {
                if bytes.is_empty() {
                    break;
                }
                let dictionary = protocol::decode(&bytes)?;
                let id = Uuid::parse_str(protocol::text(&dictionary, "CommandUUID")?)?;
                let payload = dictionary["Command"].as_dictionary().unwrap();
                let actual = protocol::text(payload, "RequestType")?;
                if actual == "InstallProfile"
                    && let Some(slot) = bootstrap.as_deref_mut()
                {
                    ensure!(slot.is_none(), "duplicate managed bootstrap profile");
                    *slot = Some(payload.clone());
                    bytes = self.confirm_managed_profile(id, payload).await?;
                    continue;
                }
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
// ref: apple/device-management mdm/commands/profile.list.yaml
fn installed_profile(payload: &plist::Dictionary) -> Result<plist::Dictionary> {
    use x509_cert::der::{Decode, asn1::OctetString};
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
    // Report installed identities, without certificate data or SCEP secrets.
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
    Ok(summary)
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
        let body = json!({"operationId":id,"action":{"kind":"restart"},"deadline":self.clock.unix_seconds()?+300});
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
