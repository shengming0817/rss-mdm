//! Fixed upstream receives the same authenticated-device PDUs in isolated file storage.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::collections::{BTreeMap, BTreeSet};
pub(super) struct Oracle {
    client: reqwest::Client,
    origin: String,
    key: String,
    certificate: String,
    queued: tokio::sync::Mutex<BTreeSet<String>>,
    acknowledgements: tokio::sync::Mutex<BTreeMap<String, Vec<u8>>>,
    history: tokio::sync::Mutex<std::collections::VecDeque<serde_json::Value>>,
}
impl Oracle {
    pub fn new(leaf: &[u8]) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()?,
            origin: std::env::var("MDM_NANO_URL")?,
            key: std::env::var("MDM_NANO_API_KEY")?,
            certificate: format!(":{}:", STANDARD.encode(leaf)),
            queued: Default::default(),
            acknowledgements: Default::default(),
            history: Default::default(),
        })
    }
    pub async fn compare(&self, path: &str, request: &[u8], response: &[u8]) -> Result<()> {
        let request_dictionary = protocol::decode(request)?;
        if path == "/mdm"
            && request_dictionary
                .get("Status")
                .and_then(plist::Value::as_string)
                == Some("Acknowledged")
            && let Some(id) = request_dictionary
                .get("CommandUUID")
                .and_then(plist::Value::as_string)
        {
            self.acknowledgements
                .lock()
                .await
                .insert(id.to_owned(), request.to_vec());
        }

        let command = if response.is_empty() {
            None
        } else {
            Some(protocol::decode(response)?)
        };
        if command.is_some() || request_dictionary.contains_key("CommandUUID") {
            let mut history = self.history.lock().await;
            if history.len() == 20 {
                history.pop_front();
            }
            history.push_back(serde_json::json!({
                "status":request_dictionary.get("Status").and_then(plist::Value::as_string),
                "ack":request_dictionary.get("CommandUUID").and_then(plist::Value::as_string),
                "sent":command.as_ref().and_then(|v| v.get("CommandUUID")).and_then(plist::Value::as_string),
                "kind":command.as_ref().and_then(|v| v.get("Command")).and_then(plist::Value::as_dictionary).and_then(|v|v.get("RequestType")).and_then(plist::Value::as_string)
            }));
        }

        let mut enrollment = crate::test_support::case::name("rss-t2-apple").to_owned();
        if let Some(user) = request_dictionary
            .get("UserID")
            .and_then(plist::Value::as_string)
        {
            enrollment = format!("{enrollment}:{user}");
        }
        if path == "/mdm" && !response.is_empty() {
            let command = protocol::decode(response)?;
            let id = protocol::text(&command, "CommandUUID")?;
            if self.queued.lock().await.insert(id.into()) {
                let reply = self
                    .client
                    .post(format!(
                        "{}/v1/enqueue/{}?nopush=1",
                        self.origin, enrollment
                    ))
                    .basic_auth("nanomdm", Some(&self.key))
                    .body(response.to_vec())
                    .send()
                    .await?;
                ensure!(
                    reply.status().is_success(),
                    "NanoMDM enqueue failed {}",
                    reply.status()
                );
            }
        }
        let bytes = self.exchange(path, request).await?;
        if path == "/mdm" && !response.is_empty() {
            let actual = protocol::decode(&bytes)?;
            let expected = protocol::decode(response)?;
            ensure!(
                actual == expected,
                "NanoMDM returned different command fields: actual UUID {:?}, expected UUID {:?}, input status {:?}; protocol trace {}",
                actual.get("CommandUUID"),
                expected.get("CommandUUID"),
                request_dictionary.get("Status"),
                serde_json::to_string(&*self.history.lock().await)?
            );
        }
        Ok(())
    }
    async fn exchange(&self, path: &str, request: &[u8]) -> Result<Vec<u8>> {
        let reply = self
            .client
            .put(format!("{}{path}", self.origin))
            .header("X-Fixture-Certificate", &self.certificate)
            .body(request.to_vec())
            .send()
            .await?;
        ensure!(
            reply.status() == StatusCode::OK,
            "NanoMDM {path} failed {}",
            reply.status()
        );
        Ok(reply.bytes().await?.to_vec())
    }
    pub async fn acknowledge_without_product(&self, request: &[u8]) -> Result<()> {
        let acknowledgement = protocol::decode(request)?;
        ensure!(
            acknowledgement
                .get("Status")
                .and_then(plist::Value::as_string)
                == Some("Acknowledged")
        );
        let mut response = self.exchange("/mdm", request).await?;
        for _ in 0..128 {
            if response.is_empty() {
                return Ok(());
            }
            let command = protocol::decode(&response)?;
            let id = protocol::text(&command, "CommandUUID")?;
            let previous = self.acknowledgements.lock().await.get(id).cloned();
            let Some(previous) = previous else {
                return Ok(());
            };
            // Replay only an exact authenticated PDU already accepted by the product.
            // Never invent an ACK for an outstanding command or relax command equality.
            response = self.exchange("/mdm", &previous).await?;
        }
        anyhow::bail!("reference did not settle previously acknowledged commands")
    }
}
