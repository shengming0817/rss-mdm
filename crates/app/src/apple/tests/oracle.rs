//! Fixed upstream receives the same authenticated-device PDUs in isolated file storage.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::collections::BTreeSet;
pub(super) struct Oracle {
    client: reqwest::Client,
    origin: String,
    key: String,
    certificate: String,
    queued: tokio::sync::Mutex<BTreeSet<String>>,
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
        })
    }
    pub async fn compare(&self, path: &str, request: &[u8], response: &[u8]) -> Result<()> {
        if path == "/mdm" && !response.is_empty() {
            let command = protocol::decode(response)?;
            let id = protocol::text(&command, "CommandUUID")?;
            if self.queued.lock().await.insert(id.into()) {
                let reply = self
                    .client
                    .post(format!("{}/v1/enqueue/rss-apple-t2?nopush=1", self.origin))
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
        let bytes = reply.bytes().await?;
        if path == "/mdm" && !response.is_empty() {
            ensure!(
                protocol::decode(&bytes)? == protocol::decode(response)?,
                "NanoMDM returned different command fields"
            );
        }
        Ok(())
    }
}
