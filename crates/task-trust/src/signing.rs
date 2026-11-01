//! Task signing authority, independently configured from artifact storage.
use crate::{ConfigIssue, Error};
use crate::{Signing, Use, trust};
use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rss_mdm_agent_wire::runtime::{SignedTask, TaskPayload};
use std::collections::BTreeMap;
pub(crate) struct Signer {
    key_id: String,
    key: Ed25519KeyPair,
}
fn bad() -> Error {
    Error::Configuration(ConfigIssue::TaskSigning)
}
impl Signer {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn from_bytes(
        private: &[u8],
        key_id: &str,
        trusted_keys: &BTreeMap<String, String>,
    ) -> Result<Self, Error> {
        if trusted_keys.is_empty()
            || trusted_keys.len() > 16
            || trusted_keys.iter().any(|(id, key)| {
                id.is_empty()
                    || id.len() > 128
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    || base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(key)
                        .map_or(true, |bytes| bytes.len() != 32)
            })
            || key_id.is_empty()
            || key_id.len() > 128
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(bad());
        }
        if private.len() > 4096 {
            return Err(bad());
        }
        let key = Ed25519KeyPair::from_pkcs8(private).map_err(|_| bad())?;
        let expected = trusted_keys.get(key_id).ok_or_else(bad)?;
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(expected)
            .map_err(|_| bad())?;
        if expected != key.public_key().as_ref() {
            return Err(bad());
        }
        Ok(Self {
            key_id: key_id.to_owned(),
            key,
        })
    }
    /// Sign the current periodic configuration after the caller's live issue/ACK check.
    pub fn sign_telemetry(
        &self,
        configuration: rss_mdm_agent_wire::runtime::TelemetryConfiguration,
    ) -> Result<rss_mdm_agent_wire::runtime::SignedTelemetryConfiguration, Error> {
        let bytes = configuration
            .signing_bytes(&self.key_id)
            .map_err(|_| Error::Malformed)?;
        Ok(rss_mdm_agent_wire::runtime::SignedTelemetryConfiguration {
            configuration,
            key_id: self.key_id.clone(),
            signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(self.key.sign(&bytes).as_ref()),
        })
    }
    pub fn sign_configuration(
        &self,
        configuration: rss_mdm_agent_wire::da::Configuration,
    ) -> Result<rss_mdm_agent_wire::da::SignedConfiguration, Error> {
        let bytes = configuration
            .signing_bytes(&self.key_id)
            .map_err(|_| Error::Malformed)?;
        Ok(rss_mdm_agent_wire::da::SignedConfiguration {
            configuration,
            key_id: self.key_id.clone(),
            signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(self.key.sign(&bytes).as_ref()),
        })
    }
    pub fn sign(&self, payload: TaskPayload) -> Result<SignedTask, Error> {
        let bytes = payload
            .signing_bytes(&self.key_id)
            .map_err(|_| Error::Malformed)?;
        Ok(SignedTask {
            payload,
            key_id: self.key_id.clone(),
            signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(self.key.sign(&bytes).as_ref()),
        })
    }
}

impl Signing {
    /// Reuse the active task authority and durable device ACK for periodic collection.
    pub async fn sign_telemetry_on(
        &self,
        c: &mut sqlx::PgConnection,
        p: &rss_mdm_registration_service::device::DevicePrincipal,
        configuration: rss_mdm_agent_wire::runtime::TelemetryConfiguration,
    ) -> Result<rss_mdm_agent_wire::runtime::SignedTelemetryConfiguration, Error> {
        if self.usage != Use::AgentTask
            || p.tenant() != self.tenant
            || p.channel() != Some(rss_mdm_inventory::Channel::Agent)
            || p.purpose() != rss_mdm_registration_service::device::Purpose::Primary
            || configuration.tenant_id.to_string() != p.tenant().to_string()
            || configuration.device_id != p.device()
            || configuration.registration_id != p.registration()
            || configuration.generation != p.generation() as u64
        {
            return Err(Error::Forbidden);
        }
        let signer = self.signer.as_ref().ok_or(Error::Unsupported)?;
        self.revalidate(c, p).await?;
        trust::require_issue(self.profile, self.usage, c, p, signer.key_id()).await?;
        let until = configuration
            .expires_at
            .checked_add(i64::from(configuration.backfill_seconds))
            .ok_or(Error::Malformed)?;
        let signed = signer.sign_telemetry(configuration)?;
        trust::retain_until(
            self.profile,
            self.usage,
            c,
            self.tenant,
            signer.key_id(),
            until,
        )
        .await?;
        Ok(signed)
    }
}

impl Signing {
    /// Authenticate original periodic material using the existing active/verify-only trust set.
    pub async fn verify_telemetry_on(
        &self,
        c: &mut sqlx::PgConnection,
        p: &rss_mdm_registration_service::device::DevicePrincipal,
        signed: &rss_mdm_agent_wire::runtime::SignedTelemetryConfiguration,
    ) -> Result<(), Error> {
        use rss_mdm_agent_wire::task_trust::KeyState;
        let configuration = &signed.configuration;
        if self.usage != Use::AgentTask
            || p.tenant() != self.tenant
            || configuration.tenant_id.to_string() != p.tenant().to_string()
            || configuration.device_id != p.device()
            || configuration.registration_id != p.registration()
            || configuration.generation != p.generation() as u64
        {
            return Err(Error::Forbidden);
        }
        self.revalidate(c, p).await?;
        let trust = trust::current(self.profile, self.usage, c, self.tenant).await?;
        let key = trust
            .keys
            .iter()
            .find(|k| {
                k.id == signed.key_id && matches!(k.state, KeyState::Active | KeyState::VerifyOnly)
            })
            .ok_or(Error::Forbidden)?;
        let public = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&key.public_key)
            .map_err(|_| Error::Malformed)?;
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&signed.signature)
            .map_err(|_| Error::Forbidden)?;
        let bytes = configuration
            .signing_bytes(&signed.key_id)
            .map_err(|_| Error::Malformed)?;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
            .verify(&bytes, &signature)
            .map_err(|_| Error::Forbidden)
    }
}
