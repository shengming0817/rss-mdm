//! The registration owner is the only producer of Agent signing authorization.
//! ref: smallstep/certificates authority/provisioner/jwk.go and api/sign.go@v0.30.2.
use crate::Error;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{rand::SystemRandom, signature};
use rss_mdm_certificate::agent::{AgentTrust, IssuedAgentCertificate, SUBJECT, VerifiedAgentCsr};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use zeroize::Zeroizing;

pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> Result<i64, Error>;
}
#[derive(Debug, thiserror::Error)]
pub enum IssuanceError {
    #[error("Agent signing configuration rejected")]
    Configuration,
    #[error("Agent certificate request rejected")]
    Request,
    #[error("Agent signing authorization rejected")]
    Authorization(#[source] Error),
    #[error("Agent signing result unknown")]
    Unknown { attempt: Uuid },
}
/// No network schema or public constructor can mint signing authority.
/// ```compile_fail
/// let intent = rss_mdm_registration_service::agent_pki::AuthorizedAgentIssuanceIntent::new();
/// ```
/// ```compile_fail
/// let intent: rss_mdm_registration_service::agent_pki::AuthorizedAgentIssuanceIntent = serde_json::from_str("{}").unwrap();
/// ```
pub struct AuthorizedAgentIssuanceIntent {
    attempt: Uuid,
    request: Uuid,
    csr: VerifiedAgentCsr,
    identity: String,
    deadline: i64,
    start: i64,
    end: i64,
}
impl AuthorizedAgentIssuanceIntent {
    pub fn attempt(&self) -> Uuid {
        self.attempt
    }
}
pub struct Issued {
    pub attempt: Uuid,
    pub request: Uuid,
    pub certificate: IssuedAgentCertificate,
}
pub struct AgentIssuer {
    client: reqwest::Client,
    sign_url: url::Url,
    key: signature::RsaKeyPair,
    kid: String,
    trust: Arc<AgentTrust>,
    days: u16,
    clock: Arc<dyn Clock>,
}
pub struct Provider {
    pub ca_url: String,
    pub kid: String,
    pub validity_days: u16,
    pub development: bool,
}
impl AgentIssuer {
    pub fn new(
        provider: Provider,
        tls_root: &[u8],
        pkcs8: &[u8],
        trust: Arc<AgentTrust>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, IssuanceError> {
        let invalid = || IssuanceError::Configuration;
        let mut origin = url::Url::parse(&provider.ca_url).map_err(|_| invalid())?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
            || provider.kid.is_empty()
            || provider.kid.len() > 128
            || provider.validity_days == 0
            || provider.validity_days > 3650
            || (!provider.development && provider.validity_days != 365)
            || pkcs8.len() > 32768
            || tls_root.len() > 131072
        {
            return Err(invalid());
        }
        origin.set_path("/sign");
        let key = signature::RsaKeyPair::from_pkcs8(pkcs8).map_err(|_| invalid())?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(tls_root).map_err(|_| invalid())?)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|_| invalid())?;
        Ok(Self {
            client,
            sign_url: origin,
            key,
            kid: provider.kid,
            trust,
            days: provider.validity_days,
            clock,
        })
    }
    /// Freeze the signing issuer, provisioner and its public key without retaining secrets.
    pub(crate) fn authority_digest(&self) -> String {
        use ring::signature::KeyPair;
        crate::enrollment::digest(&(
            "agent-ca/v1",
            self.trust.issuer_digest(),
            "rss-agent",
            &self.kid,
            URL_SAFE_NO_PAD.encode(self.key.public_key().as_ref()),
        ))
    }
    pub fn trust(&self) -> &Arc<AgentTrust> {
        &self.trust
    }
    /// Freeze a validated, already persisted signing intention. Only the lifecycle owner calls this.
    pub(crate) fn persisted_intent(
        &self,
        spec: crate::agent::issuance::Signing,
    ) -> Result<AuthorizedAgentIssuanceIntent, Error> {
        let csr = VerifiedAgentCsr::verify(&spec.csr).map_err(|_| Error::Corrupt)?;
        let end = spec.end;
        if !self.trust.permits_window(spec.start, end) {
            return Err(Error::Configuration);
        }
        Ok(AuthorizedAgentIssuanceIntent {
            attempt: spec.attempt,
            request: spec.grant,
            csr,
            identity: spec.identity,
            deadline: spec.deadline,
            start: spec.start,
            end,
        })
    }
    pub(crate) fn end(&self, start: i64) -> Result<i64, Error> {
        let end = start
            .checked_add(i64::from(self.days) * 86400)
            .ok_or(Error::Configuration)?;
        if !self.trust.permits_window(start, end) {
            return Err(Error::Configuration);
        }
        Ok(end)
    }
    /// Consume one persisted authorization. Persistence and audit belong to the lifecycle owner.
    pub async fn issue(
        &self,
        intent: AuthorizedAgentIssuanceIntent,
    ) -> Result<Issued, IssuanceError> {
        let now = self
            .clock
            .unix_seconds()
            .map_err(IssuanceError::Authorization)?;
        if now < intent.start
            || now >= intent.deadline
            || now - intent.start >= 60
            || !self.trust.permits_window(intent.start, intent.end)
        {
            return Err(IssuanceError::Authorization(Error::Unauthorized));
        }
        self.sign(&intent, now).await.map(|certificate| Issued {
            attempt: intent.attempt,
            request: intent.request,
            certificate,
        })
    }
    fn token(
        &self,
        intent: &AuthorizedAgentIssuanceIntent,
        now: i64,
    ) -> Result<Zeroizing<String>, IssuanceError> {
        let unknown = || IssuanceError::Unknown {
            attempt: intent.attempt,
        };
        let header = serde_json::json!({"alg":"RS256","typ":"JWT","kid":self.kid});
        let payload = serde_json::json!({"iss":"rss-agent","aud":[self.sign_url.as_str()],"sub":SUBJECT,"sans":[intent.identity],"iat":now,"nbf":now,"exp":intent.deadline.min(now+60),"jti":intent.attempt.to_string(),"cnf":{"x5rt#S256":URL_SAFE_NO_PAD.encode(intent.csr.digest())}});
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| unknown())?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).map_err(|_| unknown())?)
        );
        let mut sig = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message.as_bytes(),
                &mut sig,
            )
            .map_err(|_| unknown())?;
        Ok(Zeroizing::new(format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(sig)
        )))
    }
    async fn sign(
        &self,
        intent: &AuthorizedAgentIssuanceIntent,
        now: i64,
    ) -> Result<IssuedAgentCertificate, IssuanceError> {
        let unknown = || IssuanceError::Unknown {
            attempt: intent.attempt,
        };
        let token = self.token(intent, now)?;
        let timestamp = |value| {
            time::OffsetDateTime::from_unix_timestamp(value)
                .ok()
                .and_then(|t| {
                    t.format(&time::format_description::well_known::Rfc3339)
                        .ok()
                })
                .ok_or_else(unknown)
        };
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Request<'a> {
            csr: String,
            ott: &'a str,
            not_before: String,
            not_after: String,
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&Request {
                csr: intent.csr.pem().map_err(|_| unknown())?,
                ott: &token,
                not_before: timestamp(intent.start)?,
                not_after: timestamp(intent.end)?,
            })
            .map_err(|_| unknown())?,
        );
        let mut response = self
            .client
            .post(self.sign_url.clone())
            .header("content-type", "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| unknown())?;
        // After sending, even an error/used-token response cannot prove no certificate exists.
        if !response.status().is_success() {
            return Err(unknown());
        }
        if response.content_length().is_some_and(|n| n > 131072) {
            return Err(unknown());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| unknown())? {
            if bytes.len() + chunk.len() > 131072 {
                return Err(unknown());
            }
            bytes.extend_from_slice(&chunk);
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            crt: String,
            cert_chain: Vec<String>,
        }
        let output: Response = serde_json::from_slice(&bytes).map_err(|_| unknown())?;
        if output.cert_chain.is_empty()
            || output.cert_chain.len() > 4
            || output.cert_chain[0] != output.crt
        {
            return Err(unknown());
        }
        use x509_cert::der::{DecodePem, Encode};
        let chain = output
            .cert_chain
            .iter()
            .map(|pem| {
                x509_cert::Certificate::from_pem(pem)
                    .and_then(|c| c.to_der())
                    .map_err(|_| unknown())
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.trust
            .validate_issued(
                chain,
                &intent.csr,
                &intent.identity,
                intent.start,
                intent.end,
                self.clock.unix_seconds().map_err(|_| unknown())?,
            )
            .map_err(|_| unknown())
    }
}
