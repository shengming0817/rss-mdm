//! The registration owner is the only producer of Agent signing authorization.
//! ref: smallstep/certificates authority/provisioner/jwk.go and api/sign.go@v0.30.2.
use crate::{
    Error,
    database::db,
    enrollment::{
        Password, equal,
        store::{request, uuid},
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{rand::SystemRandom, signature};
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_certificate::agent::{AgentTrust, IssuedAgentCertificate, SUBJECT, VerifiedAgentCsr};
use serde::{Deserialize, Serialize};
use sqlx::Row;
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
    tenant: rss_request_context::TenantId,
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
    audit: Arc<AuditStore>,
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
        audit: Arc<AuditStore>,
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
            audit,
        })
    }
    pub fn trust(&self) -> &Arc<AgentTrust> {
        &self.trust
    }
    /// Validate current PG authority, then commit its audit before external signing.
    pub async fn authorize(
        &self,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        password: &Password,
        csr: &[u8],
        audit: &RequestAudit,
    ) -> Result<AuthorizedAgentIssuanceIntent, IssuanceError> {
        let csr = VerifiedAgentCsr::verify(csr).map_err(|_| IssuanceError::Request)?;
        proof
            .bind_audit(audit)
            .map_err(|e| IssuanceError::Authorization(e.into()))?;
        let tenant = rss_request_context::TenantId::parse(proof.tenant_id())
            .map_err(|_| IssuanceError::Request)?;
        let attempt = Uuid::new_v4();
        audit.operation(attempt, "agent_certificate_issue");
        let budget = AuditBudget::new(Duration::from_secs(2));
        let control = budget.control();
        let outcome=self.audit.write(tenant,&control,(&self.audit,proof,password,&csr,id,attempt,&self.trust,self.days,audit),
            |(store,proof,password,csr,id,attempt,trust,days,audit),tx| Box::pin(async move {
                let (device,deadline,start)=tx.with_connection_context(&mut (*proof,*password,*id),|(proof,password,id),c| Box::pin(async move {
                    let row=request(c,proof.tenant_id(),*id).await?;
                    let device:String=row.try_get("device").map_err(db)?;
                    proof.enrollment(&device)?;
                    if row.try_get::<String,_>("state").map_err(db)?!="pending" || !row.try_get::<bool,_>("live").map_err(db)? || row.try_get::<String,_>("source").map_err(db)?!="agent.builtin"
                        || row.try_get::<String,_>("actor").map_err(db)?!=proof.principal_id() || row.try_get::<String,_>("instance").map_err(db)?!=proof.instance_id()
                        || !equal(&password.digest(proof.tenant_id(),&device)?,&row.try_get::<String,_>("password_digest").map_err(db)?) { return Err(Error::Forbidden); }
                    uuid(&row,"issuance_operation")?;
                    let deadline:i64=row.try_get("expiry").map_err(db)?;
                    let start:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").fetch_one(c).await.map_err(db)?;
                    Ok::<_,Error>((device,deadline,start))
                })).await?;
                let end=start.checked_add(i64::from(*days)*86400).ok_or(Error::Configuration)?;
                if !trust.permits_window(start,end) { return Err(Error::Configuration); }
                let identity=rss_mdm_certificate::agent::identity(Uuid::parse_str(proof.tenant_id()).map_err(|_|Error::Configuration)?,&device).map_err(|_|Error::Configuration)?;
                audit.target(&device);
                let fact=Fact::business(audit,&format!("agent-pki:{attempt}:authorized"),&csr.digest(),200,"success",Some(*id))?
                    .with_details(serde_json::json!({"phase":"authorized","attempt":attempt,"identity":identity,"spki":csr.spki(),"issuer":trust.issuer_digest(),"notBefore":start,"notAfter":end}))?;
                store.append(tx,&fact,false).await.map_err(Error::from)?;
                audit.mark_commit_started();
                Ok::<_,Error>((identity,deadline,start,end))
            })).await;
        let (identity, deadline, start, end) =
            crate::operations::settle(outcome, audit).map_err(IssuanceError::Authorization)?;
        Ok(AuthorizedAgentIssuanceIntent {
            attempt,
            request: id,
            tenant,
            csr,
            identity,
            deadline,
            start,
            end,
        })
    }
    /// Consume the authorization once. A signature does not activate a registration.
    pub async fn issue(
        &self,
        intent: AuthorizedAgentIssuanceIntent,
        audit: &RequestAudit,
    ) -> Result<Issued, IssuanceError> {
        if audit.tenant() != intent.tenant.to_string()
            || audit.snapshot().operation_id != Some(intent.attempt)
        {
            return Err(IssuanceError::Authorization(Error::Forbidden));
        }
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
        let result = self.sign(&intent, now).await;
        let (status, label, details) = match &result {
            Ok(c) => (
                200,
                "success",
                serde_json::json!({"phase":"signed","certificate":c.metadata,"csr":c.csr_digest}),
            ),
            Err(_) => (
                503,
                "unknown",
                serde_json::json!({"phase":"issuance_unknown","attempt":intent.attempt}),
            ),
        };
        let fact = Fact::business(
            audit,
            &format!("agent-pki:{}:result", intent.attempt),
            &intent.csr.digest(),
            status,
            label,
            Some(intent.request),
        )
        .and_then(|f| f.with_details(details))
        .map_err(|_| IssuanceError::Unknown {
            attempt: intent.attempt,
        })?;
        let budget = AuditBudget::new(Duration::from_secs(2));
        let control = budget.control();
        let outcome = self
            .audit
            .write(
                intent.tenant,
                &control,
                (&self.audit, &fact, audit),
                |(store, fact, audit), tx| {
                    Box::pin(async move {
                        store.append(tx, fact, false).await.map_err(Error::from)?;
                        audit.mark_commit_started();
                        Ok::<_, Error>(())
                    })
                },
            )
            .await;
        crate::operations::settle(outcome, audit).map_err(|_| IssuanceError::Unknown {
            attempt: intent.attempt,
        })?;
        result.map(|certificate| Issued {
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
