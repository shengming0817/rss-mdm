//! The registration owner is the only producer of Agent signing authorization.
//! ref: smallstep/certificates authority/provisioner/jwk.go and api/sign.go@v0.30.2.
use crate::Error;
use rss_mdm_agent_wire::pki::Purpose;
use rss_mdm_certificate::agent::{AgentTrust, IssuedAgentCertificate, SUBJECT, VerifiedAgentCsr};
use rss_mdm_pki_service::{Sign, providers::Providers};
use std::sync::Arc;
use uuid::Uuid;

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
    providers: Arc<Providers>,
    trust: Arc<AgentTrust>,
    days: u16,
    clock: Arc<dyn Clock>,
}
impl AgentIssuer {
    pub fn new(
        providers: Arc<Providers>,
        days: u16,
        development: bool,
        trust: Arc<AgentTrust>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, IssuanceError> {
        if days == 0 || days > 3650 || (!development && days != 365) {
            return Err(IssuanceError::Configuration);
        }
        let active = trust
            .trust
            .active()
            .map_err(|_| IssuanceError::Configuration)?;
        providers
            .get(Purpose::Agent, &active.digest)
            .map_err(|_| IssuanceError::Configuration)?;
        Ok(Self {
            providers,
            trust,
            days,
            clock,
        })
    }

    /// Freeze the signing issuer and provider identity without retaining secrets.
    pub(crate) fn authority_digest(&self) -> Result<String, Error> {
        let active = self
            .trust
            .trust
            .active()
            .map_err(|_| Error::Configuration)?;
        self.providers
            .get(Purpose::Agent, &active.digest)
            .map(|p| p.authority_digest(&active.digest))
            .map_err(|_| Error::Configuration)
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
        store: &rss_mdm_pki_service::signing::SigningStore,
        tenant: Uuid,
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
        self.sign(store, tenant, &intent, now)
            .await
            .map(|certificate| Issued {
                attempt: intent.attempt,
                request: intent.request,
                certificate,
            })
    }
    async fn sign(
        &self,
        store: &rss_mdm_pki_service::signing::SigningStore,
        tenant: Uuid,
        intent: &AuthorizedAgentIssuanceIntent,
        now: i64,
    ) -> Result<IssuedAgentCertificate, IssuanceError> {
        let unknown = || IssuanceError::Unknown {
            attempt: intent.attempt,
        };
        let pem = intent.csr.pem().map_err(|_| unknown())?;
        let sans = [intent.identity.clone()];
        let issuer = self
            .trust
            .issuer_digest()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let provider = self
            .providers
            .get(Purpose::Agent, &issuer)
            .map_err(|_| IssuanceError::Configuration)?;
        let chain = store
            .issue(
                tenant,
                "agent",
                &issuer,
                provider,
                Sign {
                    attempt: intent.attempt,
                    csr_pem: &pem,
                    csr_digest: &intent.csr.digest(),
                    subject: SUBJECT,
                    sans: &sans,
                    start: intent.start,
                    end: intent.end,
                    deadline: intent.deadline,
                },
                now,
                |chain| {
                    self.trust
                        .validate_issued(
                            chain.to_vec(),
                            &intent.csr,
                            &intent.identity,
                            intent.start,
                            intent.end,
                            now,
                        )
                        .is_ok()
                },
            )
            .await
            .map_err(|_| unknown())?;
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
