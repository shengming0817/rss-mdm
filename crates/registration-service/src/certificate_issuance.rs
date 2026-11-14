//! The registration owner is the only producer of Agent signing authorization.
//! ref: smallstep/certificates authority/provisioner/jwk.go and api/sign.go@v0.30.2.
use crate::Error;
use rss_mdm_agent_wire::pki::Purpose;
use rss_mdm_certificate::device_identity::{VerifiedDeviceCsr, subject};
use rss_mdm_device_trust::device_identity::{DeviceIdentityTrust, IssuedDeviceCertificate};
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
/// let intent = rss_mdm_registration_service::certificate_issuance::AuthorizedDeviceIssuanceIntent::new();
/// ```
/// ```compile_fail
/// let intent: rss_mdm_registration_service::certificate_issuance::AuthorizedDeviceIssuanceIntent = serde_json::from_str("{}").unwrap();
/// ```
pub struct AuthorizedDeviceIssuanceIntent {
    attempt: Uuid,
    issuer: [u8; 32],
    request: Uuid,
    csr: VerifiedDeviceCsr,
    identity: String,
    deadline: i64,
    start: i64,
    end: i64,
}
impl AuthorizedDeviceIssuanceIntent {
    pub fn attempt(&self) -> Uuid {
        self.attempt
    }
}
pub struct Issued {
    pub attempt: Uuid,
    pub request: Uuid,
    pub certificate: IssuedDeviceCertificate,
}
pub struct DeviceIssuer {
    profile: rss_mdm_install_support::StorageProfile,
    purpose: Purpose,
    providers: Arc<Providers>,
    registry: Arc<rss_mdm_pki_service::registry::Registry>,
    installation: Uuid,
    days: u16,
    clock: Arc<dyn Clock>,
}
impl DeviceIssuer {
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "issuer materials, installation identity and clock remain explicit"
    )]
    pub fn new(
        profile: rss_mdm_install_support::StorageProfile,
        providers: Arc<Providers>,
        days: u16,
        development: bool,
        purpose: Purpose,
        registry: Arc<rss_mdm_pki_service::registry::Registry>,
        installation: Uuid,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, IssuanceError> {
        if days == 0 || days > 3650 || (!development && days != 365) {
            return Err(IssuanceError::Configuration);
        }
        Ok(Self {
            profile,
            purpose,
            providers,
            registry,
            installation,
            days,
            clock,
        })
    }

    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    /// Freeze the signing issuer and provider identity without retaining secrets.
    pub(crate) fn authority_digest(&self, issuer: [u8; 32]) -> Result<String, Error> {
        let digest = issuer
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        self.providers
            .get(self.purpose, &digest)
            .map(|p| p.authority_digest(&digest))
            .map_err(|_| Error::Configuration)
    }
    pub fn installation(&self) -> Uuid {
        self.installation
    }
    pub async fn trust(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<Arc<DeviceIdentityTrust>, Error> {
        let trust = self
            .registry
            .current(execution, self.purpose, self.clock.unix_seconds()?)
            .await
            .map_err(|_| Error::Configuration)?;
        self.trust_snapshot(trust)
    }
    pub async fn trust_on(
        &self,
        c: &mut sqlx::PgConnection,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<Arc<DeviceIdentityTrust>, Error> {
        let trust = self
            .registry
            .current_on(c, execution, self.purpose, self.clock.unix_seconds()?)
            .await
            .map_err(|_| Error::Configuration)?;
        self.trust_snapshot(trust)
    }
    pub async fn bootstrap_trust(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<rss_mdm_device_trust::DeviceTrust, Error> {
        if self.purpose != Purpose::Agent {
            return Err(Error::Unsupported);
        }
        let trust = self
            .registry
            .current(
                execution,
                Purpose::AgentBootstrap,
                self.clock.unix_seconds()?,
            )
            .await
            .map_err(|_| Error::Configuration)?;
        if trust.public().map_err(|_| Error::Configuration)?.service_id != self.installation {
            return Err(Error::Configuration);
        }
        Ok(trust)
    }
    fn trust_snapshot(
        &self,
        trust: rss_mdm_device_trust::DeviceTrust,
    ) -> Result<Arc<DeviceIdentityTrust>, Error> {
        if trust.public().map_err(|_| Error::Configuration)?.service_id != self.installation {
            return Err(Error::Configuration);
        }
        DeviceIdentityTrust::from_trust(trust, self.days)
            .map(Arc::new)
            .map_err(|_| Error::Configuration)
    }
    /// Freeze signing under the caller's existing transaction.
    pub(crate) async fn authorize_in(
        &self,
        c: &mut sqlx::PgConnection,
        tenant: Uuid,
        spec: &crate::agent::issuance::Signing,
    ) -> Result<(), Error> {
        let csr = VerifiedDeviceCsr::verify(&spec.csr, self.purpose).map_err(|_| Error::Corrupt)?;
        let pem = csr.pem().map_err(|_| Error::Corrupt)?;
        let issuer = spec
            .issuer
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let provider = self
            .providers
            .get(self.purpose, &issuer)
            .map_err(|_| Error::Configuration)?;
        rss_mdm_pki_service::signing::authorize_in(
            self.profile,
            c,
            tenant,
            rss_mdm_pki_service::registry::purpose(self.purpose),
            &issuer,
            provider,
            Sign {
                attempt: spec.attempt,
                csr_pem: &pem,
                csr_digest: &csr.digest(),
                subject: subject(self.purpose).map_err(|_| Error::Configuration)?,
                sans: std::slice::from_ref(&spec.identity),
                start: spec.start,
                end: spec.end,
                deadline: spec.deadline,
            },
        )
        .await
        .map_err(|_| Error::Conflict)
    }
    /// Freeze a validated, already persisted signing intention. Only the lifecycle owner calls this.
    pub(crate) fn persisted_intent(
        &self,
        spec: crate::agent::issuance::Signing,
    ) -> Result<AuthorizedDeviceIssuanceIntent, Error> {
        let csr = VerifiedDeviceCsr::verify(&spec.csr, self.purpose).map_err(|_| Error::Corrupt)?;
        let end = spec.end;
        Ok(AuthorizedDeviceIssuanceIntent {
            attempt: spec.attempt,
            issuer: spec.issuer,
            request: spec.grant,
            csr,
            identity: spec.identity,
            deadline: spec.deadline,
            start: spec.start,
            end,
        })
    }
    pub(crate) fn end(&self, trust: &DeviceIdentityTrust, start: i64) -> Result<i64, Error> {
        let end = start
            .checked_add(i64::from(self.days) * 86400)
            .ok_or(Error::Configuration)?;
        if !trust.permits_window(start, end) {
            return Err(Error::Configuration);
        }
        Ok(end)
    }
    /// Consume one persisted authorization. Persistence and audit belong to the lifecycle owner.
    pub async fn issue(
        &self,
        intent: AuthorizedDeviceIssuanceIntent,
        store: &rss_mdm_pki_service::signing::SigningStore,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<Issued, IssuanceError> {
        if store.profile() != self.profile {
            return Err(IssuanceError::Configuration);
        }
        let now = self
            .clock
            .unix_seconds()
            .map_err(IssuanceError::Authorization)?;
        if now < intent.start || now >= intent.deadline || now - intent.start >= 60 {
            return Err(IssuanceError::Authorization(Error::Unauthorized));
        }
        self.sign(store, execution, &intent, now)
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
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        intent: &AuthorizedDeviceIssuanceIntent,
        now: i64,
    ) -> Result<IssuedDeviceCertificate, IssuanceError> {
        let trust = self
            .trust(execution)
            .await
            .map_err(IssuanceError::Authorization)?;
        let unknown = || IssuanceError::Unknown {
            attempt: intent.attempt,
        };
        let pem = intent.csr.pem().map_err(|_| unknown())?;
        let sans = [intent.identity.clone()];
        let issuer = intent
            .issuer
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let provider = self
            .providers
            .get(self.purpose, &issuer)
            .map_err(|_| IssuanceError::Configuration)?;
        let chain = store
            .issue(
                execution,
                (
                    rss_mdm_pki_service::registry::purpose(self.purpose),
                    &issuer,
                ),
                provider,
                Sign {
                    attempt: intent.attempt,
                    csr_pem: &pem,
                    csr_digest: &intent.csr.digest(),
                    subject: subject(self.purpose).map_err(|_| IssuanceError::Configuration)?,
                    sans: &sans,
                    start: intent.start,
                    end: intent.end,
                    deadline: intent.deadline,
                },
                &|| {
                    self.clock
                        .unix_seconds()
                        .map_err(|_| rss_mdm_pki_service::Error::Request)
                },
                |chain| {
                    trust
                        .validate_issued_for(
                            intent.issuer,
                            chain.to_vec(),
                            &intent.csr,
                            &intent.identity,
                            intent.start..intent.end,
                            now,
                        )
                        .is_ok()
                },
            )
            .await
            .map_err(|_| unknown())?;
        trust
            .validate_issued_for(
                intent.issuer,
                chain,
                &intent.csr,
                &intent.identity,
                intent.start..intent.end,
                self.clock.unix_seconds().map_err(|_| unknown())?,
            )
            .map_err(|_| unknown())
    }
}
