//! Agent issuer deployment inputs; private CA signing keys never enter this process.
use crate::{ConfigIssue, Error};
use rss_mdm_registration_service::agent_pki::AgentIssuer;
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc, time::Duration};
#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Config {
    Disabled {},
    StepCa {
        endpoint: Box<crate::native::TlsEndpoint>,
        trust_file: PathBuf,
        #[serde(default)]
        lifetime: Lifetime,
    },
}
#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Lifetime {
    Standard {},
    Development { days: u16 },
}
impl Default for Lifetime {
    fn default() -> Self {
        Self::Standard {}
    }
}
impl Lifetime {
    fn days(&self) -> Result<u16, Error> {
        match self {
            Self::Standard {} => Ok(365),
            Self::Development { days } if (1..=3650).contains(days) => Ok(*days),
            _ => Err(Error::Configuration(ConfigIssue::AgentPki)),
        }
    }
}
pub(crate) struct AgentPki {
    pub issuer: Arc<AgentIssuer>,
    pub listen: std::net::SocketAddr,
    pub origin: String,
    pub tls: Arc<tokio_rustls::rustls::ServerConfig>,
    pub pki_clock: Arc<dyn rss_mdm_registration_service::agent_pki::Clock>,
    clock: Arc<dyn crate::clock::Clock>,
    required_seconds: i64,
}
impl Config {
    pub(crate) fn load(
        &self,
        _audit: Arc<rss_mdm_audit_integration::AuditStore>,
        clock: Arc<dyn crate::clock::Clock>,
        providers: Arc<rss_mdm_pki_service::providers::Providers>,
    ) -> Result<Option<Arc<AgentPki>>, Error> {
        let Self::StepCa {
            endpoint,
            trust_file,
            lifetime,
        } = self
        else {
            return Ok(None);
        };
        let invalid = || Error::Configuration(ConfigIssue::AgentPki);
        let origin = url::Url::parse(&endpoint.origin).map_err(|_| invalid())?;
        if origin.scheme() != "https"
            || origin.origin().ascii_serialization() != endpoint.origin
            || !origin.username().is_empty()
            || origin.password().is_some()
        {
            return Err(invalid());
        }
        let days = lifetime.days()?;
        let device_trust = crate::device_pki::load(
            trust_file,
            rss_mdm_agent_wire::pki::Purpose::Agent,
            clock.unix_seconds()?,
        )?;
        if device_trust.public().map_err(|_| invalid())?.origin != endpoint.origin {
            return Err(invalid());
        }
        let trust = Arc::new(
            rss_mdm_certificate::agent::AgentTrust::from_trust(device_trust, days)
                .map_err(|_| invalid())?,
        );
        let issuer = AgentIssuer::new(
            providers,
            days,
            matches!(lifetime, Lifetime::Development { .. }),
            trust,
            Arc::new(PkiClock(clock.clone())),
        )
        .map_err(|_| invalid())?;
        let tls = crate::native::tls::configuration(
            endpoint,
            Some(issuer.trust().enrollment_verifier()),
        )?;
        Ok(Some(Arc::new(AgentPki {
            listen: endpoint.listen,
            origin: endpoint.origin.clone(),
            tls,
            pki_clock: Arc::new(PkiClock(clock.clone())),
            issuer: Arc::new(issuer),
            clock,
            required_seconds: i64::from(days) * 86400,
        })))
    }
}
pub(crate) struct PkiClock(pub(crate) Arc<dyn crate::clock::Clock>);
impl rss_mdm_registration_service::agent_pki::Clock for PkiClock {
    fn unix_seconds(&self) -> Result<i64, rss_mdm_registration_service::Error> {
        self.0
            .unix_seconds()
            .map_err(|_| rss_mdm_registration_service::Error::Runtime)
    }
}
impl AgentPki {
    pub(crate) fn issuance_ready(&self, now: i64) -> bool {
        !matches!(
            health(self.issuer.trust().expires(), now, self.required_seconds),
            "expired" | "issuance_unavailable"
        )
    }

    pub(crate) fn registration(self: Arc<Self>) -> rss_runtime::ManagedTaskRegistration {
        let (task, _) =
            rss_runtime::ManagedTask::prepare("agent-pki-expiry", Duration::from_secs(2));
        task.into_registration(move |token| async move {
            let mut previous = None;
            loop {
                let level = match self.clock.unix_seconds() {
                    Ok(now) => health(self.issuer.trust().expires(), now, self.required_seconds),
                    Err(_) => "clock_unavailable",
                };
                if previous != Some(level) {
                    eprintln!("{}", serde_json::json!({"event":"agent_certificate_health","purpose":"issuer","level":level}));
                    previous = Some(level);
                }
                tokio::select! {
                    biased;
                    () = token.cancelled() => return Ok(()),
                    () = tokio::time::sleep(Duration::from_secs(60)) => {}
                }
            }
        })
    }
}
fn health(expires: i64, now: i64, required: i64) -> &'static str {
    let remaining = expires.saturating_sub(now);
    let margin = remaining.saturating_sub(required);
    if remaining <= 0 {
        "expired"
    } else if margin < 0 {
        "issuance_unavailable"
    } else if margin <= 7 * 86400 {
        "critical"
    } else if margin <= 30 * 86400 {
        "renew_soon"
    } else {
        "healthy"
    }
}
#[cfg(test)]
#[path = "../tests/agent_pki/health.rs"]
mod tests;
