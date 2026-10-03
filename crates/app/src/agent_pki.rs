//! Agent issuer deployment inputs; private CA signing keys never enter this process.
use crate::{ConfigIssue, Error};
use rss_mdm_registration_service::agent_pki::{AgentIssuer, Provider};
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc, time::Duration};
#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Config {
    Disabled {},
    StepCa {
        ca_url: String,
        tls_root_file: PathBuf,
        issuer_certificate_file: PathBuf,
        provisioner_key_file: PathBuf,
        kid: String,
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
    clock: Arc<dyn crate::clock::Clock>,
    required_seconds: i64,
}
impl Config {
    pub(crate) fn load(
        &self,
        audit: Arc<rss_mdm_audit_integration::AuditStore>,
        clock: Arc<dyn crate::clock::Clock>,
    ) -> Result<Option<Arc<AgentPki>>, Error> {
        let Self::StepCa {
            ca_url,
            tls_root_file,
            issuer_certificate_file,
            provisioner_key_file,
            kid,
            lifetime,
        } = self
        else {
            return Ok(None);
        };
        let invalid = || Error::Configuration(ConfigIssue::AgentPki);
        let days = lifetime.days()?;
        let trust = Arc::new(
            rss_mdm_certificate::agent::AgentTrust::from_pem(
                &crate::config::read(issuer_certificate_file, 32768, false)
                    .map_err(|_| invalid())?,
                "rss-agent",
                kid,
                days,
                clock.unix_seconds()?,
            )
            .map_err(|_| invalid())?,
        );
        let issuer = AgentIssuer::new(
            Provider {
                ca_url: ca_url.clone(),
                kid: kid.clone(),
                validity_days: days,
                development: matches!(lifetime, Lifetime::Development { .. }),
            },
            &crate::config::read(tls_root_file, 131072, false).map_err(|_| invalid())?,
            &crate::config::read(provisioner_key_file, 32768, true).map_err(|_| invalid())?,
            trust,
            Arc::new(PkiClock(clock.clone())),
            audit,
        )
        .map_err(|_| invalid())?;
        Ok(Some(Arc::new(AgentPki {
            issuer: Arc::new(issuer),
            clock,
            required_seconds: i64::from(days) * 86400,
        })))
    }
}
struct PkiClock(Arc<dyn crate::clock::Clock>);
impl rss_mdm_registration_service::agent_pki::Clock for PkiClock {
    fn unix_seconds(&self) -> Result<i64, rss_mdm_registration_service::Error> {
        self.0
            .unix_seconds()
            .map_err(|_| rss_mdm_registration_service::Error::Runtime)
    }
}
impl AgentPki {
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
