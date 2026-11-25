//! Agent issuer deployment inputs; private CA signing keys never enter this process.
use crate::{ConfigIssue, Error};
use rss_mdm_registration_service::certificate_issuance::DeviceIssuer;
use serde::Deserialize;
use std::sync::Arc;
#[derive(serde::Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Config {
    Disabled {},
    StepCa {
        endpoint: Box<crate::native::PublicEndpoint>,
        #[serde(default)]
        additional_origins: Vec<String>,
        #[serde(default)]
        bootstrap: Option<BootstrapConfig>,
        #[serde(default)]
        lifetime: Lifetime,
    },
}
#[derive(serde::Serialize, Deserialize)]
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
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfig {
    #[serde(default)]
    pub webhooks: Vec<crate::ca_webhooks::Credentials>,
}
pub(crate) struct AgentPki {
    pub issuer: Arc<DeviceIssuer>,
    pub bootstrap: Option<Arc<rss_mdm_pki_service::scep::Verifier>>,
    pub origins: rss_mdm_registration_service::agent::connections::InstalledOrigins,
    pub pki_clock: Arc<dyn rss_mdm_registration_service::certificate_issuance::Clock>,

    required_seconds: i64,
}
impl Config {
    pub(crate) fn load(
        &self,
        service_id: &str,
        _audit: Arc<rss_mdm_audit_integration::AuditStore>,
        clock: Arc<dyn crate::clock::Clock>,
        providers: Arc<rss_mdm_pki_service::providers::Providers>,
        registry: Arc<rss_mdm_pki_service::registry::Registry>,
        bootstrap: Option<Arc<rss_mdm_pki_service::scep::Verifier>>,
    ) -> Result<Option<Arc<AgentPki>>, Error> {
        let Self::StepCa {
            endpoint,
            additional_origins,
            lifetime,
            ..
        } = self
        else {
            return Ok(None);
        };
        let invalid = || Error::Configuration(ConfigIssue::AgentPki);
        let origins = rss_mdm_registration_service::agent::connections::InstalledOrigins::new(
            endpoint.origin.clone(),
            additional_origins,
        )
        .map_err(|_| invalid())?;
        let days = lifetime.days()?;
        let issuer = DeviceIssuer::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            providers,
            days,
            matches!(lifetime, Lifetime::Development { .. }),
            rss_mdm_agent_wire::pki::Purpose::Agent,
            registry,
            uuid::Uuid::parse_str(service_id).map_err(|_| invalid())?,
            Arc::new(PkiClock(clock.clone())),
        )
        .map_err(|_| invalid())?;
        Ok(Some(Arc::new(AgentPki {
            origins,
            pki_clock: Arc::new(PkiClock(clock.clone())),
            issuer: Arc::new(issuer),
            bootstrap,

            required_seconds: i64::from(days) * 86400,
        })))
    }
}
pub(crate) struct PkiClock(pub(crate) Arc<dyn crate::clock::Clock>);
impl rss_mdm_registration_service::certificate_issuance::Clock for PkiClock {
    fn unix_seconds(&self) -> Result<i64, rss_mdm_registration_service::Error> {
        self.0
            .unix_seconds()
            .map_err(|_| rss_mdm_registration_service::Error::Runtime)
    }
}
impl AgentPki {
    pub(crate) async fn issuance_ready_on(
        &self,
        c: &mut sqlx::PgConnection,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        now: i64,
    ) -> Result<bool, Error> {
        let trust = self
            .issuer
            .trust_on(c, execution)
            .await
            .map_err(Error::from)?;
        Ok(!matches!(
            health(trust.expires(), now, self.required_seconds),
            "expired" | "issuance_unavailable"
        ))
    }
    pub(crate) async fn issuance_ready(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        now: i64,
    ) -> bool {
        let Ok(trust) = self.issuer.trust(execution).await else {
            return false;
        };
        !matches!(
            health(trust.expires(), now, self.required_seconds),
            "expired" | "issuance_unavailable"
        )
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
impl Config {
    pub(crate) fn bootstrap_materials(
        &self,
        _service_id: &str,
        _providers: &rss_mdm_pki_service::providers::Providers,
        _now: i64,
    ) -> Result<Option<Arc<rss_mdm_pki_service::scep::Verifier>>, Error> {
        let Self::StepCa {
            bootstrap: Some(input),
            ..
        } = self
        else {
            return Ok(None);
        };
        Ok(if input.webhooks.is_empty() {
            None
        } else {
            Some(Arc::new(crate::ca_webhooks::load(&input.webhooks)?))
        })
    }
}

#[cfg(test)]
#[path = "../tests/agent_pki/health.rs"]
mod tests;

#[cfg(test)]
mod lifetime_tests {
    #[test]
    fn deployment_lifetime_has_a_closed_upper_bound() {
        assert_eq!(
            super::Lifetime::Development { days: 3650 }.days().unwrap(),
            3650
        );
        assert!(matches!(
            super::Lifetime::Development { days: 3651 }.days(),
            Err(crate::Error::Configuration(crate::ConfigIssue::AgentPki))
        ));
    }
}
