//! Standalone listener and shutdown budgets, compiled once before acquiring resources.
use super::{
    identity::{Compiled as Identity, seconds},
    *,
};
use std::time::Duration;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http {
    pub max_connections: usize,
    pub handshake_seconds: u64,
    pub rejection_seconds: u64,
    pub connection_drain_seconds: u64,
    pub header_seconds: u64,
    pub max_headers: usize,
    pub max_header_bytes: usize,
    pub request_drain_seconds: u64,
    pub total_drain_seconds: u64,
    pub maintenance_drain_seconds: u64,
}
#[derive(Clone, Copy)]
pub struct Compiled {
    pub listener: rss_axum::Http1ServePolicy,
    pub requests: Duration,
    pub total: Duration,
    pub maintenance: Duration,
}
impl Http {
    pub(super) fn compile(&self, identity: &Identity) -> Result<Compiled> {
        let requests = seconds(self.request_drain_seconds)?;
        let total = seconds(self.total_drain_seconds)?;
        let maintenance = seconds(self.maintenance_drain_seconds)?;
        let connections = seconds(self.connection_drain_seconds)?;
        if identity.request > requests
            || identity.request > connections
            || [
                requests,
                connections,
                identity.drain,
                Duration::from_secs(10),
            ]
            .into_iter()
            .any(|d| d > total)
            || [identity.drain, Duration::from_secs(5)]
                .into_iter()
                .any(|d| d > maintenance)
        {
            return Err(Error::Configuration);
        }
        let listener = rss_axum::Http1ServePolicy::new(
            rss_axum::ServePolicy::new(
                self.max_connections,
                seconds(self.handshake_seconds)?,
                seconds(self.rejection_seconds)?,
                connections,
            )
            .map_err(|_| Error::Configuration)?,
            seconds(self.header_seconds)?,
            self.max_headers,
            self.max_header_bytes,
        )
        .map_err(|_| Error::Configuration)?;
        Ok(Compiled {
            listener,
            requests,
            total,
            maintenance,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configured_request_and_password_work_fit_their_shutdown_budgets() {
        let mut config: Config = serde_json::from_str(include_str!(
            "../../../../deployment/da-config.example.json"
        ))
        .unwrap();
        let compile = |c: &Config| {
            c.http.compile(
                &c.identity_policy
                    .compile(&c.installation, rss_audit_postgres::Integrity::Plain)?,
            )
        };
        assert!(compile(&config).is_ok());
        config.identity_policy.request_seconds = 30;
        config.http.request_drain_seconds = 30;
        config.http.connection_drain_seconds = 30;
        config.identity_policy.drain_seconds = 40;
        config.http.maintenance_drain_seconds = 40;
        assert!(compile(&config).is_ok());
        config.http.request_drain_seconds = 29;
        assert!(compile(&config).is_err());
        config.http.request_drain_seconds = 30;
        config.http.maintenance_drain_seconds = 39;
        assert!(compile(&config).is_err());
        config.http.maintenance_drain_seconds = 40;
        config.http.total_drain_seconds = 39;
        assert!(compile(&config).is_err());
    }
}
