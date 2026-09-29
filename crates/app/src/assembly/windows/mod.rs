//! Host file loading, listener configuration and Windows channel construction.
use crate::native::{TlsEndpoint, TlsRouter, admission, tls};
use crate::{ConfigIssue, Error};
use axum::middleware;
use rss_mdm_certificate::windows as certificate;
use rss_mdm_windows_channel::boundary::Envelope;
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsConfig {
    pub enrollment: TlsEndpoint,
    pub management: TlsEndpoint,
    pub ca_certificate_file: PathBuf,
    pub ca_private_key_file: PathBuf,
    pub protocol_key_file: PathBuf,
    pub provider_id: String,
}
impl WindowsConfig {
    pub(crate) fn validate(&self, browser: SocketAddr) -> Result<(), Error> {
        if self.enrollment.listen == self.management.listen
            || self.enrollment.listen == browser
            || self.management.listen == browser
            || self.enrollment.origin == self.management.origin
            || self.provider_id.is_empty()
            || self.provider_id.len() > 64
            || !self
                .provider_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err(Error::Configuration(ConfigIssue::WindowsListeners));
        }
        for endpoint in [&self.enrollment, &self.management] {
            let u = crate::config::https_url(&endpoint.origin)
                .map_err(|_| Error::Configuration(ConfigIssue::WindowsListeners))?;
            if u.origin().ascii_serialization() != endpoint.origin || endpoint.listen.port() == 0 {
                return Err(Error::Configuration(ConfigIssue::WindowsListeners));
            }
        }
        Ok(())
    }
}

pub(crate) struct Windows {
    pub(crate) config: WindowsConfig,
    pub(crate) channel: Arc<rss_mdm_windows_channel::Windows>,
    pub(crate) enrollment_tls: Arc<tokio_rustls::rustls::ServerConfig>,
    pub(crate) management_tls: Arc<tokio_rustls::rustls::ServerConfig>,
}
impl Windows {
    pub(crate) fn load(
        config: WindowsConfig,
        now: i64,
        agent: Option<rss_mdm_flow_service::planning::policies::agent_install::Identity>,
    ) -> Result<Self, Error> {
        let ca = certificate::WindowsEnrollmentAuthority::from_bytes(
            &crate::config::read(&config.ca_certificate_file, 32768, false)
                .map_err(|_| Error::Configuration(ConfigIssue::EnrollmentCa))?,
            &crate::config::read(&config.ca_private_key_file, 32768, true)
                .map_err(|_| Error::Configuration(ConfigIssue::EnrollmentCa))?,
            now,
        )
        .map_err(|_| Error::Configuration(ConfigIssue::EnrollmentCa))?;
        let enrollment_tls = tls::configuration(&config.enrollment, None)?;
        let management_tls = tls::configuration(&config.management, Some(ca.verifier()))?;
        let mut channel = rss_mdm_windows_channel::Windows::new(
            config.enrollment.origin.clone(),
            config.management.origin.clone(),
            config.provider_id.clone(),
            ca,
            &crate::config::read(&config.protocol_key_file, 32, true)
                .map_err(|_| Error::Configuration(ConfigIssue::ProtocolKey))?,
        )
        .map_err(|_| Error::Configuration(ConfigIssue::ProtocolKey))?;
        channel.agent_identity = agent;
        let channel = Arc::new(channel);
        Ok(Self {
            config,
            channel,
            enrollment_tls,
            management_tls,
        })
    }
}
pub(crate) fn routers(
    windows: Option<&Windows>,
    app: Arc<rss_mdm_windows_channel::HttpState>,
    clock: Arc<dyn rss_observation::Clock>,
) -> Option<(TlsRouter, TlsRouter)> {
    let windows = windows?;
    let boundary = |origin: &str| Envelope {
        admission: Arc::new(tokio::sync::Semaphore::new(32)),
        host: origin.trim_start_matches("https://").into(),
        clock: clock.clone(),
        audit_store: app.audit_store.clone(),
        requests: app.requests.clone(),
        tenant: app.identity.tenant().to_string(),
    };
    let (enrollment, management) = rss_mdm_windows_channel::routers(
        app.clone(),
        boundary(&windows.config.enrollment.origin),
        boundary(&windows.config.management.origin),
    );
    let enrollment = enrollment.layer(middleware::from_fn(admission::admit));
    let management = management.layer(middleware::from_fn(admission::admit));
    Some((
        TlsRouter {
            admission: admission::Admission::new(
                clock.clone(),
                app.requests.clone(),
                "mdm-enrollment-tls",
            ),
            listen: windows.config.enrollment.listen,
            tls: windows.enrollment_tls.clone(),
            router: enrollment,
        },
        TlsRouter {
            admission: admission::Admission::new(clock, app.requests.clone(), "mdm-management-tls"),
            listen: windows.config.management.listen,
            tls: windows.management_tls.clone(),
            router: management,
        },
    ))
}
#[cfg(test)]
use rss_mdm_windows_channel::issuance;
#[cfg(test)]
#[path = "../../../tests/windows/mod.rs"]
mod t2;
#[cfg(test)]
#[path = "../../../tests/windows/support.rs"]
pub(crate) mod test_support;
