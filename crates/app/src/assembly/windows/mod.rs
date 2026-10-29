//! Host file loading, listener configuration and Windows channel construction.
use crate::native::{ChannelRouter, PublicEndpoint, admission};
use crate::{ConfigIssue, Error};
use axum::middleware;
use rss_mdm_certificate::windows as certificate;
use rss_mdm_windows_channel::boundary::Envelope;
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsConfig {
    pub entra: Option<rss_mdm_windows_channel::entra::Config>,
    pub enrollment: PublicEndpoint,
    pub management: PublicEndpoint,
    pub trust_file: PathBuf,
    pub protocol_protection: crate::config::NativeProtection,
    #[serde(default)]
    pub lifetime: certificate::Lifetime,
    pub provider_id: String,
    pub poll: rss_mdm_windows_mdm::provisioning::Poll,
    pub push: Option<WindowsPushConfig>,
    pub additional_management: Vec<PublicEndpoint>,
}
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPushConfig {
    pub revision: i64,
}
impl WindowsConfig {
    pub(crate) fn validate(&self, browser: SocketAddr) -> Result<(), Error> {
        if self.push.as_ref().is_some_and(|p| p.revision < 1) {
            return Err(Error::Configuration(ConfigIssue::WindowsPush));
        }
        self.poll
            .validate()
            .map_err(|_| Error::Configuration(ConfigIssue::WindowsPoll))?;
        let _ = browser;
        if self.additional_management.len() > 16 {
            return Err(Error::Configuration(ConfigIssue::WindowsListeners));
        }
        let mut origins = std::collections::BTreeSet::from([
            self.management.origin.as_str(),
            self.enrollment.origin.as_str(),
        ]);
        for endpoint in &self.additional_management {
            let uri = crate::config::https_url(&endpoint.origin)
                .map_err(|_| Error::Configuration(ConfigIssue::WindowsListeners))?;
            if uri.origin().ascii_serialization() != endpoint.origin
                || !origins.insert(&endpoint.origin)
            {
                return Err(Error::Configuration(ConfigIssue::WindowsListeners));
            }
        }
        for endpoint in [&self.enrollment, &self.management] {
            let u = crate::config::https_url(&endpoint.origin)
                .map_err(|_| Error::Configuration(ConfigIssue::WindowsListeners))?;
            if u.origin().ascii_serialization() != endpoint.origin {
                return Err(Error::Configuration(ConfigIssue::WindowsListeners));
            }
        }
        Ok(())
    }
}

pub(crate) struct Windows {
    pub(crate) config: WindowsConfig,
    pub(crate) channel: Arc<rss_mdm_windows_channel::Windows>,
}
impl Windows {
    #[allow(
        clippy::disallowed_methods,
        reason = "App composition root injects the system monotonic clock into the WNS transport"
    )]
    pub(crate) fn load(
        config: WindowsConfig,
        now: i64,
        providers: Arc<rss_mdm_pki_service::providers::Providers>,
        push: Option<rss_mdm_windows_channel::push::Push>,
    ) -> Result<Self, Error> {
        let trust = crate::device_pki::load(
            &config.trust_file,
            rss_mdm_agent_wire::pki::Purpose::Windows,
            now,
        )?;
        if trust
            .public()
            .map_err(|_| Error::Configuration(ConfigIssue::EnrollmentCa))?
            .origin
            != config.management.origin
        {
            return Err(Error::Configuration(ConfigIssue::EnrollmentCa));
        }
        if matches!(config.lifetime, certificate::Lifetime::Development { .. }) {
            return Err(Error::Configuration(ConfigIssue::EnrollmentCa));
        }
        let ca = rss_mdm_device_trust::windows::WindowsDeviceTrust::from_trust(trust)
            .and_then(|ca| ca.with_lifetime(config.lifetime))
            .map_err(|_| Error::Configuration(ConfigIssue::EnrollmentCa))?;
        let mut channel = rss_mdm_windows_channel::Windows::new(
            config.enrollment.origin.clone(),
            config.management.origin.clone(),
            config.provider_id.clone(),
            ca,
            providers,
            config
                .protocol_protection
                .load()
                .map_err(|_| Error::Configuration(ConfigIssue::ProtocolKey))?,
            config.poll.clone(),
        )
        .map_err(|_| Error::Configuration(ConfigIssue::ProtocolKey))?;
        channel.additional_management_origins = config
            .additional_management
            .iter()
            .map(|e| e.origin.clone())
            .collect();
        channel.push = push;
        Ok(Self {
            config,
            channel: Arc::new(channel),
        })
    }
}
pub(crate) fn routers(
    windows: Option<&Windows>,
    app: Arc<rss_mdm_windows_channel::HttpState>,
    clock: Arc<dyn rss_observation::Clock>,
) -> Option<(ChannelRouter, Vec<ChannelRouter>)> {
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
    let mut management_routers = vec![ChannelRouter {
        admission: admission::Admission::new(
            clock.clone(),
            app.requests.clone(),
            "mdm-management-tls",
        ),
        origins: vec![windows.config.management.origin.clone()],
        router: management.into_checked_axum(rss_mdm_http_contract::catalog::WINDOWS_LISTENER),
    }];
    for endpoint in &windows.config.additional_management {
        let (_, router) = rss_mdm_windows_channel::routers(
            app.clone(),
            boundary(&windows.config.enrollment.origin),
            boundary(&endpoint.origin),
        );
        management_routers.push(ChannelRouter {
            admission: admission::Admission::new(
                clock.clone(),
                app.requests.clone(),
                "mdm-management-tls",
            ),
            origins: vec![endpoint.origin.clone()],
            router: router
                .layer(middleware::from_fn(admission::admit))
                .into_checked_axum(rss_mdm_http_contract::catalog::WINDOWS_LISTENER),
        });
    }
    Some((
        ChannelRouter {
            admission: admission::Admission::new(clock, app.requests.clone(), "mdm-enrollment-tls"),
            origins: vec![windows.config.enrollment.origin.clone()],
            router: enrollment.into_checked_axum(rss_mdm_http_contract::catalog::WINDOWS_LISTENER),
        },
        management_routers,
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

#[cfg(test)]
#[path = "../../../tests/windows/unit.rs"]
mod unit;
