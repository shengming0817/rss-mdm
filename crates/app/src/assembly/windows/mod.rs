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
    pub poll: rss_mdm_windows_mdm::provisioning::Poll,
    pub push: Option<WindowsPushConfig>,
    pub additional_management: Vec<TlsEndpoint>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPushConfig {
    pub package_family_name: String,
    pub sid: String,
    pub client_secret_file: PathBuf,
}
impl WindowsConfig {
    pub(crate) fn validate(&self, browser: SocketAddr) -> Result<(), Error> {
        self.poll
            .validate()
            .map_err(|_| Error::Configuration(ConfigIssue::WindowsPoll))?;
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
        if self.additional_management.len() > 16 {
            return Err(Error::Configuration(ConfigIssue::WindowsListeners));
        }
        let mut origins = std::collections::BTreeSet::from([
            self.management.origin.as_str(),
            self.enrollment.origin.as_str(),
        ]);
        let mut listeners = std::collections::BTreeSet::from([
            browser,
            self.enrollment.listen,
            self.management.listen,
        ]);
        for endpoint in &self.additional_management {
            let uri = crate::config::https_url(&endpoint.origin)
                .map_err(|_| Error::Configuration(ConfigIssue::WindowsListeners))?;
            if uri.origin().ascii_serialization() != endpoint.origin
                || !origins.insert(&endpoint.origin)
                || !listeners.insert(endpoint.listen)
                || endpoint.listen.port() == 0
            {
                return Err(Error::Configuration(ConfigIssue::WindowsListeners));
            }
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
    additional_management_tls: Vec<Arc<tokio_rustls::rustls::ServerConfig>>,
}
impl Windows {
    #[allow(
        clippy::disallowed_methods,
        reason = "App composition root injects the system monotonic clock into the WNS transport"
    )]
    pub(crate) fn load(
        config: WindowsConfig,
        now: i64,
        agent: Option<rss_mdm_execution_service::agent_install::Identity>,
    ) -> Result<Self, Error> {
        let ca = certificate::WindowsEnrollmentAuthority::from_bytes(
            &crate::config::read(&config.ca_certificate_file, 32768, false)
                .map_err(|_| Error::Configuration(ConfigIssue::EnrollmentCa))?,
            &crate::config::read(&config.ca_private_key_file, 32768, true)
                .map_err(|_| Error::Configuration(ConfigIssue::EnrollmentCa))?,
            now,
        )
        .map_err(|_| Error::Configuration(ConfigIssue::EnrollmentCa))?;
        let enrollment_tls =
            tls::configuration(&config.enrollment, Some(ca.enrollment_verifier()))?;
        let management_tls = tls::configuration(&config.management, Some(ca.verifier()))?;
        let mut channel = rss_mdm_windows_channel::Windows::new(
            config.enrollment.origin.clone(),
            config.management.origin.clone(),
            config.provider_id.clone(),
            ca,
            &crate::config::read(&config.protocol_key_file, 32, true)
                .map_err(|_| Error::Configuration(ConfigIssue::ProtocolKey))?,
            config.poll.clone(),
        )
        .map_err(|_| Error::Configuration(ConfigIssue::ProtocolKey))?;
        channel.additional_management_origins = config
            .additional_management
            .iter()
            .map(|e| e.origin.clone())
            .collect();
        let additional_management_tls = config
            .additional_management
            .iter()
            .map(|endpoint| tls::configuration(endpoint, Some(channel.ca.verifier())))
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(push) = &config.push {
            let bytes = crate::config::read(&push.client_secret_file, 4096, true)
                .map_err(|_| Error::Configuration(ConfigIssue::WindowsPush))?;
            let secret = std::str::from_utf8(&bytes)
                .map_err(|_| Error::Configuration(ConfigIssue::WindowsPush))?;
            channel.push = Some(
                rss_mdm_windows_channel::push::Push::new(
                    push.package_family_name.clone(),
                    push.sid.clone(),
                    secret.trim_end_matches(['\r', '\n']).to_owned(),
                    Arc::new(crate::Monotonic(std::time::Instant::now)),
                )
                .map_err(|_| Error::Configuration(ConfigIssue::WindowsPush))?,
            );
        }
        channel.agent_identity = agent;
        let channel = Arc::new(channel);
        Ok(Self {
            config,
            channel,
            enrollment_tls,
            management_tls,
            additional_management_tls,
        })
    }
}
pub(crate) fn routers(
    windows: Option<&Windows>,
    app: Arc<rss_mdm_windows_channel::HttpState>,
    clock: Arc<dyn rss_observation::Clock>,
) -> Option<(TlsRouter, Vec<TlsRouter>)> {
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
    let mut management_routers = vec![TlsRouter {
        admission: admission::Admission::new(
            clock.clone(),
            app.requests.clone(),
            "mdm-management-tls",
        ),
        listen: windows.config.management.listen,
        tls: windows.management_tls.clone(),
        router: management,
    }];
    for (endpoint, tls) in windows
        .config
        .additional_management
        .iter()
        .zip(&windows.additional_management_tls)
    {
        let (_, router) = rss_mdm_windows_channel::routers(
            app.clone(),
            boundary(&windows.config.enrollment.origin),
            boundary(&endpoint.origin),
        );
        management_routers.push(TlsRouter {
            admission: admission::Admission::new(
                clock.clone(),
                app.requests.clone(),
                "mdm-management-tls",
            ),
            listen: endpoint.listen,
            tls: tls.clone(),
            router: router.layer(middleware::from_fn(admission::admit)),
        });
    }
    Some((
        TlsRouter {
            admission: admission::Admission::new(clock, app.requests.clone(), "mdm-enrollment-tls"),
            listen: windows.config.enrollment.listen,
            tls: windows.enrollment_tls.clone(),
            router: enrollment,
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

/// Map the existing execution authority to the channel's narrow wake port.
pub(crate) struct WakeEligibility(pub(crate) Arc<rss_mdm_execution_service::ExecutionService>);
impl rss_mdm_windows_channel::push::WakeEligibility for WakeEligibility {
    fn pending_in<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        device: &'a str,
        registration: uuid::Uuid,
        generation: i64,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<bool, rss_mdm_windows_channel::Error>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.0
                .windows_wake_pending_in(c, device, registration, generation)
                .await
                .map_err(Into::into)
        })
    }
}
