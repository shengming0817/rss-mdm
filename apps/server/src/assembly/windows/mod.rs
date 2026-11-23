//! Host file loading, listener configuration and Windows channel construction.
use crate::native::{ChannelRouter, PublicEndpoint, admission};
use crate::{ConfigIssue, Error};
use axum::middleware;
use rss_mdm_windows_channel::boundary::Envelope;
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsConfig {
    pub enrollment: PublicEndpoint,
    pub management: PublicEndpoint,

    pub protocol_protection: crate::config::NativeProtection,

    pub additional_management: Vec<PublicEndpoint>,
}
impl WindowsConfig {
    pub(crate) fn validate(&self, browser: SocketAddr) -> Result<(), Error> {
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
    pub(crate) channel: Arc<rss_mdm_windows_channel::runtime_materials::Runtime>,
}
impl Windows {
    pub(crate) fn load(
        config: WindowsConfig,
        authority: rss_identity_postgres::Authority,
        verifier: Arc<dyn rss_identity_core::entra::EntraTokenVerifier>,
        clock: Arc<dyn rss_observation::Clock>,
    ) -> Result<Self, Error> {
        let channel = Arc::new(rss_mdm_windows_channel::runtime_materials::Runtime::new(
            config.enrollment.origin.clone(),
            config.management.origin.clone(),
            config
                .additional_management
                .iter()
                .map(|e| e.origin.clone())
                .collect(),
            config.protocol_protection.load()?,
            authority,
            verifier,
            clock,
        ));
        Ok(Self { config, channel })
    }
}
pub(crate) fn routers(
    windows: Option<&Windows>,
    app: Arc<rss_mdm_windows_channel::HttpState>,
    clock: Arc<dyn rss_observation::Clock>,
    request_budget: rss_axum::RequestBudget,
    buffered_bytes: Arc<tokio::sync::Semaphore>,
) -> Option<(ChannelRouter, Vec<ChannelRouter>)> {
    let windows = windows?;
    let boundary = |origin: &str| Envelope {
        request_budget,
        host: origin.trim_start_matches("https://").into(),
        clock: clock.clone(),
        audit_store: app.audit_store.clone(),
        buffered_bytes: buffered_bytes.clone(),
    };
    let (enrollment, management) = rss_mdm_windows_channel::routers(
        app.clone(),
        boundary(&windows.config.enrollment.origin),
        boundary(&windows.config.management.origin),
    );
    let enrollment = enrollment.layer(middleware::from_fn(admission::admit));
    let management = management.layer(middleware::from_fn(admission::admit_windows));
    let management_admission = admission::Admission::new(clock.clone(), "mdm-management-tls");
    let mut management_routers = vec![ChannelRouter {
        admission: management_admission.clone(),
        origins: vec![windows.config.management.origin.clone()],
        router: management
            .into_checked_axum(rss_mdm_http_contract::module::Listener::WindowsManagement),
    }];
    for endpoint in &windows.config.additional_management {
        let (_, router) = rss_mdm_windows_channel::routers(
            app.clone(),
            boundary(&windows.config.enrollment.origin),
            boundary(&endpoint.origin),
        );
        management_routers.push(ChannelRouter {
            admission: management_admission.clone(),
            origins: vec![endpoint.origin.clone()],
            router: router
                .layer(middleware::from_fn(admission::admit_windows))
                .into_checked_axum(rss_mdm_http_contract::module::Listener::WindowsManagement),
        });
    }
    Some((
        ChannelRouter {
            admission: admission::Admission::new(clock, "mdm-enrollment-tls"),
            origins: vec![windows.config.enrollment.origin.clone()],
            router: enrollment
                .into_checked_axum(rss_mdm_http_contract::module::Listener::WindowsEnrollment),
        },
        management_routers,
    ))
}

#[cfg(test)]
#[path = "../../../tests/windows/unit.rs"]
mod unit;
