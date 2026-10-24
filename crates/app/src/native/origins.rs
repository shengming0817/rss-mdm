//! TLS client-certificate negotiation belongs to an origin, before HTTP route selection.
use crate::{ConfigIssue, Error, config::Config};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Origin {
    pub origin: String,
    pub client_certificate: bool,
}

pub(crate) fn public(config: &Config) -> Result<Vec<Origin>, Error> {
    let mut origins = BTreeMap::from([(config.product_origin.clone(), None)]);
    let mut add = |origin: &str, certificate: bool| -> Result<(), Error> {
        rss_mdm_agent_wire::connections::validate_origin(origin).map_err(|_| Error::Input)?;
        let mode = origins.entry(origin.to_owned()).or_default();
        if mode.is_some_and(|previous| previous != certificate) {
            return Err(Error::Configuration(ConfigIssue::WindowsListeners));
        }
        *mode = Some(certificate);
        Ok(())
    };
    if let Some(windows) = &config.native_protocols.windows {
        add(&windows.enrollment.origin, false)?;
        add(&windows.management.origin, true)?;
        for endpoint in &windows.additional_management {
            add(&endpoint.origin, true)?;
        }
    }
    if let Some(apple) = &config.native_protocols.apple {
        add(&apple.management.origin, true)?;
    }
    if let crate::agent_pki::Config::StepCa {
        endpoint,
        additional_origins,
        ..
    } = &config.agent_pki
    {
        add(&endpoint.origin, true)?;
        for origin in additional_origins {
            add(origin, true)?;
        }
    }
    origins
        .into_iter()
        .map(|(origin, mode)| {
            rss_mdm_agent_wire::connections::validate_origin(&origin).map_err(|_| Error::Input)?;
            Ok(Origin {
                origin,
                client_certificate: mode.unwrap_or(false),
            })
        })
        .collect()
}
