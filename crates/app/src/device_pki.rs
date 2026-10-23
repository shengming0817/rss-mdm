//! Public device PKI inputs; neither an offline root key nor a local signer is loaded.
use crate::{ConfigIssue, Error};
use rss_mdm_agent_wire::pki::{Purpose, Trust};
use rss_mdm_device_trust::DeviceTrust;
pub(crate) fn load(
    path: &std::path::Path,
    purpose: Purpose,
    now: i64,
) -> Result<DeviceTrust, Error> {
    let invalid = || Error::Configuration(ConfigIssue::AgentPki);
    let bytes = crate::config::read(path, 64 * 1024 * 1024, false)?;
    let trust: Trust = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    DeviceTrust::restore(trust, purpose, now).map_err(|_| invalid())
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    #[serde(default)]
    pub scep_url: Option<String>,
    pub purpose: Purpose,
    pub issuer: String,
    pub origin: String,
    pub tls_root_file: std::path::PathBuf,
    pub provisioner: String,
    pub kid: String,
    pub provisioner_key_file: std::path::PathBuf,
}
pub(crate) fn providers(
    config: &[Provider],
) -> Result<std::sync::Arc<rss_mdm_pki_service::providers::Providers>, Error> {
    let entries = config
        .iter()
        .map(|p| {
            let invalid = || Error::Configuration(ConfigIssue::AgentPki);
            let client = rss_mdm_pki_service::StepCa::new(
                rss_mdm_pki_service::Configuration {
                    origin: p.origin.clone(),
                    provisioner: p.provisioner.clone(),
                    kid: p.kid.clone(),
                },
                &crate::config::read(&p.tls_root_file, 131072, false).map_err(|_| invalid())?,
                &crate::config::read(&p.provisioner_key_file, 32768, true)
                    .map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())?;
            Ok(rss_mdm_pki_service::providers::Provider {
                purpose: p.purpose,
                issuer: p.issuer.clone(),
                client: std::sync::Arc::new(client),
                scep_url: p.scep_url.clone(),
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    rss_mdm_pki_service::providers::Providers::new(entries)
        .map(std::sync::Arc::new)
        .map_err(|_| Error::Configuration(ConfigIssue::AgentPki))
}

/// Prepare each issuer independently; a missing optional issuer cannot hide a valid one.
pub(crate) fn prepare(
    config: &[Provider],
    channels: &crate::channel_status::Channels,
) -> Result<std::sync::Arc<rss_mdm_pki_service::providers::Providers>, Error> {
    use crate::channel_status::{ChannelName, ChannelState, Reason};
    if config.len() > 48
        || config.iter().enumerate().any(|(i, p)| {
            config[..i]
                .iter()
                .any(|q| p.purpose == q.purpose && p.issuer == q.issuer)
        })
    {
        return Err(Error::Configuration(ConfigIssue::AgentPki));
    }
    let mut entries = Vec::new();
    for p in config {
        match providers(std::slice::from_ref(p)) {
            Ok(prepared) => {
                entries.push(rss_mdm_pki_service::providers::Provider {
                    purpose: p.purpose,
                    issuer: p.issuer.clone(),
                    client: prepared
                        .get(p.purpose, &p.issuer)
                        .map_err(|_| Error::Configuration(ConfigIssue::AgentPki))?
                        .clone(),
                    scep_url: p.scep_url.clone(),
                });
            }
            Err(Error::Configuration(_)) => {
                let name = match p.purpose {
                    Purpose::Windows => ChannelName::Windows,
                    Purpose::Apple => ChannelName::Apple,
                    Purpose::Agent => ChannelName::Agent,
                    Purpose::AgentBootstrap => ChannelName::AgentBootstrap,
                };
                channels.set(
                    name,
                    ChannelState::Degraded,
                    Some(Reason::MaterialUnreadable),
                )?;
            }
            Err(error) => return Err(error),
        }
    }
    rss_mdm_pki_service::providers::Providers::new(entries)
        .map(std::sync::Arc::new)
        .map_err(|_| Error::Configuration(ConfigIssue::AgentPki))
}

pub(crate) fn registration(
    pki: std::sync::Arc<rss_mdm_pki_service::registry::Registry>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare(
        "device-pki-maintenance",
        std::time::Duration::from_secs(10),
    );
    task.into_registration(move |token|async move {
        let mut failures=0_u64;
        loop {
            use crate::clock::Clock;
            let result=tokio::select!{biased;()=token.cancelled()=>return Ok(()),result=async {
                    let sweep=pki.sweep(|| crate::clock::SystemClock.unix_seconds().map_err(|_|rss_mdm_pki_service::Error::Storage)).await;
                    let health=pki.health().await?;
                    let now=crate::clock::SystemClock.unix_seconds().map_err(|_|rss_mdm_pki_service::Error::Storage)?;
                    for health in health {
                        if health.issuer_not_after-now<=30*86400 || health.root_not_after-now<=90*86400
                            || health.crl_next_update-now<=120 || health.root_crl_next_update-now<=7*86400
                            || health.unpublished_revocations>0 {
                            eprintln!("{}",serde_json::json!({"event":"device_pki_attention","observed_at":now,"health":health}));
                        }
                    }
                    sweep
                }=>result,
            };
            if result.is_err(){failures=failures.saturating_add(1);if failures.is_power_of_two(){eprintln!("{}",serde_json::json!({"event":"device_pki_maintenance_failure","count":failures}));}}else{failures=0;}
            tokio::select!{biased;()=token.cancelled()=>return Ok(()),()=tokio::time::sleep(std::time::Duration::from_secs(60))=>{}}
        }
    })
}
