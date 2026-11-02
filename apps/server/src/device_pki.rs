//! Public device PKI inputs; neither an offline root key nor a local signer is loaded.
use crate::{ConfigIssue, Error};
use rss_mdm_agent_wire::pki::Purpose;
use rss_mdm_device_trust::DeviceTrust;
pub(crate) fn load(
    path: &std::path::Path,
    purpose: Purpose,
    now: i64,
) -> Result<DeviceTrust, Error> {
    rss_mdm_pki_service::configuration::decode(
        &crate::config::read(path, 64 * 1024 * 1024, false)?,
        purpose,
        now,
    )
    .map_err(|_| Error::Configuration(ConfigIssue::AgentPki))
}
pub(crate) fn providers(
    config: &[rss_mdm_pki_service::configuration::Provider],
) -> Result<std::sync::Arc<rss_mdm_pki_service::providers::Providers>, Error> {
    rss_mdm_pki_service::configuration::providers(config)
        .map_err(|_| Error::Configuration(ConfigIssue::AgentPki))
}
/// Prepare each issuer independently; a missing optional issuer cannot hide a valid one.
pub(crate) fn prepare(
    config: &[rss_mdm_pki_service::configuration::Provider],
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
                    Purpose::DaDevice => return Err(Error::Forbidden),
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
    name: &'static str,
    pki: std::sync::Arc<rss_mdm_pki_service::registry::Registry>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare(name, std::time::Duration::from_secs(10));
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
