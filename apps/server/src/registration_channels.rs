//! Registration readiness is observed independently from tenant admission.
#[derive(Clone, Copy)]
pub(crate) enum Availability {
    Unconfigured,
    Ready,
    Fault,
}
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    NotConfigured,
    CertificateUnavailable,
    PushUnavailable,
    ClockUnavailable,
}
pub(crate) struct Status {
    pub availability: Availability,
    pub reason: Option<Reason>,
}
use rss_mdm_registration_service::quotas::Channel;
use std::sync::Arc;
pub(crate) struct Channels {
    pub preparation: Arc<crate::channel_status::Channels>,
    pub windows: Arc<rss_mdm_windows_channel::HttpState>,
    pub agent: Option<Arc<crate::agent_pki::AgentPki>>,
    pub apple: Arc<rss_mdm_apple_channel::HttpState>,

    pub clock: Arc<dyn crate::clock::Clock>,
}
impl Channels {
    pub(crate) async fn status(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        channel: Channel,
    ) -> Status {
        let configured = match channel {
            Channel::Agent => self.agent.is_some(),
            Channel::WindowsMdm => self.windows.windows.is_some(),
            Channel::MacosMdm => self.apple.apple.is_some(),
        };
        if !configured {
            return Status {
                availability: Availability::Unconfigured,
                reason: Some(Reason::NotConfigured),
            };
        }
        let Ok(now) = self.clock.unix_seconds() else {
            return fault(Reason::ClockUnavailable);
        };
        match channel {
            Channel::Agent => {
                if !self
                    .agent
                    .as_ref()
                    .expect("configured Agent")
                    .issuance_ready(binding, now)
                    .await
                {
                    return fault(Reason::CertificateUnavailable);
                }
            }
            Channel::WindowsMdm => {
                let Ok(windows) = self.windows.windows(binding).await else {
                    return fault(Reason::CertificateUnavailable);
                };
                if windows.ca.issuance_end(now).is_err() {
                    return fault(Reason::CertificateUnavailable);
                }
            }
            Channel::MacosMdm => {
                let Ok(apple) = self.apple.apple(binding).await else {
                    return fault(Reason::CertificateUnavailable);
                };
                let health = apple.health(now);
                if health.certificates_expired() {
                    return fault(Reason::CertificateUnavailable);
                }
                if !health.push_available {
                    return fault(Reason::PushUnavailable);
                }
            }
        }
        Status {
            availability: Availability::Ready,
            reason: None,
        }
    }
}
fn fault(reason: Reason) -> Status {
    Status {
        availability: Availability::Fault,
        reason: Some(reason),
    }
}
