//! Registration readiness is observed independently from tenant admission.
use rss_mdm_agent_wire::pki::Purpose;
use rss_mdm_management_http::enrollment::channels::{Availability, Reason, Source, Status};
use rss_mdm_registration_service::quotas::Channel;
use std::sync::Arc;
pub(crate) struct Channels {
    pub windows: Option<Arc<crate::windows::Windows>>,
    pub agent: Option<Arc<crate::agent_pki::AgentPki>>,
    pub apple: Option<Arc<crate::apple::Apple>>,
    pub pki: Arc<rss_mdm_pki_service::registry::Registry>,
    pub clock: Arc<dyn crate::clock::Clock>,
}
impl Source for Channels {
    fn status(&self, channel: Channel) -> Status {
        let (configured, purpose) = match channel {
            Channel::Agent => (self.agent.is_some(), Purpose::Agent),
            Channel::WindowsMdm => (self.windows.is_some(), Purpose::Windows),
            Channel::MacosMdm => (self.apple.is_some(), Purpose::Apple),
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
        let valid = self
            .pki
            .trust(purpose)
            .ok()
            .and_then(|trust| rss_mdm_device_trust::DeviceTrust::new(trust, purpose, now).ok())
            .is_some();
        if !valid {
            return fault(Reason::CertificateUnavailable);
        }
        let issuance_ready = match channel {
            Channel::Agent => self.agent.as_ref().is_some_and(|p| p.issuance_ready(now)),
            Channel::WindowsMdm => self
                .windows
                .as_ref()
                .is_some_and(|w| w.channel.ca.issuance_end(now).is_ok()),
            Channel::MacosMdm => true,
        };
        if !issuance_ready {
            return fault(Reason::CertificateUnavailable);
        }
        if channel == Channel::MacosMdm {
            let health = self
                .apple
                .as_ref()
                .expect("configured Apple")
                .channel
                .health(now);
            if health.certificates_expired() {
                return fault(Reason::CertificateUnavailable);
            }
            if !health.push_available {
                return fault(Reason::PushUnavailable);
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
