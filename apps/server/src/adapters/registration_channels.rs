use crate::registration_channels::{Availability, Channels, Reason};
use rss_mdm_registration_service::quotas::Channel;
impl rss_mdm_management_http::enrollment::channels::Source for Channels {
    fn endpoints(&self) -> rss_mdm_management_http::enrollment::channels::PublicEndpoints {
        self.preparation.endpoints()
    }
    fn status(&self, channel: Channel) -> rss_mdm_management_http::enrollment::channels::Status {
        use rss_mdm_management_http::enrollment::channels as http;
        let status = Channels::status(self, channel);
        http::Status {
            availability: match status.availability {
                Availability::Ready => http::Availability::Ready,
                Availability::Fault => http::Availability::Fault,
                Availability::Unconfigured => http::Availability::Unconfigured,
            },
            reason: status.reason.map(|reason| match reason {
                Reason::NotConfigured => http::Reason::NotConfigured,
                Reason::CertificateUnavailable => http::Reason::CertificateUnavailable,
                Reason::PushUnavailable => http::Reason::PushUnavailable,
                Reason::ClockUnavailable => http::Reason::ClockUnavailable,
            }),
        }
    }
}
