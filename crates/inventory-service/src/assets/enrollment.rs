//! Actual observed enrollment fact supplied to the registration task owner.
use rss_request_context::TenantId;
use sqlx::PgConnection;
pub struct EnrollmentObservation {
    profile: rss_mdm_install_support::StorageProfile,
}
impl EnrollmentObservation {
    pub fn new(profile: rss_mdm_install_support::StorageProfile) -> Self {
        Self { profile }
    }
}
impl rss_mdm_registration_service::enrollment::tasks::Inventory for EnrollmentObservation {
    fn storage_profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    fn enrollment_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: rss_mdm_agent_wire::DeviceId,
    ) -> std::pin::Pin<
        Box<
            dyn Future<
                    Output = Result<
                        rss_mdm_inventory::channel::Observation,
                        rss_mdm_registration_service::enrollment::tasks::Error,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            crate::assets::channel::detail_in(
                self.profile,
                c,
                tenant,
                device,
                rss_mdm_inventory::ReportSource::AgentBuiltin,
            )
            .await
            .map_err(|e| {
                use crate::Error as I;
                use rss_mdm_registration_service::enrollment::tasks::Error as E;
                match e {
                    I::CommitUnknown => E::CommitUnknown,
                    I::RollbackFailed => E::RollbackFailed,
                    I::Forbidden => E::Forbidden,
                    I::Unauthorized => E::Unauthorized,
                    I::Conflict => E::Conflict,
                    I::Malformed => E::Malformed,
                    _ => E::Unavailable,
                }
            })
        })
    }
}
