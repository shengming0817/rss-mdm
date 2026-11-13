//! Field mapping between Apple protocol facts and their business consumers.
use rss_mdm_apple_channel::protocol_types as protocol;
use rss_mdm_apple_channel::protocol_types::{AppleProfiles as _, AppleResults as _};
use rss_mdm_recovery_credentials::native::apple_facts::*;
use sqlx::PgConnection;
use uuid::Uuid;
pub(crate) struct AppleFacts(pub rss_mdm_apple_channel::flow_store::Store);
pub(super) fn error(
    e: rss_mdm_apple_channel::Error,
) -> rss_mdm_recovery_credentials::native::Error {
    use rss_mdm_apple_channel::{Error as A, Failure as F};
    use rss_mdm_recovery_credentials::native::{Error as E, Failure};
    match e {
        A::CommitUnknown => E::CommitUnknown,
        A::RollbackFailed => E::RollbackFailed,
        A::Malformed | A::CertificateRequest => E::Malformed,
        A::Unauthorized => E::Unauthorized,
        A::Forbidden => E::Forbidden,
        A::Conflict => E::Conflict,
        A::EnrollmentPaused => E::EnrollmentPaused,
        A::Unsupported => E::Unsupported,
        A::NotFound => E::NotFound,
        A::Unavailable(f) => E::Unavailable(match f {
            F::RequestDeadline => Failure::RequestDeadline,
            F::Audit => Failure::Audit,
            F::AuditIntegrity => Failure::AuditIntegrity,
            F::AuditIsolation => Failure::AuditIsolation,
            F::AuditAdmission => Failure::AuditAdmission,
            F::AuditContract => Failure::AuditContract,
            _ => Failure::Protocol,
        }),
        _ => E::Unavailable(Failure::Protocol),
    }
}
impl AppleProfiles for AppleFacts {
    fn operation_permissions<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
        operations: Vec<Uuid>,
    ) -> Pending<'a, Vec<rss_mdm_authorization_service::Permission>> {
        Box::pin(async move {
            super::configuration_channels::operation_permissions(
                c,
                tenant,
                &self.0.protection,
                operations,
            )
            .await
            .map_err(policy_error)
        })
    }

    fn bind_command<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
        binding: rss_mdm_registration_service::command_authority::CommandBinding,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_apple_channel::command_binding::bind_on(c, tenant, binding)
                .await
                .map_err(error)
        })
    }

    fn reserve_profile<'a>(
        &'a self,
        c: &'a mut PgConnection,
        target: AppleRegistration,
        command: AppleCommand,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            let target = protocol::AppleRegistration {
                tenant: target.tenant,
                device: target.device,
            };
            let command = super::apple_business::recovery_command(command);
            self.0
                .reserve_profile(c, target, command)
                .await
                .map_err(error)
        })
    }
    fn previous_profiles<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: rss_mdm_agent_wire::DeviceId,
        user_key: String,
        identifier: String,
    ) -> Pending<'a, Vec<Uuid>> {
        Box::pin(async move {
            self.0
                .previous_profiles(c, tenant, device, user_key, identifier)
                .await
                .map_err(error)
        })
    }
}
impl AppleResults for AppleFacts {
    fn evidence_page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        requests: Vec<(Uuid, rss_mdm_apple_mdm::native::request::Request)>,
        native_values: bool,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, AppleEvidence>> {
        Box::pin(async move {
            self.0
                .evidence_page(c, tenant, requests, native_values)
                .await
                .map(|rows| {
                    rows.into_iter()
                        .map(|(id, f)| {
                            (
                                id,
                                match f {
                                    protocol::AppleEvidence::Declarations(d) => {
                                        AppleEvidence::Declarations(d)
                                    }
                                    protocol::AppleEvidence::Observations(o) => {
                                        AppleEvidence::Observations(o)
                                    }
                                },
                            )
                        })
                        .collect()
                })
                .map_err(error)
        })
    }

    fn declarations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
        native_values: bool,
    ) -> Pending<'a, Option<rss_mdm_apple_mdm::native::evidence::DeclarationEvidence>> {
        Box::pin(async move {
            self.0
                .declarations(c, tenant, operation, native_values)
                .await
                .map_err(error)
        })
    }
    fn observations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
        request: rss_mdm_apple_mdm::native::request::Request,
        native_values: bool,
    ) -> Pending<'a, Vec<rss_mdm_apple_mdm::native::evidence::Observation>> {
        Box::pin(async move {
            self.0
                .observations(c, tenant, operation, request, native_values)
                .await
                .map_err(error)
        })
    }
}

fn policy_error(e: rss_mdm_policy_service::Error) -> rss_mdm_recovery_credentials::native::Error {
    use rss_mdm_policy_service::Error as P;
    use rss_mdm_recovery_credentials::native::{Error as E, Failure};
    match e {
        P::CommitUnknown => E::CommitUnknown,
        P::RollbackFailed => E::RollbackFailed,
        P::Forbidden => E::Forbidden,
        P::Unauthorized => E::Unauthorized,
        P::Conflict => E::Conflict,
        P::Malformed => E::Malformed,
        _ => E::Unavailable(Failure::Protocol),
    }
}
