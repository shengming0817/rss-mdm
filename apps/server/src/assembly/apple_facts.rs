//! Field mapping between Apple protocol facts and their business consumers.
use rss_mdm_apple_channel::protocol_types as protocol;
use rss_mdm_apple_channel::protocol_types::{AppleProfiles as _, AppleResults as _};
use rss_mdm_device_service::control::apple_facts::*;
use sqlx::PgConnection;
use uuid::Uuid;
pub(crate) struct AppleFacts(pub rss_mdm_apple_channel::flow_store::Store);
pub(super) fn error(e: rss_mdm_apple_channel::Error) -> rss_mdm_device_service::control::Error {
    use rss_mdm_apple_channel::{Error as A, Failure as F};
    use rss_mdm_device_service::control::{Error as E, Failure};
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
            .map_err(super::configuration_cleanup::error)
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
            let command = super::apple_business::command(command).map_err(error)?;
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
    fn sent<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
        ids: Vec<Uuid>,
    ) -> Pending<'a, std::collections::BTreeSet<Uuid>> {
        Box::pin(async move { self.0.sent_on(c, tenant, ids).await.map_err(error) })
    }

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
                .map_err(error)?
                .into_iter()
                .map(|(id, f)| match f {
                    protocol::AppleEvidence::Observations(o) => {
                        Ok((id, AppleEvidence::Observations(o)))
                    }
                    protocol::AppleEvidence::Declarations(_) => {
                        Err(rss_mdm_device_service::control::Error::Conflict)
                    }
                })
                .collect()
        })
    }

    fn control_applicability<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        requests: &'a [AppleControlCheck],
    ) -> Pending<
        'a,
        std::collections::BTreeMap<
            usize,
            rss_mdm_device_service::control::device_control::Applicability,
        >,
    > {
        Box::pin(async move {
            let requests = requests
                .iter()
                .map(|r| protocol::AppleControlCheck {
                    id: r.id,
                    device: r.device,

                    action: match r.action {
                        rss_mdm_device_service::control::device_control::Kind::Restart => {
                            protocol::ControlKind::Restart
                        }
                        rss_mdm_device_service::control::device_control::Kind::Lock => {
                            protocol::ControlKind::Lock
                        }
                        rss_mdm_device_service::control::device_control::Kind::Wipe => {
                            protocol::ControlKind::Wipe
                        }
                    },
                    command: r.command.clone(),
                })
                .collect::<Vec<_>>();
            self.0
                .control_applicability(c, tenant, &requests)
                .await
                .map_err(|e| match e {
                    // These are persisted accepted reports, not caller-supplied input.
                    rss_mdm_apple_channel::Error::Malformed => {
                        rss_mdm_device_service::control::Error::Unavailable(
                            rss_mdm_device_service::control::Failure::CommandInvariant,
                        )
                    }
                    other => error(other),
                })?
                .into_iter()
                .map(|(id, result)| {
                    use rss_mdm_apple_mdm::{applicability::Rejection, native::Error as E};
                    use rss_mdm_device_service::control::device_control::Applicability as A;
                    let state = match result {
                        Ok(()) => A::Supported,
                        Err(
                            E::Unsupported
                            | E::AccessRight
                            | E::Applicability(Rejection::Unsupported(_)),
                        ) => A::Unsupported,
                        Err(E::Applicability(Rejection::MissingEvidence(_))) => A::Unknown,
                        Err(_) => {
                            return Err(rss_mdm_device_service::control::Error::Unavailable(
                                rss_mdm_device_service::control::Failure::CommandInvariant,
                            ));
                        }
                    };
                    Ok((id, state))
                })
                .collect()
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
