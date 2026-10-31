//! Field mapping between Apple protocol facts and their business consumers.
use rss_mdm_apple_channel::protocol_types as protocol;
use rss_mdm_apple_channel::protocol_types::{
    AppleCollections as _, AppleProfiles as _, AppleResults as _,
};
use rss_mdm_audit_integration::Fact;
use rss_mdm_execution_service::apple_facts::*;
use rss_mdm_registration_service::DevicePrincipal;
use sqlx::PgConnection;
use uuid::Uuid;
pub(crate) struct AppleFacts(pub rss_mdm_apple_channel::flow_store::Store);
pub(super) fn error(e: rss_mdm_apple_channel::Error) -> rss_mdm_execution_service::Error {
    use rss_mdm_apple_channel::{Error as A, Failure as F};
    use rss_mdm_execution_service::{Error as E, Failure};
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

    fn declaration_candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        user: &'a str,
    ) -> Pending<'a, Vec<Uuid>> {
        Box::pin(async move {
            self.0
                .declaration_candidates(c, p, user)
                .await
                .map_err(error)
        })
    }
    fn previous_declarations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: String,
        user: String,
        owner: String,
    ) -> Pending<'a, Vec<Uuid>> {
        Box::pin(async move {
            self.0
                .previous_declarations(c, tenant, device, user, owner)
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
                registration: target.registration,
                generation: target.generation,
            };
            let command = super::apple_business::command(command);
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
        device: String,
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
    fn platform_sso_observation<'a>(
        &'a self,
        c: &'a mut PgConnection,
        binding: &'a rss_mdm_registration_service::device_access::Binding,
        facts: &'a rss_mdm_agent_wire::runtime::AccessMacPlatformSsoFacts,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            self.0
                .platform_sso_observation(c, binding, facts)
                .await
                .map_err(error)
        })
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
    fn purge_credential_inputs<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
        terminal: bool,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            self.0
                .purge_credential_inputs(c, tenant, operation, terminal)
                .await
                .map_err(error)
        })
    }
    fn declaration_page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        generation: i64,
        after: Option<Uuid>,
        limit: usize,
    ) -> Pending<'a, Vec<(Uuid, String)>> {
        Box::pin(async move {
            self.0
                .declaration_page(c, tenant, registration, generation, after, limit)
                .await
                .map_err(error)
        })
    }
    fn device_controls_supported<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        requests: &'a [AppleControlCheck],
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, bool>> {
        Box::pin(async move {
            let requests = requests
                .iter()
                .map(|r| protocol::AppleControlCheck {
                    id: r.id,
                    registration: r.registration,
                    generation: r.generation,
                    action: match r.action {
                        rss_mdm_execution_service::device_control::Kind::Restart => {
                            protocol::ControlKind::Restart
                        }
                        rss_mdm_execution_service::device_control::Kind::Lock => {
                            protocol::ControlKind::Lock
                        }
                        rss_mdm_execution_service::device_control::Kind::Wipe => {
                            protocol::ControlKind::Wipe
                        }
                    },
                    command: r.command.clone(),
                })
                .collect::<Vec<_>>();
            self.0
                .device_controls_supported(c, tenant, &requests)
                .await
                .map_err(error)
        })
    }
    fn withdrawal_published<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            self.0
                .withdrawal_published(c, tenant, operation)
                .await
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
