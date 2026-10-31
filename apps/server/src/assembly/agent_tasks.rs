//! Static adapters; task business remains with its current owner.
use rss_mdm_agent_channel::{
    delivery::{EventEffects, Pending, Tasks},
    participants::{Installation, RecoveryUse, SelfService},
};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_registration_service::DevicePrincipal;
use rss_transactional_messaging_postgres::PgTransaction;
use std::sync::Arc;
use uuid::Uuid;
pub(crate) struct AgentTasks(pub Arc<rss_mdm_execution_service::ExecutionService>);
pub(super) fn error(e: rss_mdm_execution_service::Error) -> rss_mdm_agent_channel::Error {
    use rss_mdm_agent_channel::Missing;
    use rss_mdm_agent_channel::{Error as A, Failure};
    use rss_mdm_execution_service::Error as E;
    match e { E::MdmSoftwareDisabled => A::Forbidden, E::Malformed => A::Malformed, E::CertificateRequest => A::CertificateRequest,
            E::Unauthorized => A::Unauthorized, E::Forbidden => A::Forbidden, E::ReadConflict | E::CursorInvalidated | E::Conflict | E::EnrollmentPaused | E::WindowsDeclaredEnrollmentNotReady => A::Conflict,
            E::CommitUnknown => A::CommitUnknown, E::RollbackFailed => A::RollbackFailed, E::Unsupported => A::Unsupported,
            E::NotFound => A::NotFound, E::Resource(_) => A::Missing(Missing::Resource),
            E::Execution(e) => A::Missing(match e { rss_mdm_execution_service::missing::ExecutionError::MissingOperation => Missing::Operation, rss_mdm_execution_service::missing::ExecutionError::MissingTask => Missing::Task }),
            E::Publication(e) => A::Missing(match e { rss_mdm_software_service::management::publication::error::PublicationError::MissingSource => Missing::SoftwareSource, rss_mdm_software_service::management::publication::error::PublicationError::MissingPublication => Missing::SoftwarePublication }),
            E::Configuration(_) => A::Unavailable(Failure::BusinessConfiguration),
            E::Unavailable(f) => A::Unavailable(match f {
                rss_mdm_execution_service::Failure::RequestDeadline => Failure::RequestDeadline,
                rss_mdm_execution_service::Failure::Audit => Failure::Audit,
                rss_mdm_execution_service::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_execution_service::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_execution_service::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_execution_service::Failure::AuditContract => Failure::AuditContract,

                _ => Failure::Business,
            }),
        }
}
fn fault(e: rss_mdm_execution_service::transaction::Fault) -> rss_mdm_agent_channel::Error {
    use rss_mdm_execution_service::transaction::Fault;
    match e {
        Fault::Request(e) => error(e),
        Fault::Storage(e) => e.into(),
        Fault::Sql(e) => e.into(),
    }
}
impl Tasks for AgentTasks {
    fn prepare<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, ()> {
        Box::pin(async move { self.0.agent_prepare_in(tx, p).await.map_err(fault) })
    }
    fn offer<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        input: &'a wire::TaskClaimRequest,
        attempt: Uuid,
        audit: &'a RequestAudit,
    ) -> Pending<'a, Option<(wire::TaskPayload, rss_mdm_audit_integration::Fact)>> {
        Box::pin(async move {
            self.0
                .agent_offer_in(tx, p, input, attempt, audit)
                .await
                .map_err(fault)
        })
    }
    fn replay_offer<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        signed: &'a wire::SignedTask,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.0
                .agent_replay_offer_in(tx, p, signed, audit)
                .await
                .map_err(fault)
        })
    }
    fn replay_event<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        task: Uuid,
        input: &'a wire::TaskEventRequest,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.0
                .agent_replay_event_in(tx, p, task, input, audit)
                .await
                .map_err(fault)
        })
    }
    fn event<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        task: Uuid,
        input: &'a wire::TaskEventRequest,
        audit: &'a RequestAudit,
    ) -> Pending<'a, EventEffects> {
        Box::pin(async move {
            let e = self
                .0
                .agent_event_in(tx, p, task, input, audit)
                .await
                .map_err(fault)?;
            Ok(EventEffects {
                start: e.start,
                cancelled: e.cancelled,
                credentials: e.credentials,
                fact: e.fact,
            })
        })
    }
    fn cancellations<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        registration: Uuid,
        after: Option<Uuid>,
    ) -> Pending<'a, Vec<wire::TaskCancellation>> {
        Box::pin(async move {
            self.0
                .agent_cancellations_in(tx, registration, after)
                .await
                .map_err(fault)
        })
    }
    fn content<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        task: Uuid,
        attempt: Uuid,
        key: Option<&'a str>,
        audit: &'a RequestAudit,
    ) -> Pending<'a, rss_mdm_resource::Artifact> {
        Box::pin(async move {
            self.0
                .agent_content_in(tx, p, task, attempt, key, audit)
                .await
                .map_err(fault)
        })
    }
}
impl SelfService for AgentTasks {
    fn resolve<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        proof: Option<&'a AuthorizedPrincipal>,
        input: &'a wire::SelfServiceResolve,
        audit: &'a RequestAudit,
    ) -> Pending<'a, wire::SelfServiceDirectoryItem> {
        Box::pin(async move {
            self.0
                .resolve_self_service(p, proof, input, audit)
                .await
                .map_err(error)
        })
    }
    fn directory<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        proof: Option<&'a AuthorizedPrincipal>,
        query: &'a str,
        audit: &'a RequestAudit,
    ) -> Pending<'a, wire::SelfServiceDirectoryResponse> {
        Box::pin(async move {
            self.0
                .self_service_directory(
                    p,
                    proof,
                    &rss_mdm_execution_service::self_service::directory::Input::new(query),
                    audit,
                )
                .await
                .map_err(error)
        })
    }
    fn invoke<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        proof: Option<&'a AuthorizedPrincipal>,
        input: &'a wire::SelfServiceInvoke,
        audit: &'a RequestAudit,
    ) -> Pending<'a, wire::SelfServiceAccepted> {
        Box::pin(async move {
            self.0
                .invoke_self_service(p, proof, input, audit)
                .await
                .map_err(error)
        })
    }
    fn status<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        proof: Option<&'a AuthorizedPrincipal>,
        id: Uuid,
        audit: &'a RequestAudit,
    ) -> Pending<'a, wire::SelfServiceStatus> {
        Box::pin(async move {
            self.0
                .self_service_status(p, proof, id, audit)
                .await
                .map_err(error)
        })
    }
}
impl Installation for AgentTasks {
    fn enrollment<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        task: Uuid,
        input: &'a rss_mdm_agent_wire::enroll::NativeEnrollmentRequest,
        audit: &'a RequestAudit,
    ) -> Pending<'a, rss_mdm_agent_wire::enroll::NativeEnrollmentReceipt> {
        Box::pin(async move {
            self.0
                .native_enrollment(p, task, input, audit)
                .await
                .map_err(error)
        })
    }
    fn content<'a>(
        &'a self,
        id: Uuid,
        audit: &'a RequestAudit,
    ) -> Pending<'a, rss_mdm_content_service::Verified> {
        Box::pin(async move { self.0.installation_content(id, audit).await.map_err(error) })
    }
}
impl RecoveryUse for AgentTasks {
    fn record<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        input: &'a wire::AccessRecoveryUse,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.0
                .record_access_recovery_use(p, input, audit)
                .await
                .map_err(error)
        })
    }
}

pub(super) struct SelfServiceQuery;
impl rss_mdm_http_contract::query::QueryOwner for SelfServiceQuery {
    type Parsed = String;
    type Error = std::convert::Infallible;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Directory(
            rss_mdm_execution_service::self_service::directory::Input::schema(),
        ))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let mut schema =
            rss_mdm_http_contract::signature::Schema::request::<wire::SelfServiceDirectory>();
        schema.value["properties"]["limit"]["minimum"] = 1.into();
        schema.value["properties"]["limit"]["maximum"] =
            rss_mdm_execution_service::self_service::directory::Input::schema()
                .max_limit
                .into();
        schema.value["properties"]["limit"]["default"] =
            rss_mdm_execution_service::self_service::directory::Input::schema()
                .default_limit
                .into();
        schema
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        Ok(raw.to_owned())
    }
}
