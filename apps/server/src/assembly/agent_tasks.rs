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
#[derive(Clone)]
pub(crate) struct AgentTasks {
    pub access: Arc<rss_mdm_registration_service::device_access::execution::Service>,
    pub credentials: Option<Arc<rss_mdm_recovery_credentials::tasks::Service>>,
    pub software: Arc<rss_mdm_software_service::deployment::SoftwareService>,
    pub registration: Arc<rss_mdm_registration_service::enrollment::tasks::Service>,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,

    pub requests: Arc<super::self_service::Requests>,
    pub execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub scripts: Arc<rss_mdm_script_service::ScriptService>,
    pub collections: Arc<rss_mdm_inventory_service::collection::execution::CollectionService>,
}
pub(super) fn error(e: rss_mdm_execution_service::Error) -> rss_mdm_agent_channel::Error {
    use rss_mdm_agent_channel::Missing;
    use rss_mdm_agent_channel::{Error as A, Failure};
    use rss_mdm_execution_service::Error as E;
    match e {
        E::Malformed => A::Malformed,
        E::CertificateRequest => A::CertificateRequest,
        E::Unauthorized => A::Unauthorized,
        E::Forbidden => A::Forbidden,
        E::ReadConflict
        | E::CursorInvalidated
        | E::Conflict
        | E::EnrollmentPaused
        | E::WindowsDeclaredEnrollmentNotReady => A::Conflict,
        E::CommitUnknown => A::CommitUnknown,
        E::RollbackFailed => A::RollbackFailed,
        E::Unsupported => A::Unsupported,
        E::NotFound => A::NotFound,
        E::Resource(_) => A::Missing(Missing::Resource),
        E::Execution(e) => A::Missing(match e {
            rss_mdm_execution_service::missing::ExecutionError::MissingOperation => {
                Missing::Operation
            }
            rss_mdm_execution_service::missing::ExecutionError::MissingTask => Missing::Task,
        }),

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
pub(super) fn fault(
    e: rss_mdm_execution_service::transaction::Fault,
) -> rss_mdm_agent_channel::Error {
    use rss_mdm_execution_service::transaction::Fault;
    match e {
        Fault::Request(e) => error(e),
        Fault::Storage(e) => e.into(),
        Fault::Sql(e) => e.into(),
    }
}
use super::task_ownership::Owner;
pub(crate) async fn owner_in(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Owner, rss_mdm_agent_channel::Error> {
    let tenant = tx.tenant_id();
    Ok(tx
        .with_connection(move |c| Box::pin(super::task_ownership::on(c, tenant, id)))
        .await?)
}
pub(super) fn script_error(e: rss_mdm_script_service::Error) -> rss_mdm_agent_channel::Error {
    use rss_mdm_agent_channel::{Error as A, Failure};
    use rss_mdm_script_service::Error as S;
    match e {
        S::Malformed => A::Malformed,
        S::Conflict => A::Conflict,
        S::Forbidden => A::Forbidden,
        S::Unauthorized => A::Unauthorized,
        S::NotFound => A::NotFound,
        S::CommitUnknown => A::CommitUnknown,
        S::RollbackFailed => A::RollbackFailed,
        S::Invariant | S::Unavailable => A::Unavailable(Failure::Business),
        S::Audit(e) => e.as_ref().into(),
        S::Inventory(e) => e.into(),
        S::Content(e) => e.into(),
    }
}
pub(super) fn script_fault(
    e: rss_mdm_script_service::transaction::Fault,
) -> rss_mdm_agent_channel::Error {
    use rss_mdm_script_service::transaction::Fault as F;
    match e {
        F::Request(e) => script_error(e),
        F::Storage(e) => e.into(),
        F::Sql(e) => e.into(),
    }
}
pub(super) fn collection_fault(
    e: rss_mdm_inventory_service::transaction::Fault,
) -> rss_mdm_agent_channel::Error {
    use rss_mdm_inventory_service::transaction::Fault as F;
    match e {
        F::Request(e) => e.into(),
        F::Storage(e) => e.into(),
        F::Sql(e) => e.into(),
    }
}
impl Tasks for AgentTasks {
    fn prepare<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, ()> {
        Box::pin(async move { prepare(tx, p).await })
    }
    fn offer<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        input: &'a wire::TaskClaimRequest,
        attempt: Uuid,
        audit: &'a RequestAudit,
    ) -> Pending<'a, Option<(wire::TaskPayload, rss_mdm_audit_integration::Fact, i64)>> {
        Box::pin(async move {
            let now = rss_mdm_script_service::storage::now(tx)
                .await
                .map_err(script_fault)?;
            let after =
                rss_mdm_agent_channel::delivery::offer_after_in(tx, p.registration()).await?;
            let mut candidates: Vec<_> =
                rss_mdm_execution_service::actions::poll::offer_candidates(
                    tx,
                    p.registration(),
                    now,
                    after,
                )
                .await
                .map_err(fault)?
                .into_iter()
                .map(|v| (v, Owner::Execution))
                .collect();
            candidates.extend(
                rss_mdm_script_service::poll::offer_candidates(tx, p.registration(), now, after)
                    .await
                    .map_err(script_fault)?
                    .into_iter()
                    .map(|v| (v, Owner::Script)),
            );
            candidates.extend(
                rss_mdm_inventory_service::collection::execution::poll::offer_candidates(
                    tx,
                    p.registration(),
                    now,
                    after,
                )
                .await
                .map_err(collection_fault)?
                .into_iter()
                .map(|v| (v, Owner::Collection)),
            );
            candidates.extend(
                rss_mdm_software_service::deployment::actions::poll::offer_candidates(
                    tx,
                    p.registration(),
                    now,
                    after,
                )
                .await
                .map_err(software_fault)?
                .into_iter()
                .map(|v| (v, Owner::Software)),
            );
            candidates.extend(
                rss_mdm_registration_service::enrollment::tasks::poll::offer_candidates(
                    tx,
                    p.registration(),
                    now,
                    after,
                )
                .await
                .map_err(registration_fault)?
                .into_iter()
                .map(|v| (v, Owner::Registration)),
            );
            candidates.extend(
                rss_mdm_registration_service::device_access::execution::poll::offer_candidates(
                    tx,
                    p.registration(),
                    now,
                    after,
                )
                .await
                .map_err(access_fault)?
                .into_iter()
                .map(|v| (v, Owner::Access)),
            );
            candidates.extend(
                rss_mdm_recovery_credentials::tasks::actions::poll::offer_candidates(
                    tx,
                    p.registration(),
                    now,
                    after,
                )
                .await
                .map_err(credential_fault)?
                .into_iter()
                .map(|v| (v, Owner::Credential)),
            );
            candidates.sort_by_key(|(coordinate, _)| *coordinate);
            if candidates.windows(2).any(|v| v[0].0.1 == v[1].0.1) {
                return Err(rss_mdm_agent_channel::Error::Conflict);
            }
            candidates.truncate(128);
            // Capture the globally bounded page before admission/relay can expose additional work.
            let tenant = tx.tenant_id().to_string();
            let registration = p.registration();
            let binding = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(rss_mdm_agent_channel::Bindings
                            .binding(c, tenant, registration)
                            .await)
                    })
                })
                .await
                .map_err(|_| {
                    rss_mdm_agent_channel::Error::Unavailable(
                        rss_mdm_agent_channel::Failure::Business,
                    )
                })??
                .ok_or(rss_mdm_agent_channel::Error::Unauthorized)?;
            if binding
                .capabilities
                .contains(&wire::Capability::DeviceAccessV1)
            {
                self.access
                    .agent_admit_in(tx, p, input, audit)
                    .await
                    .map_err(access_fault)?;
            }
            if binding
                .capabilities
                .contains(&wire::Capability::CredentialsWindowsV1)
                && let Some(credentials) = &self.credentials
            {
                credentials
                    .agent_admit_in(tx, p, input, audit)
                    .await
                    .map_err(credential_fault)?;
            }
            if binding.script() {
                self.scripts
                    .agent_admit_in(tx, p, input)
                    .await
                    .map_err(script_fault)?;
            }
            if binding.inventory() {
                self.collections
                    .agent_admit_in(tx, p, input)
                    .await
                    .map_err(collection_fault)?;
            }
            if binding.software() {
                self.software
                    .agent_admit_in(tx, p, input, audit)
                    .await
                    .map_err(software_fault)?;
            }
            if binding.enrollment() {
                self.registration
                    .agent_admit_in(tx, p, input)
                    .await
                    .map_err(registration_fault)?;
            }
            let mut inspected = None;
            let mut offer = None;
            for (coordinate, owner) in candidates {
                if owner_in(tx, coordinate.1).await? != owner {
                    return Err(rss_mdm_agent_channel::Error::Conflict);
                }
                offer = match owner {
                    Owner::Access => self
                        .access
                        .agent_offer_one_in(tx, p, input, coordinate.1, attempt, audit)
                        .await
                        .map_err(access_fault)?,
                    Owner::Credential => self
                        .credentials
                        .as_ref()
                        .ok_or(rss_mdm_agent_channel::Error::Unsupported)?
                        .agent_offer_one_in(tx, p, input, coordinate.1, attempt, audit)
                        .await
                        .map_err(credential_fault)?,
                    Owner::Execution => self
                        .execution
                        .agent_offer_one_in(tx, p, input, coordinate.1, attempt, audit)
                        .await
                        .map_err(fault)?,
                    Owner::Software => self
                        .software
                        .agent_offer_one_in(tx, p, input, coordinate.1, attempt, audit)
                        .await
                        .map_err(software_fault)?,
                    Owner::Script => self
                        .scripts
                        .agent_offer_one_in(tx, p, coordinate.1, attempt, audit)
                        .await
                        .map_err(script_fault)?,
                    Owner::Registration => self
                        .registration
                        .agent_offer_one_in(tx, p, coordinate.1, attempt, audit)
                        .await
                        .map_err(registration_fault)?,
                    Owner::Collection => self
                        .collections
                        .agent_offer_one_in(tx, p, coordinate.1, attempt, audit)
                        .await
                        .map_err(collection_fault)?,
                };
                inspected = Some(coordinate);
                if offer.is_some() {
                    break;
                }
            }
            rss_mdm_agent_channel::delivery::offer_through_in(tx, p.registration(), inspected)
                .await?;
            Ok(offer)
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
            match owner_in(tx, signed.payload.task_id()).await? {
                Owner::Access => self
                    .access
                    .agent_replay_offer_in(tx, p, signed, audit)
                    .await
                    .map_err(access_fault),
                Owner::Credential => self
                    .credentials
                    .as_ref()
                    .ok_or(rss_mdm_agent_channel::Error::Unsupported)?
                    .agent_replay_offer_in(tx, p, signed, audit)
                    .await
                    .map_err(credential_fault),
                Owner::Execution => self
                    .execution
                    .agent_replay_offer_in(tx, p, signed, audit)
                    .await
                    .map_err(fault),
                Owner::Software => self
                    .software
                    .agent_replay_offer_in(tx, p, signed, audit)
                    .await
                    .map_err(software_fault),
                Owner::Script => self
                    .scripts
                    .agent_replay_offer_in(tx, p, signed, audit)
                    .await
                    .map_err(script_fault),
                Owner::Registration => self
                    .registration
                    .agent_replay_offer_in(tx, p, signed, audit)
                    .await
                    .map_err(registration_fault),
                Owner::Collection => self
                    .collections
                    .agent_replay_offer_in(tx, p, signed, audit)
                    .await
                    .map_err(collection_fault),
            }
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
            match owner_in(tx, task).await? {
                Owner::Access => self
                    .access
                    .agent_replay_event_in(tx, p, task, input, audit)
                    .await
                    .map_err(access_fault),
                Owner::Credential => self
                    .credentials
                    .as_ref()
                    .ok_or(rss_mdm_agent_channel::Error::Unsupported)?
                    .agent_replay_event_in(tx, p, task, input, audit)
                    .await
                    .map_err(credential_fault),
                Owner::Execution => self
                    .execution
                    .agent_replay_event_in(tx, p, task, input, audit)
                    .await
                    .map_err(fault),
                Owner::Software => self
                    .software
                    .agent_replay_event_in(tx, p, task, input, audit)
                    .await
                    .map_err(software_fault),
                Owner::Script => self
                    .scripts
                    .agent_replay_event_in(tx, p, task, input, audit)
                    .await
                    .map_err(script_fault),
                Owner::Registration => self
                    .registration
                    .agent_replay_event_in(tx, p, task, input, audit)
                    .await
                    .map_err(registration_fault),
                Owner::Collection => self
                    .collections
                    .agent_replay_event_in(tx, p, task, input, audit)
                    .await
                    .map_err(collection_fault),
            }
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
            Ok(match owner_in(tx, task).await? {
                Owner::Access => {
                    let e = self
                        .access
                        .agent_event_in(tx, p, task, input, audit)
                        .await
                        .map_err(access_fault)?;
                    EventEffects {
                        start: e.start,
                        cancelled: e.cancelled,
                        credentials: e.credentials,
                        fact: e.fact,
                    }
                }
                Owner::Credential => {
                    let e = self
                        .credentials
                        .as_ref()
                        .ok_or(rss_mdm_agent_channel::Error::Unsupported)?
                        .agent_event_in(tx, p, task, input, audit)
                        .await
                        .map_err(credential_fault)?;
                    EventEffects {
                        start: e.start,
                        cancelled: e.cancelled,
                        credentials: e.credentials,
                        fact: e.fact,
                    }
                }
                Owner::Execution => {
                    let e = self
                        .execution
                        .agent_event_in(tx, p, task, input, audit)
                        .await
                        .map_err(fault)?;
                    EventEffects {
                        start: e.start,
                        cancelled: e.cancelled,
                        credentials: e.credentials,
                        fact: e.fact,
                    }
                }
                Owner::Software => {
                    let e = self
                        .software
                        .agent_event_in(tx, p, task, input, audit)
                        .await
                        .map_err(software_fault)?;
                    EventEffects {
                        start: e.start,
                        cancelled: e.cancelled,
                        credentials: vec![],
                        fact: e.fact,
                    }
                }
                Owner::Script => {
                    let e = self
                        .scripts
                        .agent_event_in(tx, p, task, input, audit)
                        .await
                        .map_err(script_fault)?;
                    EventEffects {
                        start: e.start,
                        cancelled: e.cancelled,
                        credentials: vec![],
                        fact: e.fact,
                    }
                }
                Owner::Registration => {
                    let e = self
                        .registration
                        .agent_event_in(tx, p, task, input, audit)
                        .await
                        .map_err(registration_fault)?;
                    EventEffects {
                        start: e.start,
                        cancelled: e.cancelled,
                        credentials: vec![],
                        fact: e.fact,
                    }
                }
                Owner::Collection => {
                    let e = self
                        .collections
                        .agent_event_in(tx, p, task, input, audit)
                        .await
                        .map_err(collection_fault)?;
                    EventEffects {
                        start: e.start,
                        cancelled: e.cancelled,
                        credentials: vec![],
                        fact: e.fact,
                    }
                }
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
            let mut page =
                rss_mdm_execution_service::actions::poll::cancellations(tx, registration, after)
                    .await
                    .map_err(fault)?;
            page.extend(
                rss_mdm_script_service::poll::cancellations(tx, registration, after)
                    .await
                    .map_err(script_fault)?,
            );
            page.extend(
                rss_mdm_inventory_service::collection::execution::poll::cancellations(
                    tx,
                    registration,
                    after,
                )
                .await
                .map_err(collection_fault)?,
            );
            page.extend(
                rss_mdm_software_service::deployment::actions::poll::cancellations(
                    tx,
                    registration,
                    after,
                )
                .await
                .map_err(software_fault)?,
            );
            page.extend(
                rss_mdm_registration_service::enrollment::tasks::poll::cancellations(
                    tx,
                    registration,
                    after,
                )
                .await
                .map_err(registration_fault)?,
            );
            page.extend(
                rss_mdm_registration_service::device_access::execution::poll::cancellations(
                    tx,
                    registration,
                    after,
                )
                .await
                .map_err(access_fault)?,
            );
            page.extend(
                rss_mdm_recovery_credentials::tasks::actions::poll::cancellations(
                    tx,
                    registration,
                    after,
                )
                .await
                .map_err(credential_fault)?,
            );
            page.sort_by_key(|v| v.task_id());
            if page.windows(2).any(|v| v[0].task_id() == v[1].task_id()) {
                return Err(rss_mdm_agent_channel::Error::Conflict);
            }
            page.truncate(wire::MAX_TASK_CANCELLATIONS);
            Ok(page)
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
            match owner_in(tx, task).await? {
                Owner::Access => Err(rss_mdm_agent_channel::Error::Forbidden),
                Owner::Credential => Err(rss_mdm_agent_channel::Error::Forbidden),
                Owner::Execution => Err(rss_mdm_agent_channel::Error::Forbidden),
                Owner::Software => self
                    .software
                    .agent_content_in(tx, p, task, attempt, key, audit)
                    .await
                    .map_err(software_fault),
                Owner::Script => self
                    .scripts
                    .agent_content_in(tx, p, task, attempt, key, audit)
                    .await
                    .map_err(script_fault),
                Owner::Registration => Err(rss_mdm_agent_channel::Error::Malformed),
                Owner::Collection => Err(rss_mdm_agent_channel::Error::Malformed),
            }
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
        Box::pin(async move { self.resolve_self_service(p, proof, input, audit).await })
    }
    fn directory<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        proof: Option<&'a AuthorizedPrincipal>,
        query: &'a str,
        audit: &'a RequestAudit,
    ) -> Pending<'a, wire::SelfServiceDirectoryResponse> {
        Box::pin(async move {
            self.self_service_directory(p, proof, &super::self_service::Input::new(query), audit)
                .await
        })
    }
    fn invoke<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        proof: Option<&'a AuthorizedPrincipal>,
        input: &'a wire::SelfServiceInvoke,
        audit: &'a RequestAudit,
    ) -> Pending<'a, wire::SelfServiceAccepted> {
        Box::pin(async move { self.invoke_self_service(p, proof, input, audit).await })
    }
    fn status<'a>(
        &'a self,
        p: &'a DevicePrincipal,
        proof: Option<&'a AuthorizedPrincipal>,
        id: Uuid,
        audit: &'a RequestAudit,
    ) -> Pending<'a, wire::SelfServiceStatus> {
        Box::pin(async move { self.self_service_status(p, proof, id, audit).await })
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
            self.registration
                .native_enrollment(p, task, input, audit)
                .await
                .map_err(registration_error)
        })
    }
    fn content<'a>(
        &'a self,
        id: Uuid,
        audit: &'a RequestAudit,
    ) -> Pending<'a, rss_mdm_content_service::Verified> {
        Box::pin(async move {
            let store = self
                .content
                .as_ref()
                .ok_or(rss_mdm_agent_channel::Error::Unsupported)?;
            let artifact = self
                .software
                .installation_artifact(id, audit)
                .await
                .map_err(software_error)?;
            let verified = store.verify(&artifact).await?;
            self.software
                .revalidate_installation_download(id, &artifact, audit)
                .await
                .map_err(software_error)?;
            Ok(verified)
        })
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
            self.credentials
                .as_ref()
                .ok_or(rss_mdm_agent_channel::Error::Unsupported)?
                .record_access_recovery_use(p, input, audit)
                .await
                .map_err(credential_error)
        })
    }
}

pub(super) struct SelfServiceQuery;
impl rss_mdm_http_contract::query::QueryOwner for SelfServiceQuery {
    type Parsed = String;
    type Error = std::convert::Infallible;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Directory(
            super::self_service::Input::schema(),
        ))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let mut schema =
            rss_mdm_http_contract::signature::Schema::request::<wire::SelfServiceDirectory>();
        schema.value["properties"]["limit"]["minimum"] = 1.into();
        schema.value["properties"]["limit"]["maximum"] =
            super::self_service::Input::schema().max_limit.into();
        schema.value["properties"]["limit"]["default"] =
            super::self_service::Input::schema().default_limit.into();
        schema
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        Ok(raw.to_owned())
    }
}

pub(super) fn software_error(
    e: rss_mdm_software_service::deployment::Error,
) -> rss_mdm_agent_channel::Error {
    use rss_mdm_agent_channel::Missing;
    use rss_mdm_agent_channel::{Error as A, Failure};
    use rss_mdm_software_service::deployment::Error as E;
    match e { E::MdmSoftwareDisabled => A::Forbidden, E::Malformed => A::Malformed, E::CertificateRequest => A::CertificateRequest,
            E::Unauthorized => A::Unauthorized, E::Forbidden => A::Forbidden, E::ReadConflict | E::CursorInvalidated | E::Conflict | E::EnrollmentPaused | E::WindowsDeclaredEnrollmentNotReady => A::Conflict,
            E::CommitUnknown => A::CommitUnknown, E::RollbackFailed => A::RollbackFailed, E::Unsupported => A::Unsupported,
            E::NotFound => A::NotFound, E::Resource(_) => A::Missing(Missing::Resource),
            E::Execution(e) => A::Missing(match e { rss_mdm_software_service::deployment::missing::ExecutionError::MissingOperation => Missing::Operation, rss_mdm_software_service::deployment::missing::ExecutionError::MissingTask => Missing::Task }),
            E::Publication(e) => A::Missing(match e { rss_mdm_software_service::management::publication::error::PublicationError::MissingSource => Missing::SoftwareSource, rss_mdm_software_service::management::publication::error::PublicationError::MissingPublication => Missing::SoftwarePublication }),
            E::Configuration(_) => A::Unavailable(Failure::BusinessConfiguration),
            E::Unavailable(f) => A::Unavailable(match f {
                rss_mdm_software_service::deployment::Failure::RequestDeadline => Failure::RequestDeadline,
                rss_mdm_software_service::deployment::Failure::Audit => Failure::Audit,
                rss_mdm_software_service::deployment::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_software_service::deployment::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_software_service::deployment::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_software_service::deployment::Failure::AuditContract => Failure::AuditContract,

                _ => Failure::Business,
            }),
        }
}
pub(super) fn software_fault(
    e: rss_mdm_software_service::deployment::transaction::Fault,
) -> rss_mdm_agent_channel::Error {
    use rss_mdm_software_service::deployment::transaction::Fault;
    match e {
        Fault::Request(e) => software_error(e),
        Fault::Storage(e) => e.into(),
        Fault::Sql(e) => e.into(),
    }
}

pub(super) fn registration_error(
    e: rss_mdm_registration_service::enrollment::tasks::Error,
) -> rss_mdm_agent_channel::Error {
    use rss_mdm_agent_channel::{Error as A, Failure};
    use rss_mdm_registration_service::enrollment::tasks::Error as S;
    match e {
        S::Malformed => A::Malformed,
        S::Conflict => A::Conflict,
        S::Forbidden => A::Forbidden,
        S::Unauthorized => A::Unauthorized,
        S::NotFound => A::NotFound,
        S::CommitUnknown => A::CommitUnknown,
        S::RollbackFailed => A::RollbackFailed,
        S::Invariant | S::Unavailable => A::Unavailable(Failure::Business),
        S::Audit(e) => e.as_ref().into(),
    }
}
pub(super) fn registration_fault(
    e: rss_mdm_registration_service::enrollment::tasks::transaction::Fault,
) -> rss_mdm_agent_channel::Error {
    use rss_mdm_registration_service::enrollment::tasks::transaction::Fault as F;
    match e {
        F::Request(e) => registration_error(e),
        F::Storage(e) => e.into(),
        F::Sql(e) => e.into(),
    }
}

pub(super) async fn prepare(
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
) -> Result<(), rss_mdm_agent_channel::Error> {
    if tx.tenant_id() != p.tenant() {
        return Err(rss_mdm_agent_channel::Error::Unauthorized);
    }
    let p = p.clone();
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(async {
                rss_mdm_registration_service::device::store::lock_channel(
                    c,
                    &tenant,
                    p.device(),
                    rss_mdm_inventory::Channel::Mdm,
                )
                .await?;
                rss_mdm_registration_service::device::store::revalidate_source(
                    c,
                    &p,
                    rss_mdm_inventory::ReportSource::AgentBuiltin,
                )
                .await?;
                let binding = rss_mdm_agent_channel::Bindings
                    .binding(c, tenant, p.registration())
                    .await?
                    .ok_or(rss_mdm_agent_channel::Error::Unauthorized)?;
                if !binding.inventory() || !binding.task() {
                    return Err(rss_mdm_agent_channel::Error::Forbidden);
                }
                Ok(())
            }
            .await)
        })
    })
    .await
    .map_err(|_| {
        rss_mdm_agent_channel::Error::Unavailable(rss_mdm_agent_channel::Failure::Business)
    })?
}

pub(super) fn access_error(
    e: rss_mdm_registration_service::device_access::execution::Error,
) -> rss_mdm_agent_channel::Error {
    use rss_mdm_agent_channel::{Error as A, Failure};
    use rss_mdm_registration_service::device_access::execution::Error as S;
    match e {
        S::Unsupported => A::Unsupported,
        S::Malformed => A::Malformed,
        S::Conflict => A::Conflict,
        S::Forbidden => A::Forbidden,
        S::Unauthorized => A::Unauthorized,
        S::NotFound => A::NotFound,
        S::CommitUnknown => A::CommitUnknown,
        S::RollbackFailed => A::RollbackFailed,
        S::Invariant | S::Unavailable => A::Unavailable(Failure::Business),
        S::Audit(e) => e.as_ref().into(),
    }
}
pub(super) fn access_fault(
    e: rss_mdm_registration_service::device_access::execution::transaction::Fault,
) -> rss_mdm_agent_channel::Error {
    use rss_mdm_registration_service::device_access::execution::transaction::Fault as F;
    match e {
        F::Request(e) => access_error(e),
        F::Storage(e) => e.into(),
        F::Sql(e) => e.into(),
    }
}

pub(super) fn credential_error(
    e: rss_mdm_recovery_credentials::tasks::Error,
) -> rss_mdm_agent_channel::Error {
    use rss_mdm_agent_channel::{Error as A, Failure};
    use rss_mdm_recovery_credentials::tasks::Error as S;
    match e {
        S::Unsupported => A::Unsupported,
        S::Malformed => A::Malformed,
        S::Conflict => A::Conflict,
        S::Forbidden => A::Forbidden,
        S::Unauthorized => A::Unauthorized,
        S::NotFound => A::NotFound,
        S::CommitUnknown => A::CommitUnknown,
        S::RollbackFailed => A::RollbackFailed,
        S::Invariant | S::Unavailable => A::Unavailable(Failure::Business),
        S::Audit(e) => e.as_ref().into(),
    }
}
pub(super) fn credential_fault(
    e: rss_mdm_recovery_credentials::tasks::transaction::Fault,
) -> rss_mdm_agent_channel::Error {
    use rss_mdm_recovery_credentials::tasks::transaction::Fault as F;
    match e {
        F::Request(e) => credential_error(e),
        F::Storage(e) => e.into(),
        F::Sql(e) => e.into(),
    }
}
