//! Static Windows business capability mappings.
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_registration_service::DevicePrincipal;
use rss_mdm_windows_channel::participants::*;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::PgConnection;
use std::sync::Arc;
use uuid::Uuid;
pub(crate) struct WindowsBusiness(pub Arc<rss_mdm_execution_service::ExecutionService>);
fn error(e: rss_mdm_execution_service::Error) -> rss_mdm_windows_channel::Error {
    use rss_mdm_execution_service::Error as E;
    use rss_mdm_windows_channel::Missing;
    use rss_mdm_windows_channel::{Error as A, Failure};
    match e { E::MdmSoftwareDisabled => A::Forbidden, E::Malformed => A::Malformed, E::CertificateRequest => A::CertificateRequest,
            E::Unauthorized => A::Unauthorized, E::Forbidden => A::Forbidden, E::ReadConflict | E::CursorInvalidated | E::Conflict | E::WindowsDeclaredEnrollmentNotReady => A::Conflict,
            E::EnrollmentPaused=> A::EnrollmentPaused, E::CommitUnknown => A::CommitUnknown, E::RollbackFailed => A::RollbackFailed, E::Unsupported => A::Unsupported,
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
fn fault(e: rss_mdm_execution_service::transaction::Fault) -> rss_mdm_windows_channel::Error {
    use rss_mdm_execution_service::transaction::Fault;
    match e {
        Fault::Request(e) => error(e),
        _ => {
            rss_mdm_windows_channel::Error::Unavailable(rss_mdm_windows_channel::Failure::Database)
        }
    }
}
fn operation(v: rss_mdm_execution_service::windows_business::WindowsOperation) -> Operation {
    Operation {
        id: v.id,
        request: v.request,
        user: v.user,
        matches: v.matches,
        dispatch: v.dispatch,
        receipt: v.receipt,
        observe: v.observe,
        replay: v.replay,
        software: v.software,
        agent_minimum_os: v.agent_minimum_os,
        minimum_os: v.minimum_os,
        observation: v.observation,
    }
}
impl Business for WindowsBusiness {
    fn software_enabled(&self) -> bool {
        self.0.native_software_enabled()
    }
    fn detection<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
    ) -> Pending<'a, DetectionCatalog> {
        Box::pin(async move {
            let catalog = rss_mdm_execution_service::agent_install::detection_on(
                c,
                tenant,
                rss_mdm_inventory::ReportSource::MdmWindows,
            )
            .await
            .map_err(error)?;
            let digest = catalog.digest().map_err(error)?;
            let identities = catalog
                .identities
                .into_iter()
                .map(|i| {
                    Ok(match i {
                        rss_mdm_execution_service::agent_install::Identity::WindowsMsi {
                            product,
                            publisher,
                        } => Identity::WindowsMsi { product, publisher },
                        rss_mdm_execution_service::agent_install::Identity::WindowsMsix {
                            family,
                            identity,
                            minimum_os,
                        } => Identity::WindowsMsix {
                            family,
                            identity,
                            minimum_os,
                        },
                        _ => return Err(rss_mdm_windows_channel::Error::Conflict),
                    })
                })
                .collect::<Result<Vec<_>, rss_mdm_windows_channel::Error>>()?;
            Ok(DetectionCatalog {
                identities,
                win32: catalog
                    .win32
                    .into_iter()
                    .map(|i| Win32Identity {
                        key: i.key,
                        publisher: i.publisher,
                    })
                    .collect(),
                complete: catalog.complete,
                digest,
            })
        })
    }

    fn prepare<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()> {
        Box::pin(async move { self.0.windows_prepare_in(tx, p, audit).await.map_err(fault) })
    }
    fn finish<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        session: u32,
        complete: bool,
        authenticated: bool,
        retirement: rss_mdm_windows_mdm::native::Request,
        runs: Vec<Uuid>,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.0
                .windows_finish_in(
                    tx,
                    p,
                    session,
                    complete,
                    authenticated,
                    retirement,
                    runs,
                    audit,
                )
                .await
                .map_err(fault)
        })
    }
    fn candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, Vec<Operation>> {
        Box::pin(async move {
            Ok(self
                .0
                .windows_candidates_on(c, p)
                .await
                .map_err(error)?
                .into_iter()
                .map(operation)
                .collect())
        })
    }
    fn operation<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        id: Uuid,
    ) -> Pending<'a, Operation> {
        Box::pin(async move {
            self.0
                .windows_operation_on(c, p, id)
                .await
                .map(operation)
                .map_err(error)
        })
    }
    fn rejected<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        id: Uuid,
        reason: String,
        phase: Option<AttemptPhase>,
        context: Option<rss_mdm_windows_mdm::native::Context>,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.0
                .windows_dispatch_failure_on(
                    c,
                    p,
                    id,
                    reason,
                    phase.map(|p| match p {
                        AttemptPhase::Prepare => rss_mdm_execution_service::AttemptPhase::Prepare,
                        AttemptPhase::Execute => rss_mdm_execution_service::AttemptPhase::Execute,
                        AttemptPhase::Observe => rss_mdm_execution_service::AttemptPhase::Observe,
                    }),
                    context,
                )
                .await
                .map_err(error)
        })
    }
    fn wake_configuration<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_execution_service::windows_business::wake_configuration(c, p)
                .await
                .map_err(error)
        })
    }
    fn collection_eligible<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        id: Uuid,
        delivery: bool,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            self.0
                .windows_collection_eligible_on(c, p, id, delivery)
                .await
                .map_err(error)
        })
    }
    fn collection_plan<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        id: Uuid,
    ) -> Pending<'a, rss_mdm_windows_mdm::native::collection::Plan> {
        Box::pin(async move {
            rss_mdm_execution_service::actions::native_collection::plan_on(c, tenant, id)
                .await
                .map_err(error)
        })
    }
    fn collection_sent<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        id: Uuid,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_execution_service::actions::native_collection::sent(c, tenant, id)
                .await
                .map_err(error)
        })
    }
}

impl Departure for WindowsBusiness {
    fn departed<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        registration: Uuid,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_execution_service::unmanage::native_departure_in(c, tenant, registration, false)
                .await
                .map_err(error)
        })
    }
}
impl WakeDemand for WindowsBusiness {
    fn candidates<'a>(&'a self, c: &'a mut PgConnection, after: Uuid) -> Pending<'a, Vec<Uuid>> {
        Box::pin(async move {
            self.0
                .windows_wake_candidates_in(c, after)
                .await
                .map_err(error)
        })
    }
    fn pending<'a>(
        &'a self,
        c: &'a mut PgConnection,
        device: &'a str,
        registration: Uuid,
        generation: i64,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            self.0
                .windows_wake_pending_in(c, device, registration, generation)
                .await
                .map_err(error)
        })
    }
}
