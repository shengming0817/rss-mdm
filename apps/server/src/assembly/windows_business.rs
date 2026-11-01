//! Static Windows business capability mappings.
use super::native_ownership::{self, Owner};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_registration_service::DevicePrincipal;
use rss_mdm_windows_channel::participants::*;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::PgConnection;
use std::sync::Arc;
use uuid::Uuid;
pub(crate) struct WindowsBusiness(
    pub Arc<rss_mdm_execution_service::ExecutionService>,
    pub Arc<rss_mdm_policy_service::configuration::Transactions>,
    pub Arc<rss_mdm_inventory_service::collection::execution::CollectionService>,
    pub Arc<rss_mdm_software_service::deployment::SoftwareService>,
    pub Arc<rss_mdm_registration_service::installation::Service>,
);
fn error(e: rss_mdm_execution_service::Error) -> rss_mdm_windows_channel::Error {
    use rss_mdm_execution_service::Error as E;
    use rss_mdm_windows_channel::Missing;
    use rss_mdm_windows_channel::{Error as A, Failure};
    match e {
        E::Malformed => A::Malformed,
        E::CertificateRequest => A::CertificateRequest,
        E::Unauthorized => A::Unauthorized,
        E::Forbidden => A::Forbidden,
        E::ReadConflict
        | E::CursorInvalidated
        | E::Conflict
        | E::WindowsDeclaredEnrollmentNotReady => A::Conflict,
        E::EnrollmentPaused => A::EnrollmentPaused,
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
fn fault(e: rss_mdm_execution_service::transaction::Fault) -> rss_mdm_windows_channel::Error {
    use rss_mdm_execution_service::transaction::Fault;
    match e {
        Fault::Request(e) => error(e),
        Fault::Storage(e) => e.into(),
        Fault::Sql(e) => e.into(),
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
        software: false,
        agent_minimum_os: None,
        minimum_os: None,
        observation: v.observation,
    }
}
impl Business for WindowsBusiness {
    fn software_enabled(&self) -> bool {
        self.3.native_software_enabled()
    }
    fn detection<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
    ) -> Pending<'a, DetectionCatalog> {
        Box::pin(async move {
            let catalog = rss_mdm_software_service::deployment::agent_install::detection_on(
                c,
                tenant,
                rss_mdm_inventory::ReportSource::MdmWindows,
            )
            .await
            .map_err(software_error)?;
            let digest = catalog.digest().map_err(software_error)?;
            let identities = catalog
                .identities
                .into_iter()
                .map(|i| {
                    Ok(match i {
                        rss_mdm_software_service::installation::package::Identity::WindowsMsi {
                            product,
                            publisher,
                        } => Identity::WindowsMsi { product, publisher },
                        rss_mdm_software_service::installation::package::Identity::WindowsMsix {
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
            if authenticated {
                self.2
                    .authenticated_in(tx, p)
                    .await
                    .map_err(collection_fault)?;
            }
            self.0
                .windows_before_receipts_in(tx, p, authenticated, retirement, audit)
                .await
                .map_err(fault)?;
            rss_mdm_policy_service::configuration::protocol::settle_dispatch_failures(
                &self.1, tx, p, audit,
            )
            .await
            .map_err(policy_fault)?;
            self.3
                .windows_before_receipts_in(tx, p, audit)
                .await
                .map_err(software_fault)?;
            self.4
                .windows_before_receipts_in(tx, p, audit)
                .await
                .map_err(registration_fault)?;
            let mut after = None;
            loop {
                let ids = self
                    .0
                    .windows_received_in(tx, p, session, after)
                    .await
                    .map_err(fault)?;
                let Some(last) = ids.last().copied() else {
                    break;
                };
                let mut owners = Vec::with_capacity(ids.len());
                for id in ids {
                    owners.push((
                        id,
                        native_ownership::in_transaction(tx, id)
                            .await
                            .map_err(policy_fault)?,
                    ));
                }
                for (id, owner) in owners {
                    match owner {
                        Owner::Configuration => {
                            rss_mdm_policy_service::configuration::protocol::settle_windows_in(
                                &self.1, tx, id, complete, audit,
                            )
                            .await
                            .map_err(policy_fault)?
                        }
                        Owner::Execution => rss_mdm_execution_service::settle_windows_receipt_in(
                            &self.0, tx, id, complete, audit,
                        )
                        .await
                        .map_err(fault)?,
                        Owner::Software => {
                            rss_mdm_software_service::deployment::settle_windows_receipt_in(
                                &self.3, tx, id, complete, audit,
                            )
                            .await
                            .map_err(software_fault)?
                        }
                        Owner::Recovery => return Err(rss_mdm_windows_channel::Error::Forbidden),
                        Owner::Registration => {
                            rss_mdm_registration_service::installation::settle_windows_receipt_in(
                                &self.4, tx, id, complete, audit,
                            )
                            .await
                            .map_err(registration_fault)?
                        }
                    }
                }
                after = Some(last);
            }
            self.2
                .finished_in(tx, p, &runs)
                .await
                .map_err(collection_fault)?;
            self.3
                .windows_after_receipts_in(tx, p, audit)
                .await
                .map_err(software_fault)?;
            Ok(())
        })
    }
    fn candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, Vec<Operation>> {
        Box::pin(async move {
            let mut candidates = self
                .0
                .windows_candidates_on(c, p)
                .await
                .map_err(error)?
                .into_iter()
                .map(|v| (true, v.id, operation(v)))
                .collect::<Vec<_>>();
            candidates.extend(
                self.1
                    .windows_candidates_on(c, p)
                    .await
                    .map_err(policy_error)?
                    .into_iter()
                    .map(|v| (true, v.id, configuration_operation(v))),
            );
            candidates.extend(
                self.3
                    .windows_candidates_on(c, p)
                    .await
                    .map_err(software_error)?
                    .into_iter()
                    .map(|v| (true, v.id, software_operation(v))),
            );
            candidates.extend(
                self.4
                    .windows_candidates_on(c, p)
                    .await
                    .map_err(registration_error)?
                    .into_iter()
                    .map(|v| (!v.bootstrap, v.id, registration_operation(v))),
            );
            candidates.sort_by_key(|v| (v.0, v.1));
            candidates.truncate(64);
            for (_, id, _) in &candidates {
                native_ownership::on(c, p.tenant(), *id)
                    .await
                    .map_err(policy_error)?;
            }
            Ok(candidates.into_iter().map(|v| v.2).collect())
        })
    }
    fn operation<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        id: Uuid,
    ) -> Pending<'a, Operation> {
        Box::pin(async move {
            match native_ownership::on(c, p.tenant(), id)
                .await
                .map_err(policy_error)?
            {
                Owner::Configuration => self
                    .1
                    .windows_operation_on(c, p, id)
                    .await
                    .map(configuration_operation)
                    .map_err(policy_error),
                Owner::Execution => self
                    .0
                    .windows_operation_on(c, p, id)
                    .await
                    .map(operation)
                    .map_err(error),
                Owner::Software => self
                    .3
                    .windows_operation_on(c, p, id)
                    .await
                    .map(software_operation)
                    .map_err(software_error),
                Owner::Recovery => return Err(rss_mdm_windows_channel::Error::Forbidden),
                Owner::Registration => self
                    .4
                    .windows_operation_on(c, p, id)
                    .await
                    .map(registration_operation)
                    .map_err(registration_error),
            }
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
            match native_ownership::on(c, p.tenant(), id)
                .await
                .map_err(policy_error)?
            {
                Owner::Configuration => self
                    .1
                    .windows_dispatch_failure_on(
                        c,
                        p,
                        id,
                        reason,
                        phase.map(|p| match p {
                            AttemptPhase::Prepare => {
                                rss_mdm_policy_service::configuration::model::AttemptPhase::Prepare
                            }
                            AttemptPhase::Execute => {
                                rss_mdm_policy_service::configuration::model::AttemptPhase::Execute
                            }
                            AttemptPhase::Observe => {
                                rss_mdm_policy_service::configuration::model::AttemptPhase::Observe
                            }
                        }),
                        context,
                    )
                    .await
                    .map_err(policy_error),
                Owner::Execution => self
                    .0
                    .windows_dispatch_failure_on(
                        c,
                        p,
                        id,
                        reason,
                        phase.map(|p| match p {
                            AttemptPhase::Prepare => {
                                rss_mdm_execution_service::AttemptPhase::Prepare
                            }
                            AttemptPhase::Execute => {
                                rss_mdm_execution_service::AttemptPhase::Execute
                            }
                            AttemptPhase::Observe => {
                                rss_mdm_execution_service::AttemptPhase::Observe
                            }
                        }),
                        context,
                    )
                    .await
                    .map_err(error),
                Owner::Software => self
                    .3
                    .windows_dispatch_failure_on(
                        c,
                        p,
                        id,
                        reason,
                        phase.map(|p| match p {
                            AttemptPhase::Prepare => {
                                rss_mdm_software_service::deployment::AttemptPhase::Prepare
                            }
                            AttemptPhase::Execute => {
                                rss_mdm_software_service::deployment::AttemptPhase::Execute
                            }
                            AttemptPhase::Observe => {
                                rss_mdm_software_service::deployment::AttemptPhase::Observe
                            }
                        }),
                        context,
                    )
                    .await
                    .map_err(software_error),
                Owner::Recovery => return Err(rss_mdm_windows_channel::Error::Forbidden),
                Owner::Registration => self
                    .4
                    .windows_dispatch_failure_on(
                        c,
                        p,
                        id,
                        reason,
                        phase.map(|p| match p {
                            AttemptPhase::Prepare => {
                                rss_mdm_registration_service::installation::AttemptPhase::Prepare
                            }
                            AttemptPhase::Execute => {
                                rss_mdm_registration_service::installation::AttemptPhase::Execute
                            }
                            AttemptPhase::Observe => {
                                rss_mdm_registration_service::installation::AttemptPhase::Observe
                            }
                        }),
                        context,
                    )
                    .await
                    .map_err(registration_error),
            }
        })
    }
    fn wake_configuration<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.1
                .wake_registration_on(c, p)
                .await
                .map_err(policy_error)
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
            self.2
                .eligible_on(c, p, id, delivery)
                .await
                .map_err(collection_fault)
        })
    }
    fn collection_plan<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        id: Uuid,
    ) -> Pending<'a, rss_mdm_windows_mdm::native::collection::Plan> {
        Box::pin(async move {
            let definition =
                rss_mdm_inventory_service::collection::execution::native::definition_on(
                    c, tenant, id,
                )
                .await
                .map_err(collection_fault)?;
            rss_mdm_windows_channel::collection_plan::compile_plan(&definition)
        })
    }
    fn collection_sent<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        id: Uuid,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_inventory_service::collection::execution::native::sent_on(c, tenant, id)
                .await
                .map_err(collection_fault)
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
            let mut candidates = self
                .0
                .windows_wake_candidates_in(c, after)
                .await
                .map_err(error)?;
            candidates.extend(
                self.1
                    .windows_wake_candidates_in(c, after)
                    .await
                    .map_err(policy_error)?,
            );
            candidates.extend(
                self.2
                    .windows_wake_candidates_on(c, after)
                    .await
                    .map_err(collection_fault)?,
            );
            candidates.extend(
                self.3
                    .windows_wake_candidates_in(c, after)
                    .await
                    .map_err(software_error)?,
            );
            candidates.extend(
                self.4
                    .windows_wake_candidates_in(c, after)
                    .await
                    .map_err(registration_error)?,
            );
            candidates.sort();
            candidates.dedup();
            candidates.truncate(32);
            Ok(candidates)
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
            let execution = self
                .0
                .windows_wake_pending_in(c, device, registration, generation)
                .await
                .map_err(error)?;
            let configuration = self
                .1
                .windows_wake_pending_in(c, device, registration, generation)
                .await
                .map_err(policy_error)?;
            let collection = self
                .2
                .windows_wake_pending_on(c, device, registration, generation)
                .await
                .map_err(collection_fault)?;
            let software = self
                .3
                .windows_wake_pending_in(c, device, registration, generation)
                .await
                .map_err(software_error)?;
            let bootstrap = self
                .4
                .windows_wake_pending_in(c, device, registration, generation)
                .await
                .map_err(registration_error)?;
            Ok(execution || configuration || collection || software || bootstrap)
        })
    }
}

fn policy_error(e: rss_mdm_policy_service::Error) -> rss_mdm_windows_channel::Error {
    use rss_mdm_policy_service::Error as P;
    use rss_mdm_windows_channel::{Error as C, Failure};
    match e {
        P::CommitUnknown => C::CommitUnknown,
        P::RollbackFailed => C::RollbackFailed,
        P::Malformed => C::Malformed,
        P::Unauthorized => C::Unauthorized,
        P::Forbidden | P::MdmSoftwareDisabled => C::Forbidden,
        P::ReadConflict | P::Conflict | P::WindowsDeclaredEnrollmentNotReady => C::Conflict,
        P::NotFound | P::PolicyMissing | P::ResourceMissing => C::NotFound,
        P::Unsupported => C::Unsupported,
        P::Unavailable(_) => C::Unavailable(Failure::Business),
    }
}
fn policy_fault(e: rss_mdm_policy_service::transaction::Fault) -> rss_mdm_windows_channel::Error {
    match e {
        rss_mdm_policy_service::transaction::Fault::Request(e) => policy_error(e),
        rss_mdm_policy_service::transaction::Fault::Storage(e) => e.into(),
        rss_mdm_policy_service::transaction::Fault::Sql(e) => e.into(),
    }
}

fn configuration_operation(
    v: rss_mdm_policy_service::configuration::windows::WindowsOperation,
) -> Operation {
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

fn collection_fault(
    e: rss_mdm_inventory_service::transaction::Fault,
) -> rss_mdm_windows_channel::Error {
    use rss_mdm_inventory_service::transaction::Fault;
    match e {
        Fault::Request(e) => e.into(),
        Fault::Sql(e) => e.into(),
        Fault::Storage(e) => e.into(),
    }
}

fn software_error(
    e: rss_mdm_software_service::deployment::Error,
) -> rss_mdm_windows_channel::Error {
    use rss_mdm_software_service::deployment::Error as E;
    use rss_mdm_windows_channel::Missing;
    use rss_mdm_windows_channel::{Error as A, Failure};
    match e { E::MdmSoftwareDisabled => A::Forbidden, E::Malformed => A::Malformed, E::CertificateRequest => A::CertificateRequest,
            E::Unauthorized => A::Unauthorized, E::Forbidden => A::Forbidden, E::ReadConflict | E::CursorInvalidated | E::Conflict | E::WindowsDeclaredEnrollmentNotReady => A::Conflict,
            E::EnrollmentPaused=> A::EnrollmentPaused, E::CommitUnknown => A::CommitUnknown, E::RollbackFailed => A::RollbackFailed, E::Unsupported => A::Unsupported,
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

fn software_fault(
    e: rss_mdm_software_service::deployment::transaction::Fault,
) -> rss_mdm_windows_channel::Error {
    use rss_mdm_software_service::deployment::transaction::Fault;
    match e {
        Fault::Request(e) => software_error(e),
        Fault::Storage(e) => e.into(),
        Fault::Sql(e) => e.into(),
    }
}

fn software_operation(
    v: rss_mdm_software_service::deployment::windows_business::WindowsOperation,
) -> Operation {
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

fn registration_error(
    e: rss_mdm_registration_service::installation::Error,
) -> rss_mdm_windows_channel::Error {
    use rss_mdm_registration_service::installation::Error as E;
    use rss_mdm_windows_channel::Missing;
    use rss_mdm_windows_channel::{Error as A, Failure};
    match e { E::MdmSoftwareDisabled => A::Forbidden, E::Malformed => A::Malformed, E::CertificateRequest => A::CertificateRequest,
            E::Unauthorized => A::Unauthorized, E::Forbidden => A::Forbidden, E::ReadConflict | E::CursorInvalidated | E::Conflict | E::WindowsDeclaredEnrollmentNotReady => A::Conflict,
            E::EnrollmentPaused=> A::EnrollmentPaused, E::CommitUnknown => A::CommitUnknown, E::RollbackFailed => A::RollbackFailed, E::Unsupported => A::Unsupported,
            E::NotFound => A::NotFound, E::Resource(_) => A::Missing(Missing::Resource),
            E::Execution(e) => A::Missing(match e { rss_mdm_registration_service::installation::missing::ExecutionError::MissingOperation => Missing::Operation, rss_mdm_registration_service::installation::missing::ExecutionError::MissingTask => Missing::Task }),

            E::Configuration(_) => A::Unavailable(Failure::BusinessConfiguration),
            E::Unavailable(f) => A::Unavailable(match f {
                rss_mdm_registration_service::installation::Failure::RequestDeadline => Failure::RequestDeadline,
                rss_mdm_registration_service::installation::Failure::Audit => Failure::Audit,
                rss_mdm_registration_service::installation::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_registration_service::installation::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_registration_service::installation::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_registration_service::installation::Failure::AuditContract => Failure::AuditContract,

                _ => Failure::Business,
            }),
        }
}

fn registration_fault(
    e: rss_mdm_registration_service::installation::transaction::Fault,
) -> rss_mdm_windows_channel::Error {
    use rss_mdm_registration_service::installation::transaction::Fault;
    match e {
        Fault::Request(e) => registration_error(e),
        Fault::Storage(e) => e.into(),
        Fault::Sql(e) => e.into(),
    }
}

fn registration_operation(
    v: rss_mdm_registration_service::installation::windows_business::WindowsOperation,
) -> Operation {
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
