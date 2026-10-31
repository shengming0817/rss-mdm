//! Static mappings for the foreign capabilities consumed by Policy.
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::{RequestAudit, activity::ActivityOrigin};
use rss_mdm_authorization_service::{Snapshot, context::AuthorizedPrincipal};
use rss_mdm_policy::{Action, Policy};
use rss_mdm_policy_service::events::participants::*;
use rss_mdm_policy_service::{Error, Failure, inputs::*, transaction::Fault};
use rss_transactional_messaging_postgres::PgTransaction;
use std::sync::Arc;
use uuid::Uuid;
pub(super) fn error(e: rss_mdm_execution_service::Error) -> Error {
    use rss_mdm_execution_service::Error as E;
    match e {
        E::Malformed => Error::Malformed,
        E::Unauthorized => Error::Unauthorized,
        E::Forbidden => Error::Forbidden,
        E::ReadConflict
        | E::CursorInvalidated
        | E::Conflict
        | E::EnrollmentPaused
        | E::WindowsDeclaredEnrollmentNotReady => Error::Conflict,
        E::CommitUnknown => Error::CommitUnknown,
        E::RollbackFailed => Error::RollbackFailed,
        E::Unsupported => Error::Unsupported,
        E::NotFound | E::Resource(_) => Error::ResourceMissing,
        E::Unavailable(f) => Error::Unavailable(match f {
            rss_mdm_execution_service::Failure::RequestDeadline => Failure::RequestDeadline,
            rss_mdm_execution_service::Failure::Audit => Failure::Audit,
            rss_mdm_execution_service::Failure::AuditIntegrity => Failure::AuditIntegrity,
            rss_mdm_execution_service::Failure::AuditAdmission => Failure::AuditAdmission,
            rss_mdm_execution_service::Failure::AuditIsolation => Failure::AuditIsolation,
            rss_mdm_execution_service::Failure::AuditContract => Failure::AuditContract,
            rss_mdm_execution_service::Failure::NativeProtection => Failure::NativeProtection,
            rss_mdm_execution_service::Failure::NativeInputIntegrity => {
                Failure::NativeInputIntegrity
            }
            rss_mdm_execution_service::Failure::CommandInvariant => Failure::CommandInvariant,
            rss_mdm_execution_service::Failure::ContentStorage => Failure::ContentStorage,
            rss_mdm_execution_service::Failure::ContentMetadata => Failure::ContentMetadata,
            rss_mdm_execution_service::Failure::ContentInvariant => Failure::ContentInvariant,
            rss_mdm_execution_service::Failure::ContentDeadline => Failure::ContentDeadline,
            rss_mdm_execution_service::Failure::ContentCleanup => Failure::ContentCleanup,
            rss_mdm_execution_service::Failure::AutomationConnection => {
                Failure::AutomationConnection
            }
            rss_mdm_execution_service::Failure::AutomationAdmission => Failure::AutomationAdmission,
            rss_mdm_execution_service::Failure::AutomationStorage => Failure::AutomationStorage,
            rss_mdm_execution_service::Failure::Database => Failure::Database,
            rss_mdm_execution_service::Failure::AssetObjectLimit => Failure::AssetObjectLimit,
            rss_mdm_execution_service::Failure::AssetSourceLimit => Failure::AssetSourceLimit,
            rss_mdm_execution_service::Failure::AssetBytesLimit => Failure::AssetBytesLimit,
            rss_mdm_execution_service::Failure::Clock => Failure::Clock,
            rss_mdm_execution_service::Failure::Capacity => Failure::Capacity,
            rss_mdm_execution_service::Failure::Runtime => Failure::Runtime,
            rss_mdm_execution_service::Failure::SoftwareCatalogInvariant => {
                Failure::SoftwareIntegrity
            }
            rss_mdm_execution_service::Failure::PlanningAdmission => Failure::PolicyAdmission,
            rss_mdm_execution_service::Failure::PlanningStorage => Failure::PolicyStorage,
            rss_mdm_execution_service::Failure::Timeline
            | rss_mdm_execution_service::Failure::IdentityStorage
            | rss_mdm_execution_service::Failure::ResourceAdmission
            | rss_mdm_execution_service::Failure::CommandAdmission
            | rss_mdm_execution_service::Failure::ContentImport
            | rss_mdm_execution_service::Failure::SoftwareCatalogStorage
            | rss_mdm_execution_service::Failure::CommandStorage
            | rss_mdm_execution_service::Failure::AssetsStorage
            | rss_mdm_execution_service::Failure::ComplianceStorage
            | rss_mdm_execution_service::Failure::ResourceStorage
            | rss_mdm_execution_service::Failure::PublicationStorage
            | rss_mdm_execution_service::Failure::InventoryQuery
            | rss_mdm_execution_service::Failure::AssetCandidates
            | rss_mdm_execution_service::Failure::AssetSources
            | rss_mdm_execution_service::Failure::ManualQuery
            | rss_mdm_execution_service::Failure::CollectionQuery
            | rss_mdm_execution_service::Failure::InventoryRuntime
            | rss_mdm_execution_service::Failure::Protocol => Failure::Preparation,
        }),
        E::Configuration(_) => Error::Unavailable(Failure::PreparationConfiguration),
        E::Execution(_) | E::CertificateRequest => Error::Unavailable(Failure::PreparationContract),
    }
}
pub(super) fn fault(e: rss_mdm_execution_service::transaction::Fault) -> Fault {
    match e {
        rss_mdm_execution_service::transaction::Fault::Request(e) => Fault::Request(error(e)),
        rss_mdm_execution_service::transaction::Fault::Storage(e) => Fault::Storage(e),
        rss_mdm_execution_service::transaction::Fault::Sql(e) => Fault::Sql(e),
    }
}
pub(super) struct Publication {
    pub execution: Arc<rss_mdm_execution_service::Inputs>,
    pub software: Arc<rss_mdm_software_service::deployment::Inputs>,
    pub enrollment_entries: rss_mdm_registration_service::enrollment::task::Entries,
    pub signing_enabled: bool,
}
fn execution_action(action: &Action) -> Result<(), Error> {
    if matches!(
        action,
        Action::Execution { .. }
            | Action::AgentCollection { .. }
            | Action::NativeCollection { .. }
            | Action::Configuration { .. }
            | Action::TelemetryProfile { .. }
            | Action::UnmanageDevice { .. }
    ) {
        Err(Error::Unsupported)
    } else {
        Ok(())
    }
}
impl ExecutionPublication for Publication {
    fn software_binding_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        action: &'a Action,
    ) -> Pending<'a, Option<[u8; 32]>, Fault> {
        Box::pin(async move {
            self.software
                .software_binding_in(tx, action)
                .await
                .map_err(software_fault)
        })
    }
    fn publish_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        policy: &'a Policy,
        proof: &'a AuthorizedPrincipal,
        snapshot: &'a Snapshot,
    ) -> Pending<'a, serde_json::Value, Fault> {
        Box::pin(async move {
            if matches!(
                policy.definition.action,
                Action::Software { .. } | Action::EnsureAgentInstalled { .. }
            ) {
                use rss_mdm_software_service::deployment::input_preparation as software;
                let input = software::PublicationInput::try_from(&policy.definition.action)
                    .map_err(software_error)?;
                let frozen = self
                    .software
                    .publish_in(
                        tx,
                        &input,
                        &software::PublicationAuthority {
                            proof,
                            snapshot,
                            devices: None,
                        },
                    )
                    .await
                    .map_err(software_fault)?;
                return serde_json::to_value(frozen)
                    .map_err(|_| Error::Unavailable(Failure::PreparationContract).into());
            }
            if let Action::RequestMdmEnrollment {
                organization,
                schedule,
                run_lifetime_seconds,
            } = &policy.definition.action
            {
                use rss_mdm_registration_service::enrollment::{task, tasks};
                if let Some(config) = &policy.definition.self_service {
                    tasks::self_service::validate_access(
                        config,
                        proof.tenant_id(),
                        proof.instance_id(),
                    )
                    .map_err(enrollment_error)?;
                }
                let action = task::prepare(
                    &self.enrollment_entries,
                    self.signing_enabled,
                    proof,
                    snapshot,
                    *organization,
                    schedule,
                    *run_lifetime_seconds,
                )
                .map_err(|e| registration_input_error(e))?;
                return serde_json::to_value(tasks::policy::Published::Enrollment {
                    action: Box::new(action),
                })
                .map_err(|_| Error::Unavailable(Failure::PreparationContract).into());
            }
            execution_action(&policy.definition.action)?;
            let input = rss_mdm_execution_service::input_preparation::PublicationInput::try_from(
                &policy.definition.action,
            )
            .map_err(error)?;
            let frozen = self
                .execution
                .publish_in(
                    tx,
                    &input,
                    &rss_mdm_execution_service::input_preparation::PublicationAuthority {
                        proof,
                        snapshot,

                        devices: None,
                    },
                )
                .await
                .map_err(fault)?;
            serde_json::to_value(frozen)
                .map_err(|_| Error::Unavailable(Failure::PreparationContract).into())
        })
    }
}
pub(super) struct Changes {
    pub messaging: rss_reconcile_postgres::PgMessagingStore,
    pub targets: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
}
impl ExecutionChanges for Changes {
    fn policy_changed_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        policy: Uuid,
    ) -> Pending<'a, (), Fault> {
        Box::pin(async move {
            rss_mdm_software_service::deployment::sources::storage::wake_execution_in(
                &self.messaging,
                tx,
                policy,
            )
            .await
            .map_err(software_fault)?;
            rss_mdm_registration_service::enrollment::tasks::wake::policy_in(
                &self.messaging,
                tx,
                policy,
            )
            .await
            .map_err(enrollment_fault)?;
            rss_mdm_script_service::wake::policy_in(&self.messaging, tx, policy).await?;
            rss_mdm_inventory_service::collection::execution::wake::policy_in(
                &self.messaging,
                tx,
                policy,
            )
            .await?;
            rss_mdm_execution_service::sources::storage::wake_execution_in(
                &self.messaging,
                tx,
                policy,
            )
            .await
            .map_err(fault)
        })
    }
    fn assignment_changed_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        version: Uuid,
        target: &'a rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
    ) -> Pending<'a, (), Fault> {
        Box::pin(async move {
            rss_mdm_inventory_service::collection::execution::scheduled::wake_assignment_in(
                &self.messaging,
                tx,
                version,
                target,
            )
            .await?;
            rss_mdm_software_service::deployment::wake::wake_policy_device_in(
                &self.messaging,
                tx,
                version,
                target,
            )
            .await
            .map_err(software_fault)
        })
    }
    fn devices_changed_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        devices: &'a [String],
    ) -> Pending<'a, (), Fault> {
        Box::pin(async move {
            rss_mdm_software_service::deployment::wake::wake_native_batch_in(
                &self.messaging,
                Arc::new(super::software_sources::Source(self.targets.clone())),
                tx,
                devices,
            )
            .await
            .map_err(software_fault)?;
            rss_mdm_execution_service::wake::wake_native_batch_in(
                &self.messaging,
                self.targets.clone(),
                tx,
                devices,
            )
            .await
            .map_err(fault)
        })
    }
    fn retirement_accepted_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        retirement: Uuid,
    ) -> Pending<'a, (), Fault> {
        Box::pin(async move {
            rss_mdm_execution_service::unmanage::wake_in(&self.messaging, tx, retirement)
                .await
                .map_err(fault)
        })
    }
}
pub(super) struct Events {
    pub software: Arc<rss_mdm_software_service::deployment::Transactions>,
    pub enrollment: Arc<rss_mdm_registration_service::enrollment::tasks::Transactions>,
    pub scripts: Arc<rss_mdm_script_service::Transactions>,
    pub collections: Arc<rss_mdm_inventory_service::collection::execution::Transactions>,
    pub execution: Arc<rss_mdm_execution_service::policy_events::PolicyEvents>,
    pub configuration: Arc<rss_mdm_policy_service::configuration::Transactions>,
}
fn target(v: &Target) -> rss_mdm_execution_service::Target {
    rss_mdm_execution_service::Target {
        device: v.device.clone(),
        registration: v.registration,
        generation: v.generation,
    }
}
impl ExecutionEvents for Events {
    fn verify_event_device_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        principal: &'a rss_mdm_registration_service::DevicePrincipal,
        input: Option<&'a wire::PolicyEventRequest>,
    ) -> Pending<'a, (), Fault> {
        Box::pin(async move {
            self.execution
                .verify_event_device_in(tx, principal, input)
                .await
                .map_err(fault)
        })
    }
    fn apply_event_context_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        value: &'a Target,
        context: &'a wire::SoftwareExecutionContext,
    ) -> Pending<'a, (), Fault> {
        Box::pin(async move {
            self.software
                .apply_event_context_in(tx, &software_target(value), context)
                .await
                .map_err(software_fault)
        })
    }
    fn event_parent_current_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        value: &'a Target,
        source: &'a wire::PolicyEventSource,
    ) -> Pending<'a, bool, Fault> {
        Box::pin(async move {
            let wire::PolicyEventSource::Policy { run_id } = source else {
                return Ok(true);
            };
            let id = *run_id;
            let tenant = tx.tenant_id();
            let owner = tx
                .with_connection(move |c| {
                    Box::pin(async move { super::task_ownership::on(c, tenant, id).await })
                })
                .await?;
            use super::task_ownership::Owner;
            match owner {
                Owner::Execution => self
                    .execution
                    .event_parent_current_in(tx, &target(value), source)
                    .await
                    .map_err(fault),
                Owner::Software => self
                    .software
                    .event_parent_current_in(tx, &software_target(value), source)
                    .await
                    .map_err(software_fault),
                Owner::Registration => self
                    .enrollment
                    .event_parent_current_in(
                        tx,
                        &rss_mdm_registration_service::enrollment::tasks::Target {
                            device: value.device.clone(),
                            registration: value.registration,
                            generation: value.generation,
                        },
                        id,
                    )
                    .await
                    .map_err(enrollment_fault),
                Owner::Script => self
                    .scripts
                    .event_parent_current_in(
                        tx,
                        &rss_mdm_script_service::Target {
                            device: value.device.clone(),
                            registration: value.registration,
                            generation: value.generation,
                        },
                        id,
                    )
                    .await
                    .map_err(Into::into),
                Owner::Collection => self
                    .collections
                    .event_parent_current_in(
                        tx,
                        &rss_mdm_inventory_service::collection::execution::model::Target {
                            device: value.device.clone(),
                            registration: value.registration,
                            generation: value.generation,
                        },
                        id,
                    )
                    .await
                    .map_err(Into::into),
            }
        })
    }
    fn accept_policy_event_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        policy: &'a Policy,
        value: &'a Target,
        cause: (Uuid, ActivityOrigin),
        deadline: i64,
        audit: &'a RequestAudit,
    ) -> Pending<'a, wire::PolicyEventDecision, Fault> {
        Box::pin(async move {
            match policy.definition.action.kind() {
                rss_mdm_policy::ActionKind::Software
                | rss_mdm_policy::ActionKind::EnsureAgentInstalled => {
                    return self
                        .software
                        .accept_policy_event_in(
                            tx,
                            policy,
                            &software_target(value),
                            cause,
                            deadline,
                            audit,
                        )
                        .await
                        .map_err(software_fault);
                }
                rss_mdm_policy::ActionKind::RequestMdmEnrollment => {
                    return self
                        .enrollment
                        .accept_event_in(
                            tx,
                            policy.version,
                            &rss_mdm_registration_service::enrollment::tasks::Target {
                                device: value.device.clone(),
                                registration: value.registration,
                                generation: value.generation,
                            },
                            cause,
                            deadline,
                        )
                        .await
                        .map_err(enrollment_fault);
                }
                rss_mdm_policy::ActionKind::Execution => {
                    return self
                        .scripts
                        .accept_event_in(
                            tx,
                            policy.version,
                            &rss_mdm_script_service::Target {
                                device: value.device.clone(),
                                registration: value.registration,
                                generation: value.generation,
                            },
                            cause,
                            deadline,
                        )
                        .await
                        .map_err(Into::into);
                }
                rss_mdm_policy::ActionKind::AgentCollection
                | rss_mdm_policy::ActionKind::NativeCollection => {
                    return self
                        .collections
                        .accept_event_in(
                            tx,
                            policy.version,
                            &rss_mdm_inventory_service::collection::execution::model::Target {
                                device: value.device.clone(),
                                registration: value.registration,
                                generation: value.generation,
                            },
                            cause,
                            deadline,
                        )
                        .await
                        .map_err(Into::into);
                }
                _ => {}
            }
            execution_action(&policy.definition.action)?;
            self.execution
                .accept_policy_event_in(tx, policy, &target(value), cause, deadline, audit)
                .await
                .map_err(fault)
        })
    }
}
impl ExecutionProgress for Events {
    fn policy_event_operation_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        reference: &'a wire::PolicyEventOperation,
    ) -> Pending<'a, EventOperationProgress, Fault> {
        Box::pin(async move {
            if let wire::PolicyEventOperation::Run { id } = reference {
                let tenant = tx.tenant_id();
                let id = *id;
                match tx
                    .with_connection(move |c| Box::pin(super::task_ownership::on(c, tenant, id)))
                    .await?
                {
                    super::task_ownership::Owner::Script => {
                        return Ok(EventOperationProgress::Run {
                            reference: reference.clone(),
                            state: rss_mdm_script_service::storage::read_run(tx, id)
                                .await?
                                .state,
                            allowed_actions: [],
                        });
                    }
                    super::task_ownership::Owner::Collection => {
                        use rss_mdm_inventory_service::collection::execution::storage;
                        return Ok(if storage::channel_in(tx, id).await? == "agent" {
                            EventOperationProgress::Run {
                                reference: reference.clone(),
                                state: storage::read_run(tx, id).await?.state,
                                allowed_actions: [],
                            }
                        } else {
                            EventOperationProgress::Collection {
                                reference: reference.clone(),
                                state: storage::native_progress_in(tx, id).await?,
                                allowed_actions: [],
                            }
                        });
                    }
                    super::task_ownership::Owner::Registration => {
                        return Ok(EventOperationProgress::Run {
                            reference: reference.clone(),
                            state:
                                rss_mdm_registration_service::enrollment::tasks::storage::read_run(
                                    tx, id,
                                )
                                .await
                                .map_err(enrollment_fault)?
                                .state,
                            allowed_actions: [],
                        });
                    }
                    super::task_ownership::Owner::Software => {
                        return self
                            .software
                            .policy_event_operation_in(tx, reference)
                            .await
                            .map(software_progress)
                            .map_err(software_fault);
                    }
                    super::task_ownership::Owner::Execution => {}
                }
            }
            if let wire::PolicyEventOperation::Native { id } = reference {
                let owner = super::native_ownership::in_transaction(tx, *id).await?;
                if owner == super::native_ownership::Owner::Registration {
                    return Err(Error::Forbidden.into());
                }
                if owner == super::native_ownership::Owner::Software {
                    return self
                        .software
                        .policy_event_operation_in(tx, reference)
                        .await
                        .map(software_progress)
                        .map_err(software_fault);
                }
                if owner == super::native_ownership::Owner::Configuration {
                    return self.configuration.event_progress_in(tx, reference).await;
                }
            }
            use rss_mdm_execution_service::policy_events::EventOperationProgress as P;
            Ok(
                match self
                    .execution
                    .policy_event_operation_in(tx, reference)
                    .await
                    .map_err(fault)?
                {
                    P::Run {
                        reference,
                        state,
                        allowed_actions,
                    } => EventOperationProgress::Run {
                        reference,
                        state,
                        allowed_actions,
                    },
                    P::Native {
                        reference,
                        state,
                        allowed_actions,
                    } => EventOperationProgress::Native {
                        reference,
                        state,
                        agent_installation: None,
                        allowed_actions,
                    },
                    P::Retirement {
                        reference,
                        state,
                        allowed_actions,
                    } => EventOperationProgress::Retirement {
                        reference,
                        state,
                        allowed_actions,
                    },
                },
            )
        })
    }
}

pub(super) fn software_error(e: rss_mdm_software_service::deployment::Error) -> Error {
    use rss_mdm_software_service::deployment::Error as E;
    match e {
        E::MdmSoftwareDisabled => Error::MdmSoftwareDisabled,
        E::Malformed => Error::Malformed,
        E::Unauthorized => Error::Unauthorized,
        E::Forbidden => Error::Forbidden,
        E::ReadConflict
        | E::CursorInvalidated
        | E::Conflict
        | E::EnrollmentPaused
        | E::WindowsDeclaredEnrollmentNotReady => Error::Conflict,
        E::CommitUnknown => Error::CommitUnknown,
        E::RollbackFailed => Error::RollbackFailed,
        E::Unsupported => Error::Unsupported,
        E::NotFound | E::Resource(_) => Error::ResourceMissing,
        E::Unavailable(f) => Error::Unavailable(match f {
            rss_mdm_software_service::deployment::Failure::RequestDeadline => {
                Failure::RequestDeadline
            }
            rss_mdm_software_service::deployment::Failure::Audit => Failure::Audit,
            rss_mdm_software_service::deployment::Failure::AuditIntegrity => {
                Failure::AuditIntegrity
            }
            rss_mdm_software_service::deployment::Failure::AuditAdmission => {
                Failure::AuditAdmission
            }
            rss_mdm_software_service::deployment::Failure::AuditIsolation => {
                Failure::AuditIsolation
            }
            rss_mdm_software_service::deployment::Failure::AuditContract => Failure::AuditContract,
            rss_mdm_software_service::deployment::Failure::NativeProtection => {
                Failure::NativeProtection
            }
            rss_mdm_software_service::deployment::Failure::NativeInputIntegrity => {
                Failure::NativeInputIntegrity
            }
            rss_mdm_software_service::deployment::Failure::CommandInvariant => {
                Failure::CommandInvariant
            }
            rss_mdm_software_service::deployment::Failure::ContentStorage => {
                Failure::ContentStorage
            }
            rss_mdm_software_service::deployment::Failure::ContentMetadata => {
                Failure::ContentMetadata
            }
            rss_mdm_software_service::deployment::Failure::ContentInvariant => {
                Failure::ContentInvariant
            }
            rss_mdm_software_service::deployment::Failure::ContentDeadline => {
                Failure::ContentDeadline
            }
            rss_mdm_software_service::deployment::Failure::ContentCleanup => {
                Failure::ContentCleanup
            }
            rss_mdm_software_service::deployment::Failure::AutomationConnection => {
                Failure::AutomationConnection
            }
            rss_mdm_software_service::deployment::Failure::AutomationAdmission => {
                Failure::AutomationAdmission
            }
            rss_mdm_software_service::deployment::Failure::AutomationStorage => {
                Failure::AutomationStorage
            }
            rss_mdm_software_service::deployment::Failure::Database => Failure::Database,
            rss_mdm_software_service::deployment::Failure::AssetObjectLimit => {
                Failure::AssetObjectLimit
            }
            rss_mdm_software_service::deployment::Failure::AssetSourceLimit => {
                Failure::AssetSourceLimit
            }
            rss_mdm_software_service::deployment::Failure::AssetBytesLimit => {
                Failure::AssetBytesLimit
            }
            rss_mdm_software_service::deployment::Failure::Clock => Failure::Clock,
            rss_mdm_software_service::deployment::Failure::Capacity => Failure::Capacity,
            rss_mdm_software_service::deployment::Failure::Runtime => Failure::Runtime,
            rss_mdm_software_service::deployment::Failure::SoftwareCatalogInvariant => {
                Failure::SoftwareIntegrity
            }
            rss_mdm_software_service::deployment::Failure::PlanningAdmission => {
                Failure::PolicyAdmission
            }
            rss_mdm_software_service::deployment::Failure::PlanningStorage => {
                Failure::PolicyStorage
            }
            rss_mdm_software_service::deployment::Failure::Timeline
            | rss_mdm_software_service::deployment::Failure::IdentityStorage
            | rss_mdm_software_service::deployment::Failure::ResourceAdmission
            | rss_mdm_software_service::deployment::Failure::CommandAdmission
            | rss_mdm_software_service::deployment::Failure::ContentImport
            | rss_mdm_software_service::deployment::Failure::SoftwareCatalogStorage
            | rss_mdm_software_service::deployment::Failure::CommandStorage
            | rss_mdm_software_service::deployment::Failure::AssetsStorage
            | rss_mdm_software_service::deployment::Failure::ComplianceStorage
            | rss_mdm_software_service::deployment::Failure::ResourceStorage
            | rss_mdm_software_service::deployment::Failure::PublicationStorage
            | rss_mdm_software_service::deployment::Failure::InventoryQuery
            | rss_mdm_software_service::deployment::Failure::AssetCandidates
            | rss_mdm_software_service::deployment::Failure::AssetSources
            | rss_mdm_software_service::deployment::Failure::ManualQuery
            | rss_mdm_software_service::deployment::Failure::CollectionQuery
            | rss_mdm_software_service::deployment::Failure::InventoryRuntime
            | rss_mdm_software_service::deployment::Failure::Protocol => Failure::Preparation,
        }),
        E::Configuration(_) => Error::Unavailable(Failure::PreparationConfiguration),
        E::Execution(_) | E::Publication(_) | E::CertificateRequest => {
            Error::Unavailable(Failure::PreparationContract)
        }
    }
}

pub(super) fn software_fault(e: rss_mdm_software_service::deployment::transaction::Fault) -> Fault {
    match e {
        rss_mdm_software_service::deployment::transaction::Fault::Request(e) => {
            Fault::Request(software_error(e))
        }
        rss_mdm_software_service::deployment::transaction::Fault::Storage(e) => Fault::Storage(e),
        rss_mdm_software_service::deployment::transaction::Fault::Sql(e) => Fault::Sql(e),
    }
}

fn software_installation(
    v: rss_mdm_software_service::deployment::queries::records::InstallationObservation,
) -> InstallationObservation {
    let rss_mdm_software_service::deployment::queries::records::InstallationObservation {
        bootstrap,
        protocol,
        delivery,
        installation,
        agent_registration,
        observed_at,
    } = v;
    InstallationObservation {
        bootstrap: bootstrap.map(software_bootstrap_observation),
        protocol,
        delivery,
        installation,
        agent_registration: agent_registration.map(software_agent_registration_observation),
        observed_at,
    }
}

fn software_bootstrap_observation(
    v: rss_mdm_software_service::deployment::queries::records::BootstrapObservation,
) -> BootstrapObservation {
    let rss_mdm_software_service::deployment::queries::records::BootstrapObservation {
        state,
        delivery,
        cleanup,
        cleanup_complete,
        cleanup_retry_at,
        deadline,
    } = v;
    BootstrapObservation {
        state,
        delivery,
        cleanup,
        cleanup_complete,
        cleanup_retry_at,
        deadline,
    }
}

fn software_agent_registration_observation(
    v: rss_mdm_software_service::deployment::queries::records::AgentRegistration,
) -> AgentRegistration {
    let rss_mdm_software_service::deployment::queries::records::AgentRegistration {
        device_id,
        registration_id,
        state,
        capabilities,
    } = v;
    AgentRegistration {
        device_id,
        registration_id,
        state,
        capabilities,
    }
}

fn software_target(v: &Target) -> rss_mdm_software_service::deployment::Target {
    rss_mdm_software_service::deployment::Target {
        device: v.device.clone(),
        registration: v.registration,
        generation: v.generation,
    }
}
fn software_progress(
    v: rss_mdm_software_service::deployment::policy_events::EventOperationProgress,
) -> EventOperationProgress {
    use rss_mdm_software_service::deployment::policy_events::EventOperationProgress as P;
    match v {
        P::Run {
            reference,
            state,
            allowed_actions,
        } => EventOperationProgress::Run {
            reference,
            state,
            allowed_actions,
        },
        P::Native {
            reference,
            state,
            agent_installation,
            allowed_actions,
        } => EventOperationProgress::Native {
            reference,
            state,
            agent_installation: agent_installation.map(software_installation),
            allowed_actions,
        },
    }
}
fn enrollment_error(e: rss_mdm_registration_service::enrollment::tasks::Error) -> Error {
    use rss_mdm_registration_service::enrollment::tasks::Error as E;
    match e {
        E::CommitUnknown => Error::CommitUnknown,
        E::RollbackFailed => Error::RollbackFailed,
        E::Malformed => Error::Malformed,
        E::Forbidden => Error::Forbidden,
        E::Unauthorized => Error::Unauthorized,
        E::Conflict => Error::Conflict,
        E::NotFound => Error::NotFound,
        E::Audit(_) => Error::Unavailable(Failure::Audit),
        E::Invariant => Error::Unavailable(Failure::CommandInvariant),
        E::Unavailable => Error::Unavailable(Failure::PolicyStorage),
    }
}
fn enrollment_fault(
    e: rss_mdm_registration_service::enrollment::tasks::transaction::Fault,
) -> Fault {
    use rss_mdm_registration_service::enrollment::tasks::transaction::Fault as F;
    match e {
        F::Storage(e) => Fault::Storage(e),
        F::Sql(e) => Fault::Sql(e),
        F::Request(e) => Fault::Request(enrollment_error(e)),
    }
}
fn registration_input_error(e: rss_mdm_registration_service::Error) -> Fault {
    use rss_mdm_registration_service::Error as E;
    match e {
        E::CommitUnknown => Error::CommitUnknown,
        E::RollbackFailed => Error::RollbackFailed,
        E::Malformed => Error::Malformed,
        E::Forbidden => Error::Forbidden,
        E::Unauthorized => Error::Unauthorized,
        E::Conflict => Error::Conflict,
        _ => Error::Unsupported,
    }
    .into()
}
