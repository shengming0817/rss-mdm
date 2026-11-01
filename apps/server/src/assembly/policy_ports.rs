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
pub(super) fn error(e: rss_mdm_device_service::control::Error) -> Error {
    use rss_mdm_device_service::control::Error as E;
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
            rss_mdm_device_service::control::Failure::RequestDeadline => Failure::RequestDeadline,
            rss_mdm_device_service::control::Failure::Audit => Failure::Audit,
            rss_mdm_device_service::control::Failure::AuditIntegrity => Failure::AuditIntegrity,
            rss_mdm_device_service::control::Failure::AuditAdmission => Failure::AuditAdmission,
            rss_mdm_device_service::control::Failure::AuditIsolation => Failure::AuditIsolation,
            rss_mdm_device_service::control::Failure::AuditContract => Failure::AuditContract,
            rss_mdm_device_service::control::Failure::NativeProtection => Failure::NativeProtection,
            rss_mdm_device_service::control::Failure::NativeInputIntegrity => {
                Failure::NativeInputIntegrity
            }
            rss_mdm_device_service::control::Failure::CommandInvariant => Failure::CommandInvariant,
            rss_mdm_device_service::control::Failure::ContentStorage => Failure::ContentStorage,
            rss_mdm_device_service::control::Failure::ContentMetadata => Failure::ContentMetadata,
            rss_mdm_device_service::control::Failure::ContentInvariant => Failure::ContentInvariant,
            rss_mdm_device_service::control::Failure::ContentDeadline => Failure::ContentDeadline,
            rss_mdm_device_service::control::Failure::ContentCleanup => Failure::ContentCleanup,
            rss_mdm_device_service::control::Failure::AutomationConnection => {
                Failure::AutomationConnection
            }
            rss_mdm_device_service::control::Failure::AutomationAdmission => {
                Failure::AutomationAdmission
            }
            rss_mdm_device_service::control::Failure::AutomationStorage => {
                Failure::AutomationStorage
            }
            rss_mdm_device_service::control::Failure::Database => Failure::Database,
            rss_mdm_device_service::control::Failure::AssetObjectLimit => Failure::AssetObjectLimit,
            rss_mdm_device_service::control::Failure::AssetSourceLimit => Failure::AssetSourceLimit,
            rss_mdm_device_service::control::Failure::AssetBytesLimit => Failure::AssetBytesLimit,
            rss_mdm_device_service::control::Failure::Clock => Failure::Clock,
            rss_mdm_device_service::control::Failure::Capacity => Failure::Capacity,
            rss_mdm_device_service::control::Failure::Runtime => Failure::Runtime,
            rss_mdm_device_service::control::Failure::SoftwareCatalogInvariant => {
                Failure::SoftwareIntegrity
            }
            rss_mdm_device_service::control::Failure::PlanningAdmission => Failure::PolicyAdmission,
            rss_mdm_device_service::control::Failure::PlanningStorage => Failure::PolicyStorage,
            rss_mdm_device_service::control::Failure::Timeline
            | rss_mdm_device_service::control::Failure::IdentityStorage
            | rss_mdm_device_service::control::Failure::ResourceAdmission
            | rss_mdm_device_service::control::Failure::CommandAdmission
            | rss_mdm_device_service::control::Failure::ContentImport
            | rss_mdm_device_service::control::Failure::SoftwareCatalogStorage
            | rss_mdm_device_service::control::Failure::CommandStorage
            | rss_mdm_device_service::control::Failure::AssetsStorage
            | rss_mdm_device_service::control::Failure::ComplianceStorage
            | rss_mdm_device_service::control::Failure::ResourceStorage
            | rss_mdm_device_service::control::Failure::PublicationStorage
            | rss_mdm_device_service::control::Failure::InventoryQuery
            | rss_mdm_device_service::control::Failure::AssetCandidates
            | rss_mdm_device_service::control::Failure::AssetSources
            | rss_mdm_device_service::control::Failure::ManualQuery
            | rss_mdm_device_service::control::Failure::CollectionQuery
            | rss_mdm_device_service::control::Failure::InventoryRuntime
            | rss_mdm_device_service::control::Failure::Protocol => Failure::Preparation,
        }),
        E::Configuration(_) => Error::Unavailable(Failure::PreparationConfiguration),
        E::Execution(_) | E::CertificateRequest => Error::Unavailable(Failure::PreparationContract),
    }
}
pub(super) fn fault(e: rss_mdm_device_service::control::transaction::Fault) -> Fault {
    match e {
        rss_mdm_device_service::control::transaction::Fault::Request(e) => Fault::Request(error(e)),
        rss_mdm_device_service::control::transaction::Fault::Storage(e) => Fault::Storage(e),
        rss_mdm_device_service::control::transaction::Fault::Sql(e) => Fault::Sql(e),
    }
}
pub(super) struct Publication {
    pub software: Arc<rss_mdm_software_service::deployment::Inputs>,
    pub enrollment_entries: rss_mdm_registration_service::enrollment::task::Entries,
    pub signing_enabled: bool,
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
                .map_err(registration_input_error)?;
                return serde_json::to_value(tasks::policy::Published::Enrollment {
                    action: Box::new(action),
                })
                .map_err(|_| Error::Unavailable(Failure::PreparationContract).into());
            }
            Err(Error::Unsupported.into())
        })
    }
}
pub(super) struct Changes {
    pub reader: rss_mdm_policy_postgres::PolicyReader,
    pub messaging: rss_reconcile_postgres::PgMessagingStore,
    pub targets: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
}
impl ExecutionChanges for Changes {
    fn policy_changed_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        policy: &'a Policy,
        previous: Option<&'a Policy>,
    ) -> Pending<'a, (), Fault> {
        Box::pin(async move {
            use rss_mdm_policy::ActionKind as K;
            if previous.is_some_and(|p| p.id != policy.id) {
                return Err(Error::Malformed.into());
            }
            let mut kinds = rss_mdm_policy_service::transaction::checked(
                self.reader.action_kinds_in(tx, policy.id).await?,
            )?;
            kinds.push(policy.definition.action.kind());
            kinds.extend(previous.map(|p| p.definition.action.kind()));
            let id = policy.id;
            if kinds.contains(&K::Software) || kinds.contains(&K::EnsureAgentInstalled) {
                rss_mdm_software_service::deployment::sources::storage::wake_execution_in(
                    &self.messaging,
                    tx,
                    id,
                )
                .await
                .map_err(software_fault)?;
            }
            if kinds.contains(&K::RequestMdmEnrollment) {
                rss_mdm_registration_service::enrollment::tasks::wake::policy_in(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    &self.messaging,
                    tx,
                    id,
                )
                .await
                .map_err(enrollment_fault)?;
            }
            if kinds.contains(&K::DeviceAccess) {
                rss_mdm_registration_service::device_access::execution::wake::policy_in(
                    &self.messaging,
                    tx,
                    id,
                )
                .await?;
            }
            if kinds.contains(&K::Credential) {
                rss_mdm_recovery_credentials::tasks::wake::policy_in(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    &self.messaging,
                    tx,
                    id,
                )
                .await?;
            }
            if kinds.contains(&K::Execution) {
                rss_mdm_script_service::wake::policy_in(&self.messaging, tx, id).await?;
            }
            if kinds.contains(&K::NativeCollection) || kinds.contains(&K::AgentCollection) {
                rss_mdm_inventory_service::collection::execution::wake::policy_in(
                    &self.messaging,
                    tx,
                    id,
                )
                .await?;
            }
            if kinds.contains(&K::UnmanageDevice) {
                rss_mdm_device_service::control::sources::storage::wake_execution_in(
                    &self.messaging,
                    tx,
                    id,
                )
                .await
                .map_err(fault)?;
            }
            Ok(())
        })
    }
    fn assignment_changed_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        version: Uuid,
        target: &'a rss_mdm_registration_service::device::endpoints::PrimaryRegistration,
        available: bool,
    ) -> Pending<'a, (), Fault> {
        Box::pin(async move {
            use rss_mdm_policy::ActionKind;
            let persisted = rss_mdm_policy_service::transaction::checked(
                self.reader.version_in(tx, version).await?,
            )?
            .ok_or(Error::NotFound)?;
            match persisted.action_kind {
                ActionKind::NativeCollection if !available => {
                    rss_mdm_inventory_service::collection::execution::wake::policy_in(&self.messaging, tx, persisted.policy).await?;
                }
                ActionKind::Software if !available => {
                    rss_mdm_software_service::deployment::sources::storage::wake_execution_in(&self.messaging, tx, persisted.policy).await.map_err(software_fault)?;
                }
                ActionKind::NativeCollection => {
                    if let Some(verified) = rss_mdm_inventory_service::collection::execution::scheduled::VerifiedNativeCollectionVersion::verify_in(&self.reader, tx, version).await? {
                        verified.wake_assignment_in(&self.messaging, tx, target).await?;
                    }
                }
                ActionKind::Software => {
                    if let Some(verified) = rss_mdm_software_service::deployment::actions::scheduled::VerifiedSoftwareVersion::verify_in(&self.reader, tx, version).await.map_err(software_fault)? {
                        verified.wake_assignment_in(&self.messaging, tx, target).await.map_err(software_fault)?;
                    }
                }
                _ => {}
            }
            Ok(())
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
            rss_mdm_device_service::control::wake::wake_native_batch_in(
                &self.messaging,
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
            rss_mdm_device_service::control::unmanage::wake_in(&self.messaging, tx, retirement)
                .await
                .map_err(fault)
        })
    }
}
pub(super) struct Events {
    pub software: Arc<rss_mdm_software_service::deployment::Transactions>,
    pub enrollment: Arc<rss_mdm_registration_service::enrollment::tasks::Transactions>,
    pub access: Arc<rss_mdm_registration_service::device_access::execution::Transactions>,
    pub credentials: Option<Arc<rss_mdm_recovery_credentials::tasks::Transactions>>,
    pub scripts: Arc<rss_mdm_script_service::Transactions>,
    pub collections: Arc<rss_mdm_inventory_service::collection::execution::Transactions>,
    pub configuration: Arc<rss_mdm_policy_service::configuration::Transactions>,
}

impl ExecutionEvents for Events {
    fn verify_event_device_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        principal: &'a rss_mdm_registration_service::DevicePrincipal,
        input: Option<&'a wire::PolicyEventRequest>,
    ) -> Pending<'a, (), Fault> {
        Box::pin(async move {
            if tx.tenant_id() != principal.tenant() {
                return Err(Error::Unauthorized.into());
            }
            let p = principal.clone();
            tx.with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        rss_mdm_registration_service::device::store::revalidate_source(
                            rss_mdm_install_support::StorageProfile::Mdm,
                            c,
                            &p,
                            rss_mdm_inventory::ReportSource::AgentBuiltin,
                        )
                        .await,
                    )
                })
            })
            .await??;
            let binding = rss_mdm_device_service::control::agent_facts::agent_binding_in(
                tx,
                Arc::new(super::agent_facts::AgentFacts),
                principal.registration(),
            )
            .await
            .map_err(fault)?;
            if !binding.is_some_and(|b| b.inventory() && b.task()) {
                return Err(Error::Forbidden.into());
            }
            if let Some(input) = input {
                input
                    .execution_context
                    .as_ref()
                    .ok_or(Error::Malformed)?
                    .validate()
                    .map_err(|_| Error::Malformed)?;
            }
            Ok(())
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
                Owner::Device => {
                    let run = rss_mdm_device_service::control::actions::storage::load_run(tx, id)
                        .await
                        .map_err(fault)?;
                    Ok(run.target.device == value.device
                        && run.target.registration == value.registration
                        && run.target.generation == value.generation
                        && run.state.execution == rss_mdm_task_state::Execution::Running
                        && run.state.started_at.is_some())
                }
                Owner::Software => self
                    .software
                    .event_parent_current_in(tx, &software_target(value), source)
                    .await
                    .map_err(software_fault),
                Owner::Access => self
                    .access
                    .event_parent_current_in(
                        tx,
                        &rss_mdm_registration_service::device_access::execution::Target {
                            device: value.device.clone(),
                            registration: value.registration,
                            generation: value.generation,
                        },
                        id,
                    )
                    .await
                    .map_err(Into::into),
                Owner::Credential => self
                    .credentials
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .event_parent_current_in(
                        tx,
                        &rss_mdm_recovery_credentials::tasks::Target {
                            device: value.device.clone(),
                            registration: value.registration,
                            generation: value.generation,
                        },
                        id,
                    )
                    .await
                    .map_err(Into::into),
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
                rss_mdm_policy::ActionKind::DeviceAccess => {
                    return self
                        .access
                        .accept_event_in(
                            tx,
                            policy,
                            &rss_mdm_registration_service::device_access::execution::Target {
                                device: value.device.clone(),
                                registration: value.registration,
                                generation: value.generation,
                            },
                            cause,
                            deadline,
                            audit,
                        )
                        .await
                        .map_err(Into::into);
                }
                rss_mdm_policy::ActionKind::Credential => {
                    return self
                        .credentials
                        .as_ref()
                        .ok_or(Error::Unsupported)?
                        .accept_event_in(
                            tx,
                            policy.version,
                            &rss_mdm_recovery_credentials::tasks::Target {
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
            // Unmanage events are admitted by Policy's lifecycle path before this port.
            Err(Error::Unsupported.into())
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
                    super::task_ownership::Owner::Access=>return Ok(EventOperationProgress::Run{reference:reference.clone(),state:rss_mdm_registration_service::device_access::execution::storage::read_run(tx,id).await?.state,allowed_actions:[]}),
                    super::task_ownership::Owner::Credential=>return Ok(EventOperationProgress::Run{reference:reference.clone(),state:rss_mdm_recovery_credentials::tasks::storage::read_run(rss_mdm_install_support::StorageProfile::Mdm, tx,id).await?.state,allowed_actions:[]}),
                    super::task_ownership::Owner::Registration => {
                        return Ok(EventOperationProgress::Run {
                            reference: reference.clone(),
                            state:
                                rss_mdm_registration_service::enrollment::tasks::storage::read_run(rss_mdm_install_support::StorageProfile::Mdm, tx, id,
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
                    super::task_ownership::Owner::Device => {}
                }
            }
            if let wire::PolicyEventOperation::Native { id } = reference {
                let owner = super::native_ownership::in_transaction(tx, *id).await?;
                if matches!(
                    owner,
                    super::native_ownership::Owner::Registration
                        | super::native_ownership::Owner::Recovery
                ) {
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
            Ok(match reference {
                wire::PolicyEventOperation::Run { id } => EventOperationProgress::Run {
                    reference: reference.clone(),
                    state: rss_mdm_device_service::control::actions::storage::read_run(tx, *id)
                        .await
                        .map_err(fault)?
                        .state,
                    allowed_actions: [],
                },
                wire::PolicyEventOperation::Native { id } => EventOperationProgress::Native {
                    reference: reference.clone(),
                    state: rss_mdm_device_service::control::storage::status_in(tx, *id)
                        .await
                        .map_err(fault)?,
                    agent_installation: None,
                    allowed_actions: [],
                },
                wire::PolicyEventOperation::Retirement { id } => {
                    let tenant = tx.tenant_id();
                    let id = *id;
                    let state = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(rss_mdm_device_service::lifecycle::read_in(c, tenant, id).await)
                            })
                        })
                        .await??;
                    EventOperationProgress::Retirement {
                        reference: reference.clone(),
                        state,
                        allowed_actions: [],
                    }
                }
            })
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
        E::Unsupported => Error::Unsupported,
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
