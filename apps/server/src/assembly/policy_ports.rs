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
        E::Execution(_) | E::Publication(_) | E::CertificateRequest => {
            Error::Unavailable(Failure::PreparationContract)
        }
    }
}
pub(super) fn fault(e: rss_mdm_execution_service::transaction::Fault) -> Fault {
    match e {
        rss_mdm_execution_service::transaction::Fault::Request(e) => Fault::Request(error(e)),
        rss_mdm_execution_service::transaction::Fault::Storage(e) => Fault::Storage(e),
        rss_mdm_execution_service::transaction::Fault::Sql(e) => Fault::Sql(e),
    }
}
pub(super) struct Publication(pub Arc<rss_mdm_execution_service::Inputs>);
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
    fn prepare_resource<'a>(
        &'a self,
        action: &'a Action,
    ) -> Pending<'a, Option<rss_mdm_content_service::Verified>, Error> {
        Box::pin(async move {
            execution_action(action)?;
            self.0
                .prepare_resource(
                    rss_mdm_execution_service::input_preparation::PublicationInput::try_from(
                        action,
                    )
                    .map_err(error)?
                    .resource(),
                )
                .await
                .map_err(error)
        })
    }
    fn software_binding_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        action: &'a Action,
    ) -> Pending<'a, Option<[u8; 32]>, Fault> {
        Box::pin(async move { self.0.software_binding_in(tx, action).await.map_err(fault) })
    }
    fn publish_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        policy: &'a Policy,
        verified: Option<&'a rss_mdm_content_service::Verified>,
        proof: &'a AuthorizedPrincipal,
        snapshot: &'a Snapshot,
    ) -> Pending<'a, serde_json::Value, Fault> {
        Box::pin(async move {
            execution_action(&policy.definition.action)?;
            let input = rss_mdm_execution_service::input_preparation::PublicationInput::try_from(
                &policy.definition.action,
            )
            .map_err(error)?;
            let frozen = self
                .0
                .publish_in(
                    tx,
                    &input,
                    verified,
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
            rss_mdm_execution_service::wake::wake_policy_device_in(
                &self.messaging,
                tx,
                version,
                target,
            )
            .await
            .map_err(fault)
        })
    }
    fn devices_changed_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        devices: &'a [String],
    ) -> Pending<'a, (), Fault> {
        Box::pin(async move {
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
            self.execution
                .apply_event_context_in(tx, &target(value), context)
                .await
                .map_err(fault)
        })
    }
    fn event_parent_current_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        value: &'a Target,
        source: &'a wire::PolicyEventSource,
    ) -> Pending<'a, bool, Fault> {
        Box::pin(async move {
            self.execution
                .event_parent_current_in(tx, &target(value), source)
                .await
                .map_err(fault)
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
                    super::task_ownership::Owner::Execution => {}
                }
            }
            if let wire::PolicyEventOperation::Native { id } = reference {
                let owner = super::native_ownership::in_transaction(tx, *id).await?;
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
                        agent_installation,
                        allowed_actions,
                    } => EventOperationProgress::Native {
                        reference,
                        state,
                        agent_installation: agent_installation.map(installation),
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

fn installation(
    v: rss_mdm_execution_service::queries::records::InstallationObservation,
) -> InstallationObservation {
    let rss_mdm_execution_service::queries::records::InstallationObservation {
        bootstrap,
        protocol,
        delivery,
        installation,
        agent_registration,
        observed_at,
    } = v;
    InstallationObservation {
        bootstrap: bootstrap.map(bootstrap_observation),
        protocol,
        delivery,
        installation,
        agent_registration: agent_registration.map(agent_registration_observation),
        observed_at,
    }
}
fn bootstrap_observation(
    v: rss_mdm_execution_service::queries::records::BootstrapObservation,
) -> BootstrapObservation {
    let rss_mdm_execution_service::queries::records::BootstrapObservation {
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
fn agent_registration_observation(
    v: rss_mdm_execution_service::queries::records::AgentRegistration,
) -> AgentRegistration {
    let rss_mdm_execution_service::queries::records::AgentRegistration {
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
