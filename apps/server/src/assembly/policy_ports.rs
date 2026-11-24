//! Static mappings for the foreign capabilities consumed by Policy.
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_policy_service::events::participants::*;
use rss_mdm_policy_service::{Error, Failure, inputs::*, transaction::Fault};
use rss_transactional_messaging_postgres::PgTransaction;
use std::sync::Arc;
use uuid::Uuid;

pub(super) struct PolicyDependents(pub rss_reconcile_postgres::PgMessagingStore);
impl PublishedPolicyDependents for PolicyDependents {
    fn policy_changed_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        id: Uuid,
        kinds: &'a [rss_mdm_policy::ActionKind],
    ) -> Pending<'a, (), Fault> {
        Box::pin(async move {
            use rss_mdm_policy::ActionKind as K;
            if kinds.contains(&K::Software) || kinds.contains(&K::EnsureAgentInstalled) {
                rss_mdm_software_service::deployment::sources::storage::wake_execution_in(
                    &self.0, tx, id,
                )
                .await
                .map_err(Fault::from)?;
            }
            if kinds.contains(&K::RequestMdmEnrollment) {
                rss_mdm_registration_service::enrollment::tasks::wake::policy_in(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    &self.0,
                    tx,
                    id,
                )
                .await
                .map_err(Fault::from)?;
            }
            if kinds.contains(&K::Credential) {
                for profile in [
                    rss_mdm_install_support::StorageProfile::Mdm,
                    rss_mdm_install_support::StorageProfile::Da,
                ] {
                    rss_mdm_recovery_credentials::tasks::wake::policy_in(profile, &self.0, tx, id)
                        .await?;
                }
            }
            if kinds.contains(&K::Execution) {
                rss_mdm_script_service::wake::policy_in(&self.0, tx, id).await?;
            }
            if kinds.contains(&K::NativeCollection) || kinds.contains(&K::AgentCollection) {
                rss_mdm_inventory_service::collection::execution::wake::policy_in(&self.0, tx, id)
                    .await?;
            }
            if kinds.contains(&K::UnmanageDevice) {
                rss_mdm_device_service::control::sources::storage::wake_execution_in(
                    &self.0, tx, id,
                )
                .await
                .map_err(Fault::from)?;
            }
            Ok(())
        })
    }
}

pub(super) struct NativeDependents(pub Arc<rss_mdm_scope_service::channels::ChannelTargets>);
impl ConfigurationDependents for NativeDependents {
    fn configuration_progressed_in<'a>(
        &'a self,
        messaging: &'a rss_reconcile_postgres::PgMessagingStore,
        tx: &'a mut PgTransaction<'_>,
        devices: &'a [rss_mdm_agent_wire::DeviceId],
    ) -> Pending<'a, (), Fault> {
        Box::pin(async move {
            rss_mdm_software_service::deployment::wake::wake_native_batch_in(
                messaging,
                Arc::new(super::software_sources::Source(self.0.clone())),
                tx,
                devices,
            )
            .await
            .map_err(Fault::from)?;
            rss_mdm_device_service::control::wake::wake_native_batch_in(messaging, tx, devices)
                .await
                .map_err(Fault::from)
        })
    }
}

pub(super) struct OperationReads {
    pub members: Arc<MemberOwners>,
    pub configuration: Arc<rss_mdm_policy_service::configuration::Transactions>,
}

impl OperationOwners for OperationReads {
    fn event_parent_current_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        device: rss_mdm_agent_wire::DeviceId,
        id: Uuid,
    ) -> Pending<'a, bool, Fault> {
        Box::pin(async move {
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
                        .map_err(Fault::from)?;
                    Ok(run.target.device == device
                        && run.state.execution == rss_mdm_task_state::Execution::Running
                        && run.state.started_at.is_some())
                }
                Owner::Software => self.members
                    .software
                    .event_parent_current_in(tx, device, id)
                    .await
                    .map_err(Fault::from),
                Owner::Access => {
                                        tx.with_connection(move|c|Box::pin(async move{rss_mdm_device_access_postgres::device_access::execution::events::parent_current_on(c,&device,id).await})).await.map_err(Into::into)
                }
                Owner::Credential(profile) => self.members
                    .credentials
                    .iter()
                    .find(|s| s.profile() == profile)
                    .ok_or(Error::Unsupported)?
                    .event_parent_current_in(
                        tx,
                        &rss_mdm_recovery_credentials::tasks::Target {
                            device: device,
                        },
                        id,
                    )
                    .await
                    .map_err(Into::into),
                Owner::Registration => self.members
                    .enrollment
                    .event_parent_current_in(
                        tx,
                        &rss_mdm_registration_service::enrollment::tasks::Target {
                            device: device,
                        },
                        id,
                    )
                    .await
                    .map_err(Fault::from),
                Owner::Script => self.members
                    .scripts
                    .event_parent_current_in(
                        tx,
                        &rss_mdm_script_service::Target {
                            device: device,
                        },
                        id,
                    )
                    .await
                    .map_err(Into::into),
                Owner::Collection => self.members
                    .collections
                    .event_parent_current_in(
                        tx,
                        &rss_mdm_inventory_service::collection::execution::model::Target {
                            device: device,
                        },
                        id,
                    )
                    .await
                    .map_err(Into::into),
            }
        })
    }
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
                    super::task_ownership::Owner::Access=>return Ok(EventOperationProgress::Run{reference:reference.clone(),state:rss_mdm_device_access_postgres::device_access::execution::storage::read_run(tx,id).await.map_err(access_fault)?.state,allowed_actions:[]}),
                    super::task_ownership::Owner::Credential(profile)=>return Ok(EventOperationProgress::Run{reference:reference.clone(),state:rss_mdm_recovery_credentials::tasks::storage::read_run(profile, tx,id).await?.state,allowed_actions:[]}),
                    super::task_ownership::Owner::Registration => {
                        return Ok(EventOperationProgress::Run {
                            reference: reference.clone(),
                            state:
                                rss_mdm_registration_service::enrollment::tasks::storage::read_run(rss_mdm_install_support::StorageProfile::Mdm, tx, id,
                                )
                                .await
                                .map_err(Fault::from)?
                                .state,
                            allowed_actions: [],
                        });
                    }
                    super::task_ownership::Owner::Software => {
                        return self.members
                            .software
                            .policy_event_operation_in(tx, reference)
                            .await
                            .map(software_progress)
                            .map_err(Fault::from);
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
                        .members
                        .software
                        .policy_event_operation_in(tx, reference)
                        .await
                        .map(software_progress)
                        .map_err(Fault::from);
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
                        .map_err(Fault::from)?
                        .state,
                    allowed_actions: [],
                },
                wire::PolicyEventOperation::Native { id } => EventOperationProgress::Native {
                    reference: reference.clone(),
                    state: rss_mdm_device_service::control::storage::status_in(tx, *id)
                        .await
                        .map_err(Fault::from)?,
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
        state,
        capabilities,
    } = v;
    AgentRegistration {
        device_id,

        state,
        capabilities,
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

fn access_fault(
    e: rss_mdm_device_access_postgres::device_access::execution::transaction::Fault,
) -> Fault {
    use rss_mdm_device_access_postgres::device_access::execution::{
        Error as E, transaction::Fault as F,
    };
    match e {
        F::Storage(e) => Fault::Storage(e),
        F::Sql(e) => Fault::Sql(e),
        F::Request(e) => Fault::Request(match e {
            E::Malformed => Error::Malformed,
            E::Unsupported => Error::Unsupported,
            E::Unauthorized => Error::Unauthorized,
            E::Forbidden => Error::Forbidden,
            E::Conflict => Error::Conflict,
            E::NotFound => Error::NotFound,
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Audit(e) => Error::from(e.as_ref()),
            E::Invariant => Error::Unavailable(Failure::PreparationContract),
            E::Unavailable => Error::Unavailable(Failure::Preparation),
        }),
    }
}
