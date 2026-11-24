//! Static mappings for the foreign capabilities consumed by Policy.
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_device_access_postgres::device_access::execution::events as access_events;
use rss_mdm_device_service::control::actions as device_actions;
use rss_mdm_policy_service::events::participants::*;
use rss_mdm_policy_service::{Error, Failure, inputs::*, transaction::Fault};
use rss_mdm_recovery_credentials::tasks::events as credential_events;
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
            Ok(match owner {
                Owner::Device => device_actions::event_parent_current_in(tx, device, id).await?,
                Owner::Access => {
                    tx.with_connection(move |c| {
                        Box::pin(
                            async move { access_events::parent_current_on(c, &device, id).await },
                        )
                    })
                    .await?
                }
                Owner::Software => {
                    self.members
                        .software
                        .event_parent_current_in(tx, device, id)
                        .await?
                }
                Owner::Registration => {
                    self.members
                        .enrollment
                        .event_parent_current_in(tx, device, id)
                        .await?
                }
                Owner::Credential(profile) => {
                    self.members
                        .credentials(profile)?
                        .event_parent_current_in(tx, device, id)
                        .await?
                }
                Owner::Script => {
                    self.members
                        .scripts
                        .event_parent_current_in(tx, device, id)
                        .await?
                }
                Owner::Collection => {
                    self.members
                        .collections
                        .event_parent_current_in(tx, device, id)
                        .await?
                }
            })
        })
    }
    fn policy_event_operation_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        reference: &'a wire::PolicyEventOperation,
    ) -> Pending<'a, EventOperationProgress, Fault> {
        Box::pin(async move {
            Ok(match *reference {
                wire::PolicyEventOperation::Run { id } => {
                    use super::task_ownership::Owner;
                    use rss_mdm_inventory_service::collection::execution::events::EventProgress;
                    let tenant = tx.tenant_id();
                    let owner = tx
                        .with_connection(move |c| {
                            Box::pin(super::task_ownership::on(c, tenant, id))
                        })
                        .await?;
                    let state = match owner {
                        Owner::Script => self.members.scripts.event_progress_in(tx, id).await?,
                        Owner::Collection => {
                            match self.members.collections.event_progress_in(tx, id).await? {
                                EventProgress::Agent(state) => state,
                                EventProgress::Native(state) => {
                                    return Ok(EventOperationProgress::Collection {
                                        reference: reference.clone(),
                                        state,
                                        allowed_actions: [],
                                    });
                                }
                            }
                        }
                        Owner::Credential(profile) => {
                            credential_events::event_progress_in(profile, tx, id).await?
                        }
                        Owner::Registration => {
                            self.members.enrollment.event_progress_in(tx, id).await?
                        }
                        Owner::Software => self.members.software.run_progress_in(tx, id).await?,
                        Owner::Device => device_actions::event_progress_in(tx, id).await?,
                        Owner::Access => access_events::event_progress_in(tx, id)
                            .await
                            .map_err(access_fault)?,
                    };
                    EventOperationProgress::Run {
                        reference: reference.clone(),
                        state,
                        allowed_actions: [],
                    }
                }
                wire::PolicyEventOperation::Native { id } => {
                    use super::native_ownership::Owner;
                    let (state, agent_installation) =
                        match super::native_ownership::in_transaction(tx, id).await? {
                            Owner::Registration | Owner::Recovery => {
                                return Err(Error::Forbidden.into());
                            }
                            Owner::Configuration => {
                                return self.configuration.event_progress_in(tx, reference).await;
                            }
                            Owner::Software => {
                                let progress =
                                    self.members.software.native_progress_in(tx, id).await?;
                                (progress.state, progress.installation)
                            }
                            Owner::Device => (
                                rss_mdm_device_service::control::storage::status_in(tx, id).await?,
                                None,
                            ),
                        };
                    EventOperationProgress::Native {
                        reference: reference.clone(),
                        state,
                        agent_installation,
                        allowed_actions: [],
                    }
                }
                wire::PolicyEventOperation::Retirement { id } => {
                    let tenant = tx.tenant_id();
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
