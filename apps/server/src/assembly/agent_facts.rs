//! Static mapping of Agent facts to their business consumers.
use rss_mdm_device_service::control::agent_facts::{Binding, Pending, Store};
use sqlx::PgConnection;
use uuid::Uuid;
pub(crate) struct AgentFacts;
fn error(e: rss_mdm_agent_channel::Error) -> rss_mdm_device_service::control::Error {
    use rss_mdm_agent_channel::Error as A;
    use rss_mdm_device_service::control::{Error as E, Failure};
    match e {
        A::Malformed => E::Malformed,
        A::Unauthorized => E::Unauthorized,
        A::Forbidden => E::Forbidden,
        A::Conflict => E::Conflict,
        A::CommitUnknown => E::CommitUnknown,
        A::RollbackFailed => E::RollbackFailed,
        _ => E::Unavailable(Failure::CommandStorage),
    }
}
impl Store for AgentFacts {
    fn bindings<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registrations: Vec<rss_mdm_agent_wire::DeviceId>,
    ) -> Pending<'a, std::collections::BTreeMap<rss_mdm_agent_wire::DeviceId, Binding>> {
        Box::pin(async move {
            Ok(
                rss_mdm_agent_channel::Bindings::new(rss_mdm_install_support::StorageProfile::Mdm)
                    .bindings(c, tenant, registrations)
                    .await
                    .map_err(error)?
                    .into_iter()
                    .map(|(id, b)| {
                        (
                            id,
                            Binding {
                                platform: b.platform,
                                architecture: b.architecture,
                                capabilities: b.capabilities,
                                execution_context: b.execution_context,
                            },
                        )
                    })
                    .collect(),
            )
        })
    }
    fn payload<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        run: Uuid,
        attempt: Uuid,
    ) -> Pending<'a, rss_mdm_agent_wire::runtime::TaskPayload> {
        Box::pin(async move {
            rss_mdm_agent_channel::delivery::payload(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                tenant,
                run,
                attempt,
            )
            .await
            .map_err(error)
        })
    }
    fn announcement<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, Option<rss_mdm_agent_wire::runtime::TaskClaimRequest>> {
        Box::pin(async move {
            rss_mdm_agent_channel::Bindings::new(rss_mdm_install_support::StorageProfile::Mdm)
                .announcement(c, tenant, registration)
                .await
                .map_err(error)
        })
    }
}

impl rss_mdm_script_service::agent_facts::Store for AgentFacts {
    fn bindings<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registrations: Vec<rss_mdm_agent_wire::DeviceId>,
    ) -> rss_mdm_script_service::agent_facts::Pending<
        'a,
        std::collections::BTreeMap<
            rss_mdm_agent_wire::DeviceId,
            rss_mdm_script_service::agent_facts::Binding,
        >,
    > {
        Box::pin(async move {
            Ok(
                rss_mdm_agent_channel::Bindings::new(rss_mdm_install_support::StorageProfile::Mdm)
                    .bindings(c, tenant, registrations)
                    .await
                    .map_err(script_error)?
                    .into_iter()
                    .map(|(id, b)| {
                        (
                            id,
                            rss_mdm_script_service::agent_facts::Binding {
                                platform: b.platform,
                                architecture: b.architecture,
                                capabilities: b.capabilities,
                                execution_context: b.execution_context,
                            },
                        )
                    })
                    .collect(),
            )
        })
    }
    fn payload<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        run: Uuid,
        attempt: Uuid,
    ) -> rss_mdm_script_service::agent_facts::Pending<'a, rss_mdm_agent_wire::runtime::TaskPayload>
    {
        Box::pin(async move {
            rss_mdm_agent_channel::delivery::payload(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                tenant,
                run,
                attempt,
            )
            .await
            .map_err(script_error)
        })
    }
    fn announcement<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: rss_mdm_agent_wire::DeviceId,
    ) -> rss_mdm_script_service::agent_facts::Pending<
        'a,
        Option<rss_mdm_agent_wire::runtime::TaskClaimRequest>,
    > {
        Box::pin(async move {
            rss_mdm_agent_channel::Bindings::new(rss_mdm_install_support::StorageProfile::Mdm)
                .announcement(c, tenant, registration)
                .await
                .map_err(script_error)
        })
    }
}

impl rss_mdm_inventory_service::collection::execution::agent_facts::Store for AgentFacts {
    fn bindings<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registrations: Vec<rss_mdm_agent_wire::DeviceId>,
    ) -> rss_mdm_inventory_service::collection::execution::agent_facts::Pending<
        'a,
        std::collections::BTreeMap<
            rss_mdm_agent_wire::DeviceId,
            rss_mdm_inventory_service::collection::execution::agent_facts::Binding,
        >,
    > {
        Box::pin(async move {
            Ok(
                rss_mdm_agent_channel::Bindings::new(rss_mdm_install_support::StorageProfile::Mdm)
                    .bindings(c, tenant, registrations)
                    .await
                    .map_err(collection_error)?
                    .into_iter()
                    .map(|(id, b)| {
                        (
                        id,
                        rss_mdm_inventory_service::collection::execution::agent_facts::Binding {
                            platform: b.platform,
                            architecture: b.architecture,
                            capabilities: b.capabilities,
                            execution_context: b.execution_context,
                        },
                    )
                    })
                    .collect(),
            )
        })
    }
    fn payload<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        run: Uuid,
        attempt: Uuid,
    ) -> rss_mdm_inventory_service::collection::execution::agent_facts::Pending<
        'a,
        rss_mdm_agent_wire::runtime::TaskPayload,
    > {
        Box::pin(async move {
            rss_mdm_agent_channel::delivery::payload(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                tenant,
                run,
                attempt,
            )
            .await
            .map_err(collection_error)
        })
    }
    fn announcement<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: rss_mdm_agent_wire::DeviceId,
    ) -> rss_mdm_inventory_service::collection::execution::agent_facts::Pending<
        'a,
        Option<rss_mdm_agent_wire::runtime::TaskClaimRequest>,
    > {
        Box::pin(async move {
            rss_mdm_agent_channel::Bindings::new(rss_mdm_install_support::StorageProfile::Mdm)
                .announcement(c, tenant, registration)
                .await
                .map_err(collection_error)
        })
    }
}

fn script_error(e: rss_mdm_agent_channel::Error) -> rss_mdm_script_service::Error {
    use rss_mdm_agent_channel::Error as A;
    use rss_mdm_script_service::Error as E;
    match e {
        A::Malformed => E::Malformed,
        A::Unauthorized => E::Unauthorized,
        A::Forbidden => E::Forbidden,
        A::Conflict => E::Conflict,
        A::NotFound => E::NotFound,
        A::CommitUnknown => E::CommitUnknown,
        A::RollbackFailed => E::RollbackFailed,
        _ => E::Unavailable,
    }
}
fn collection_error(e: rss_mdm_agent_channel::Error) -> rss_mdm_inventory_service::Error {
    use rss_mdm_agent_channel::Error as A;
    use rss_mdm_inventory_service::{Error as E, Failure};
    match e {
        A::Malformed => E::Malformed,
        A::Unauthorized => E::Unauthorized,
        A::Forbidden => E::Forbidden,
        A::Conflict => E::Conflict,
        A::NotFound => E::NotFound,
        A::CommitUnknown => E::CommitUnknown,
        A::RollbackFailed => E::RollbackFailed,
        _ => E::Unavailable(Failure::Protocol),
    }
}
