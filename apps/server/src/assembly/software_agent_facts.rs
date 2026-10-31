//! Static mapping of Agent facts to their business consumers.
use rss_mdm_software_service::deployment::agent_facts::{Binding, Pending, Store};
use sqlx::PgConnection;
use uuid::Uuid;
pub(crate) struct AgentFacts;
fn error(e: rss_mdm_agent_channel::Error) -> rss_mdm_software_service::deployment::Error {
    use rss_mdm_agent_channel::Error as A;
    use rss_mdm_software_service::deployment::{Error as E, Failure};
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
    fn update_context<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        context: &'a rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            rss_mdm_agent_channel::Bindings
                .update_context(c, tenant, registration, context)
                .await
                .map_err(error)
        })
    }
    fn bindings<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registrations: Vec<Uuid>,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, Binding>> {
        Box::pin(async move {
            Ok(rss_mdm_agent_channel::Bindings
                .bindings(c, tenant, registrations)
                .await
                .map_err(error)?
                .into_iter()
                .map(|(id, b)| {
                    (
                        id,
                        Binding {
                            execution_context: b.execution_context,
                            platform: b.platform,
                            architecture: b.architecture,
                            capabilities: b.capabilities,
                        },
                    )
                })
                .collect())
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
            rss_mdm_agent_channel::delivery::payload(c, tenant, run, attempt)
                .await
                .map_err(error)
        })
    }
    fn announcement<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
    ) -> Pending<'a, Option<rss_mdm_agent_wire::runtime::TaskClaimRequest>> {
        Box::pin(async move {
            rss_mdm_agent_channel::Bindings
                .announcement(c, tenant, registration)
                .await
                .map_err(error)
        })
    }
}
