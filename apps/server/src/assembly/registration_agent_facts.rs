//! Static mapping of Agent facts to their business consumers.
use rss_mdm_registration_service::enrollment::tasks::agent_facts::{Binding, Pending, Store};
use sqlx::PgConnection;
use uuid::Uuid;
pub(crate) struct AgentFacts;
fn error(
    e: rss_mdm_agent_channel::Error,
) -> rss_mdm_registration_service::enrollment::tasks::Error {
    use rss_mdm_agent_channel::Error as A;
    use rss_mdm_registration_service::enrollment::tasks::Error as E;
    match e {
        A::Malformed => E::Malformed,
        A::Unauthorized => E::Unauthorized,
        A::Forbidden => E::Forbidden,
        A::Conflict => E::Conflict,
        A::CommitUnknown => E::CommitUnknown,
        A::RollbackFailed => E::RollbackFailed,
        _ => E::Unavailable,
    }
}
impl Store for AgentFacts {
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
                            platform: b.platform,
                            architecture: b.architecture,
                            capabilities: b.capabilities,
                            execution_context: b.execution_context,
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
}
