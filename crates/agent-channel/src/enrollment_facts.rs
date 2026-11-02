//! Static mapping of Agent facts to their business consumers.
use rss_mdm_registration_service::participants::agent::{Binding, Pending, Store};
use sqlx::PgConnection;
use uuid::Uuid;
pub struct EnrollmentFacts {
    profile: rss_mdm_install_support::StorageProfile,
}
impl EnrollmentFacts {
    pub fn new(profile: rss_mdm_install_support::StorageProfile) -> Self {
        Self { profile }
    }
}
fn error(e: crate::Error) -> rss_mdm_registration_service::participants::Error {
    use crate::Error as A;
    use rss_mdm_registration_service::participants::Error as E;
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
impl Store for EnrollmentFacts {
    fn storage_profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    fn bindings<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registrations: Vec<Uuid>,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, Binding>> {
        Box::pin(async move {
            Ok(crate::Bindings::new(self.profile)
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
            crate::delivery::payload(self.profile, c, tenant, run, attempt)
                .await
                .map_err(error)
        })
    }
}

/// Host-installed Agent snapshot for the DA enterprise broker.
pub const DA_BROKER_QUERY: &str =
    rss_mdm_device_access_postgres::broker_release_query!(include_str!("current-sessions.sql"));
