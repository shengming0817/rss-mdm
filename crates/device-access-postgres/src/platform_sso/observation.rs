use crate::{Error, Pending};
use sqlx::PgConnection;
pub struct Observation;
impl crate::device_access::participants::PlatformFacts for Observation {
    fn platform_sso_observation<'a>(
        &'a self,
        c: &'a mut PgConnection,
        binding: &'a crate::device_access::Binding,
        facts: &'a rss_mdm_agent_wire::runtime::AccessMacPlatformSsoFacts,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            let binding = serde_json::to_value(binding).map_err(|_| Error::Malformed)?;
            sqlx::query_scalar("SELECT rss_da.platform_registration_matches($1,$2,$3)")
                .bind(facts.user_source_id)
                .bind(facts.user_source_version)
                .bind(binding)
                .fetch_one(c)
                .await
                .map_err(crate::database::db)
        })
    }
}
