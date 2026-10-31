use rss_mdm_timeline_service::{
    Error,
    associations::{Association, Associations, Identity},
};
use std::{future::Future, pin::Pin};
pub(crate) struct Producers;
impl Associations for Producers {
    fn association_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: &'a str,
        actor: &'a str,
        identity: Identity,
    ) -> Pin<Box<dyn Future<Output = Result<Association, Error>> + Send + 'a>> {
        Box::pin(async move {
            use super::native_ownership::{self, Owner};
            use rss_mdm_execution_service::timeline as execution;
            let identity = match identity {
                Identity::Operation(id) => {
                    let parsed = rss_request_context::TenantId::parse(tenant)
                        .map_err(|_| Error::Integrity)?;
                    let owner = native_ownership::on(c, parsed, id)
                        .await
                        .map_err(|e| match e {
                            rss_mdm_policy_service::Error::NotFound => Error::NotFound,
                            rss_mdm_policy_service::Error::Unavailable(
                                rss_mdm_policy_service::Failure::CommandInvariant,
                            ) => Error::Integrity,
                            _ => Error::Storage,
                        })?;
                    if owner == Owner::Configuration {
                        return Ok(
                            rss_mdm_policy_service::configuration::storage::association_on(
                                c, tenant, id,
                            )
                            .await?,
                        );
                    }
                    execution::Identity::Operation(id)
                }
                Identity::ActionRun(id) => execution::Identity::ActionRun(id),
                Identity::ChangeRequest(id) => execution::Identity::ChangeRequest(id),
            };
            Ok(execution::association_in(c, tenant, actor, identity).await?)
        })
    }
}
