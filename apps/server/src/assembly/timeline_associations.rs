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
                    if owner == Owner::Software {
                        return Ok(
                            rss_mdm_software_service::deployment::timeline::association_in(
                                c,
                                tenant,
                                actor,
                                rss_mdm_software_service::deployment::timeline::Identity::Operation(
                                    id,
                                ),
                            )
                            .await?,
                        );
                    }
                    if owner == Owner::Registration {
                        return Ok(rss_mdm_registration_service::installation::timeline::association_in(c,tenant,actor,rss_mdm_registration_service::installation::timeline::Identity::Operation(id)).await?);
                    }
                    if owner == Owner::Recovery {
                        return Ok(
                            rss_mdm_recovery_credentials::native::timeline::association_in(
                                c,
                                tenant,
                                actor,
                                rss_mdm_recovery_credentials::native::timeline::Identity::Operation(
                                    id,
                                ),
                            )
                            .await?,
                        );
                    }
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
                Identity::ActionRun(id) => {
                    let tenant_id = rss_request_context::TenantId::parse(tenant)
                        .map_err(|_| Error::Integrity)?;
                    use super::task_ownership::{self, Owner as TaskOwner};
                    let owner =
                        task_ownership::on(c, tenant_id, id)
                            .await
                            .map_err(|e| match e {
                                sqlx::Error::RowNotFound => Error::NotFound,
                                sqlx::Error::Protocol(_) => Error::Integrity,
                                _ => Error::Storage,
                            })?;
                    match owner {
                        TaskOwner::Script => return Ok(rss_mdm_script_service::storage::association_on(c, tenant, id).await?),
                        TaskOwner::Collection => return Ok(rss_mdm_inventory_service::collection::execution::storage::association_on(c, tenant, id).await?),
                        TaskOwner::Software=>return Ok(rss_mdm_software_service::deployment::timeline::association_in(c,tenant,actor,rss_mdm_software_service::deployment::timeline::Identity::ActionRun(id)).await?),
                        TaskOwner::Registration=>return Ok(rss_mdm_registration_service::enrollment::tasks::storage::association_on(c,tenant,id).await?),
                        TaskOwner::Access=>return Ok(rss_mdm_registration_service::device_access::execution::storage::association_on(c,tenant,id).await?),
                        TaskOwner::Credential=>return Ok(rss_mdm_recovery_credentials::tasks::storage::association_on(c,tenant,id).await?),
                        TaskOwner::Execution => execution::Identity::ActionRun(id),
                    }
                }
                Identity::ChangeRequest(id) => {
                    let mut associations = Vec::new();
                    associations.extend(
                        execution::association_in(
                            c,
                            tenant,
                            actor,
                            execution::Identity::ChangeRequest(id),
                        )
                        .await?,
                    );
                    associations.extend(
                        rss_mdm_software_service::deployment::timeline::association_in(
                            c,
                            tenant,
                            actor,
                            rss_mdm_software_service::deployment::timeline::Identity::ChangeRequest(
                                id,
                            ),
                        )
                        .await?,
                    );
                    associations.extend(rss_mdm_registration_service::installation::timeline::association_in(c,tenant,actor,rss_mdm_registration_service::installation::timeline::Identity::ChangeRequest(id)).await?);
                    associations.extend(
                        rss_mdm_recovery_credentials::native::timeline::association_in(
                            c,
                            tenant,
                            actor,
                            rss_mdm_recovery_credentials::native::timeline::Identity::ChangeRequest(
                                id,
                            ),
                        )
                        .await?,
                    );
                    return match associations.len() {
                        0 => Ok(None),
                        1 => Ok(associations.pop()),
                        _ => Err(Error::Integrity),
                    };
                }
            };
            Ok(execution::association_in(c, tenant, actor, identity).await?)
        })
    }
}
