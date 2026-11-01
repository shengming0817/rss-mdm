//! Content management borrows its own runtime and the established identity ports.
use crate::{Error, Failure, identity::Identity, owner_storage::OwnerRuntime};
use std::{sync::Arc, time::Duration};
pub(crate) struct Resource(pub Arc<rss_mdm_content_service::Store>);
impl rss_runtime::ManagedResource for Resource {
    fn name(&self) -> &str {
        "content-store"
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.0.close().await;
        Ok(())
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}
pub(crate) async fn open(
    config: &crate::config::Config,
    protection: Arc<rss_mdm_native_protection::Protector>,
) -> std::result::Result<Option<Arc<rss_mdm_content_service::Store>>, Error> {
    let Some(c) = config.content.as_ref() else {
        return Ok(None);
    };
    let bad = || Error::Configuration(crate::ConfigIssue::Content);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(crate::background::CONTENT_CONNECTIONS)
        .acquire_timeout(Duration::from_secs(6))
        .connect_with(config.business_databases.content.options()?)
        .await
        .map_err(|_| bad())?;
    match rss_mdm_content_service::Store::open(
        protection,
        c,
        &config.identity.tenant_id,
        Arc::new(crate::lifecycle::RuntimeTimer),
        pool.clone(),
    )
    .await
    {
        Ok(store) => Ok(Some(store)),
        Err(e) => {
            pool.close().await;
            Err(e.into())
        }
    }
}

pub(crate) async fn access(
    owner: &OwnerRuntime,
    identity: &Identity,
    authorization: Arc<rss_mdm_authorization_service::Store>,
    content: Arc<rss_mdm_content_service::Store>,
    clock: Arc<dyn crate::clock::Clock>,
) -> Result<Arc<rss_mdm_content_service::service::Access>, Error> {
    let tenant = identity.tenant;
    owner
        .runtime
        .local_tx(tenant, crate::identity::deadline(), move |tx| {
            Box::pin(async move {
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        if !sqlx::query_scalar::<_, bool>(rss_mdm_content_service::ADMISSION_SQL)
                            .fetch_one(&mut *c)
                            .await?
                        {
                            return Err(sqlx::Error::Protocol(
                                "owner storage admission rejected".into(),
                            ));
                        }
                        Ok(())
                    })
                })
                .await
            })
        })
        .await
        .fold(
            Ok,
            |_| Err(Error::Unavailable(Failure::Database)),
            |_| Err(Error::Unavailable(Failure::Database)),
            |_| Err(Error::RollbackFailed),
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::Unavailable(Failure::Database)),
        )?;
    Ok(Arc::new(rss_mdm_content_service::service::Access {
        sessions: rss_mdm_authorization_service::session::SessionAuthority::new(
            identity.authority.clone(),
            identity.tenant,
        ),
        authorization,
        runtime: owner.runtime.clone(),
        audit_store: owner.audit.clone(),
        tenant: identity.tenant,
        content: Some(content),
        clock: Arc::new(crate::clock::ContentClock(clock)),
        catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(
            identity.tenant,
        )),
    }))
}
