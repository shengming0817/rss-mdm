//! Content management borrows its own runtime and the established identity ports.
use crate::{Error, Failure, identity::Identity, owner_storage::OwnerRuntime};
use std::sync::Arc;
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
