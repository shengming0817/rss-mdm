//! Software management assembly on its own initiating runtime.
use crate::{Error, Failure, owner_storage::OwnerRuntime};
use rss_request_context::TenantId;
use std::sync::Arc;
pub(crate) async fn catalog(
    owner: &OwnerRuntime,
    tenant: TenantId,
    key: &[u8],
    clock: Arc<dyn crate::clock::Clock>,
    content: Option<Arc<rss_mdm_content_service::Store>>,
) -> Result<
    Arc<
        rss_mdm_software_service::management::catalog::Access<
            rss_mdm_content_service::software::SoftwareContent,
        >,
    >,
    Error,
> {
    owner
        .runtime
        .local_tx(tenant, crate::identity::deadline(), move |tx| {
            Box::pin(async move {
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        if !sqlx::query_scalar::<_, bool>(
                            rss_mdm_software_service::catalog::ADMISSION_SQL,
                        )
                        .fetch_one(&mut *c)
                        .await?
                        {
                            return Err(sqlx::Error::Protocol(
                                "owner storage admission rejected".into(),
                            ));
                        }
                        if !sqlx::query_scalar::<_, bool>(
                            rss_mdm_software_service::agent_packages::ADMISSION_SQL,
                        )
                        .fetch_one(&mut *c)
                        .await?
                        {
                            return Err(sqlx::Error::Protocol(
                                "Agent package storage admission rejected".into(),
                            ));
                        }
                        if !sqlx::query_scalar::<_, bool>(
                            rss_mdm_software_service::source_snapshots::ADMISSION_SQL,
                        )
                        .fetch_one(&mut *c)
                        .await?
                        {
                            return Err(sqlx::Error::Protocol(
                                "Software source snapshot admission rejected".into(),
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
    let resources = Arc::new(
        rss_mdm_resource_postgres::ResourceStore::new(
            owner.runtime.clone(),
            tenant,
            rss_mdm_resource_service::transaction::deadline(),
        )
        .await
        .map_err(|_| {
            Error::Resource(rss_mdm_resource_service::Error::Unavailable(
                rss_mdm_resource_service::Failure::ResourceAdmission,
            ))
        })?,
    );

    Ok(Arc::new(
        rss_mdm_software_service::management::catalog::Access {
            cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
                ring::hmac::HMAC_SHA256,
                &key,
            )),
            resources: resources.clone(),
            resource_writer: std::sync::Arc::new(crate::resource_assembly::SoftwareResources(
                rss_mdm_resource_service::software::SoftwareWriter::new(resources.clone()),
            )),
            clock: Arc::new(crate::clock::ContentClock(clock.clone())),
            runtime: owner.runtime.clone(),
            audit: owner.audit.clone(),
            tenant: tenant,
            catalog: rss_mdm_software_service::catalog::Catalog::new(
                owner.runtime.clone(),
                tenant,
                owner.audit.clone(),
            ),
            content: content.as_ref().map(|store| {
                Arc::new(rss_mdm_content_service::software::SoftwareContent::new(
                    store.clone(),
                    Arc::new(crate::clock::ContentClock(clock.clone())),
                ))
            }),
            imports: rss_mdm_software_service::management::catalog::ImportConfig {
                sources: content
                    .as_ref()
                    .map(|s| s.config.imports.clone())
                    .unwrap_or_default(),
                transfer_seconds: content.as_ref().map_or(0, |s| s.config.transfer_seconds),
            },
        },
    ))
}
