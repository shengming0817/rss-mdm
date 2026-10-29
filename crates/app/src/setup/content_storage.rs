//! Explicit installation-owner content maintenance; never an HTTP request's copy loop.
use super::{Error, Result};
use rss_mdm_audit_integration::{AuditIntent, AuditStore, Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_content_service::migration::{self, Phase, Receipt};
use rss_request_context::TenantId;
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub runtime_file: PathBuf,
    pub owner_database: crate::config::Database,
    pub operation_id: uuid::Uuid,
}
pub async fn maintain(input: Input) -> Result<Receipt> {
    let config: crate::config::Config =
        crate::config::load(&input.runtime_file).map_err(|_| Error::Input)?;
    if input.owner_database.user != "mdm_owner" || input.operation_id.is_nil() {
        return Err(Error::Input);
    }
    let tenant = TenantId::parse(&config.identity.tenant_id).map_err(|_| Error::Input)?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(6))
        .connect_with(input.owner_database.options().map_err(|_| Error::Input)?)
        .await
        .map_err(|_| Error::Storage)?;
    let result = async {
        let mut c = pool.acquire().await.map_err(|_| Error::Storage)?;
        if !crate::migration::owner_admitted(&mut c)
            .await
            .map_err(|_| Error::Storage)?
        {
            return Err(Error::Input);
        }
        crate::migration::verify_current_manifest(&mut c)
            .await
            .map_err(|_| Error::Conflict)?;
        crate::migration::verify_identity(
            &mut c,
            &crate::migration::Installation {
                instance_id: config.identity.instance_id.clone(),
                target: config.flow.storage.target,
                lineage: config.flow.storage.lineage,
                audit_mode: config.audit.mode(),
            },
        )
        .await
        .map_err(|_| Error::Conflict)?;
        drop(c);
        let source = rss_mdm_content_service::Store::open(
            config.native_protector().map_err(|_| Error::Input)?,
            config.content.as_ref().ok_or(Error::Input)?,
            &config.identity.tenant_id,
            Arc::new(crate::lifecycle::RuntimeTimer),
            pool.clone(),
        )
        .await
        .map_err(|_| Error::Conflict)?;
        let operation = migration::prepare(&source, input.operation_id)
            .await
            .map_err(|_| Error::Storage)?;
        if !matches!(operation.phase, Phase::Ready | Phase::Committed) {
            return Ok(operation);
        }
        let runtime = crate::identity::open_runtime(
            &config.access_database,
            &config.flow.storage.target,
            &config.flow.storage.lineage,
            &[(tenant, config.flow.storage.epoch)],
            crate::background::IDENTITY_CONNECTIONS,
        )
        .await
        .map_err(|_| Error::Storage)?;
        let audit_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(6))
            .connect_with(config.access_options().map_err(|_| Error::Input)?)
            .await
            .map_err(|_| Error::Storage)?;
        let result = async {
            let budget = AuditBudget::new(Duration::from_secs(6));
            let audit_store = AuditStore::new(
                audit_pool.clone(),
                config.audit.integrity().map_err(|_| Error::Input)?,
                runtime.clone(),
                tenant,
                &budget.control(),
            )
            .await
            .map_err(|_| Error::Storage)?;
            let audit = RequestAudit::new(
                tenant.to_string(),
                "storage_migration_commit",
                AuditIntent::Management,
            );
            audit.identify_service("content-storage-maintenance");
            audit.operation(
                input.operation_id,
                "storage_migration_commit",
                AuditIntent::Management,
            );
            let result = audit_store
                .write(
                    tenant,
                    &budget.source_control(),
                    (&audit_store, &audit, input.operation_id),
                    |(store, audit, operation), tx| {
                        Box::pin(async move {
                            let operation = *operation;
                            let (receipt, replayed) = tx
                                .with_connection(move |c| {
                                    Box::pin(async move {
                                        migration::cutover_on(c, tenant, operation)
                                            .await
                                            .map_err(rss_mdm_content_service::service::Error::from)
                                    })
                                })
                                .await?;
                            if !replayed {
                                let fact = Fact::business(
                                    audit,
                                    &format!("storage-migration-commit:{operation}"),
                                    200,
                                    "success",
                                    None,
                                )?;
                                store.append(tx, &fact).await?;
                            }
                            Ok::<_, rss_mdm_content_service::service::Error>(receipt)
                        })
                    },
                )
                .await;
            result.fold(
                Ok,
                |_| Err(Error::Storage),
                |_| Err(Error::Conflict),
                |_| Err(Error::Storage),
                |_| Err(Error::Storage),
                |_| Err(Error::Storage),
            )
        }
        .await;
        audit_pool.close().await;
        runtime.close().await;
        result
    }
    .await;
    pool.close().await;
    result
}
