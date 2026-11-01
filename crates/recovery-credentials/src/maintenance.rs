//! Bounded rewrap and expiry are Recovery-owned mutations and audit in one transaction.
use crate::tasks::{Error, checked_input, transaction};
use crate::{
    Protection,
    cleanup::{CopyState, InputCopies},
    storage as materials,
};
use rss_mdm_audit_integration::{AuditStore, RequestAudit};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgRuntime;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
pub struct Maintenance {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    audit_store: Arc<AuditStore>,
    protection: Arc<Protection>,
    copies: Arc<dyn InputCopies>,
    budget: Arc<tokio::sync::Semaphore>,
}
impl Maintenance {
    pub fn new(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        audit_store: Arc<AuditStore>,
        protection: Arc<Protection>,
        copies: Arc<dyn InputCopies>,
        budget: Arc<tokio::sync::Semaphore>,
    ) -> Self {
        Self {
            runtime,
            tenant,
            audit_store,
            protection,
            copies,
            budget,
        }
    }
    pub async fn validate_keys(&self) -> Result<(), Error> {
        let tenant = Uuid::parse_str(&self.tenant.to_string()).map_err(|_| Error::Malformed)?;
        transaction::inspect(
            &self.runtime,
            self.tenant,
            self.protection.clone(),
            |protection, tx| {
                Box::pin(async move {
                    let keys = protection.keys.clone();
                    tx.with_connection(move |c| {
                        Box::pin(
                            async move { Ok(materials::validate_keys_in(c, tenant, &keys).await) },
                        )
                    })
                    .await??;
                    Ok(())
                })
            },
        )
        .await
    }
    pub fn registration(self: Arc<Self>) -> rss_runtime::ManagedTaskRegistration {
        let (task, _) = rss_runtime::ManagedTask::prepare(
            "recovery-credential-maintenance",
            Duration::from_secs(8),
        );
        task.into_registration(move|stop|async move{
   loop {if stop.is_cancelled(){break}
    if let Ok(_permit)=self.budget.try_acquire() && let Err(error)=self.run_once().await {eprintln!("{}",serde_json::json!({"event":"recovery_credential_maintenance_failed","reason":error.to_string()}));}
    tokio::select!{()=stop.cancelled()=>break,()=tokio::time::sleep(Duration::from_secs(60))=>{}}
   }Ok(())
  })
    }
    pub async fn run_once(&self) -> Result<(), Error> {
        let audit = RequestAudit::new(
            self.tenant.to_string(),
            "recovery_credential_maintenance",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("recovery-credentials");
        let result = transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            &audit,
            (self, &audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, audit) = *ctx;
                    let tenant = checked_input(Uuid::parse_str(&service.tenant.to_string()))?;
                    let keys = service.protection.keys.clone();
                    let prepared = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(materials::prepare_rewrap_in(c, tenant, &keys).await)
                            })
                        })
                        .await??;
                    let expired = tx
                        .with_connection(move |c| {
                            Box::pin(async move { Ok(materials::expired_in(c, tenant).await) })
                        })
                        .await??;
                    transaction::prepare_audit_in(&service.audit_store, tx, audit, &[]).await?;
                    let keys = service.protection.keys.clone();
                    let rewrapped = tx
                        .with_connection(move |c| {
                            Box::pin(
                                async move { Ok(materials::rewrap_in(c, prepared, &keys).await) },
                            )
                        })
                        .await??;
                    let mut changed = rewrapped > 0;
                    let mut remaining = 100;
                    for material in expired {
                        if remaining == 0 {
                            break;
                        }
                        let registration = material.binding.registration;
                        let id = material.id;
                        let version = material.version;
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                Ok(materials::cleanup_visited_in(c, tenant, id, version).await)
                            })
                        })
                        .await??;
                        changed = true;
                        let copies = tx
                            .with_connection(move |c| {
                                Box::pin(async move {
                                    Ok(materials::input_copies_in(c, tenant, registration).await)
                                })
                            })
                            .await??;
                        for operation in copies.into_iter().take(remaining) {
                            remaining -= 1;
                            if service.copies.purge_in(tx, operation).await? == CopyState::Purged {
                                tx.with_connection(move |c| {
                                    Box::pin(async move {
                                        Ok(materials::input_purged_in(c, tenant, operation).await)
                                    })
                                })
                                .await??;
                            }
                        }
                        if tx
                            .with_connection(move |c| {
                                Box::pin(async move {
                                    Ok(materials::inputs_remain_in(c, tenant, registration).await)
                                })
                            })
                            .await??
                        {
                            continue;
                        }
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                Ok(materials::clear_expired_in(c, tenant, id, version).await)
                            })
                        })
                        .await??;
                    }
                    if changed {
                        let fact = rss_mdm_audit_integration::Fact::business(
                            audit,
                            &format!("recovery:maintenance:{}", audit.request_id()),
                            200,
                            "success",
                            None,
                        )?;
                        service.audit_store.append_in(tx, &fact).await?;
                    }
                    Ok(())
                })
            },
        )
        .await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}
