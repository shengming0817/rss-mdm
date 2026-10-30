//! Execution owns device-source consumption; Scope has its own independent checkpoint.
use crate::transaction::*;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use std::sync::Arc;
pub async fn pending_in(
    tx: &mut PgTransaction<'_>,
    source: Arc<dyn crate::source_authority::SourceAuthority>,
) -> Result<bool> {
    let source_tenant = tx.tenant_id();
    let revision = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(source.object_change_head_on(c, source_tenant).await) })
        })
        .await?
        .map_err(crate::Error::from)?;
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move |c|Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT mdm.asset_visible((SELECT from_cut FROM mdm_commands.device_source_dispatch WHERE tenant_id=$1::uuid),revision)) OR $2>coalesce((SELECT relation_consumed FROM mdm_commands.device_source_dispatch WHERE tenant_id=$1::uuid),0)").bind(tenant).bind(revision).fetch_one(c).await
    })).await?)
}
pub async fn advance_in(
    tx: &mut PgTransaction<'_>,
    messaging: &rss_reconcile_postgres::PgMessagingStore,
    source: Arc<dyn crate::source_authority::SourceAuthority>,
    candidate: &rss_mdm_inventory::AssetCut,
) -> Result<()> {
    tx.with_connection(|c| Box::pin(verify_storage(c))).await?;
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_commands.device_source_dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(&tenant).execute(&mut *c).await?;
        sqlx::query("SELECT from_cut,to_cut,event_after,page_through,cursor FROM mdm_commands.device_source_dispatch WHERE tenant_id=$1::uuid FOR UPDATE").bind(tenant).fetch_one(c).await
    })).await?;
    let from: Option<serde_json::Value> = row.try_get("from_cut")?;
    let to: serde_json::Value = row
        .try_get::<Option<serde_json::Value>, _>("to_cut")?
        .unwrap_or_else(|| candidate.to_json());
    let after: i64 = row.try_get("event_after")?;
    let cursor: Option<String> = row.try_get("cursor")?;
    let through = match row.try_get::<Option<i64>, _>("page_through")? {
        Some(value) => Some(value),
        None => {
            let tenant = tx.tenant_id().to_string();
            let f = from.clone();
            let t = to.clone();
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query_scalar::<_,Option<i64>>("SELECT max(revision) FROM (SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT mdm.asset_visible($2,revision) AND mdm.asset_visible($3,revision) AND revision>$4 ORDER BY revision LIMIT 1000) page")
                    .bind(tenant).bind(f).bind(t).bind(after).fetch_one(c).await
            })).await?
        }
    };
    let Some(through) = through else {
        let tenant = tx.tenant_id().to_string();
        tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("UPDATE mdm_commands.device_source_dispatch SET from_cut=$2,to_cut=NULL,event_after=0,page_through=NULL,cursor=NULL WHERE tenant_id=$1::uuid").bind(tenant).bind(to).execute(c).await?;Ok(())
        })).await?;
        return relation_page_in(tx, messaging, source).await;
    };
    let tenant = tx.tenant_id().to_string();
    let frozen = to.clone();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("UPDATE mdm_commands.device_source_dispatch SET to_cut=$2,page_through=$3 WHERE tenant_id=$1::uuid").bind(tenant).bind(frozen).bind(through).execute(c).await?;Ok(())
    })).await?;
    let tenant = tx.tenant_id().to_string();
    let devices=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar::<_,String>(r#"WITH changed AS (
            SELECT DISTINCT coalesce(a.identity->>'device',(SELECT h.device FROM mdm_access.asset_authority_history h WHERE h.tenant_id=a.tenant_id AND h.kind='registration' AND h.identity=a.identity->>'registration' ORDER BY h.revision DESC LIMIT 1)) COLLATE "C" AS device
            FROM mdm.asset_changes a WHERE a.tenant_id=$1::uuid AND NOT mdm.asset_visible($2,a.revision) AND mdm.asset_visible($3,a.revision) AND a.revision>$4 AND a.revision<=$5
            AND (a.kind IN('device','registration','source','credential') OR 'channel.agent.installation'=ANY(a.fields))
        ) SELECT device FROM changed WHERE device IS NOT NULL AND ($6::text IS NULL OR device>$6 COLLATE "C") ORDER BY device COLLATE "C" LIMIT 33"#)
            .bind(tenant).bind(from).bind(to).bind(after).bind(through).bind(cursor).fetch_all(c).await
    })).await?;
    crate::wake::wake_native_batch_in(
        messaging,
        source.clone(),
        tx,
        &devices[..devices.len().min(32)],
    )
    .await?;
    let more = devices.len() > 32;
    let next = more.then(|| devices[31].clone());
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("UPDATE mdm_commands.device_source_dispatch SET event_after=$2,page_through=$3,cursor=$4 WHERE tenant_id=$1::uuid")
            .bind(tenant).bind(if more {after}else{through}).bind(more.then_some(through)).bind(next).execute(c).await?;Ok(())
    })).await?;
    relation_page_in(tx, messaging, source).await
}
pub async fn health_in(tx: &mut PgTransaction<'_>) -> Result<(u64, bool, bool)> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query_as::<_,(i64,bool,Option<String>)>("SELECT event_after,to_cut IS NOT NULL,failure FROM mdm_commands.device_source_dispatch WHERE tenant_id=$1::uuid").bind(tenant).fetch_optional(c).await
    })).await?;
    Ok(row.map_or((0, false, false), |(position, open, f)| {
        (position as u64, open, f.is_some())
    }))
}
pub async fn clear_failure_in(tx: &mut PgTransaction<'_>) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move {sqlx::query("UPDATE mdm_commands.device_source_dispatch SET failure=NULL WHERE tenant_id=$1::uuid AND failure IS NOT NULL").bind(tenant).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub async fn fail_in(
    tx: &mut PgTransaction<'_>,
    audit_store: &rss_mdm_audit_integration::AuditStore,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let generation=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query_scalar::<_,i64>("INSERT INTO mdm_commands.device_source_dispatch(tenant_id,failure,failure_generation) VALUES($1::uuid,'automation_suspended',1) ON CONFLICT(tenant_id) DO UPDATE SET failure=excluded.failure,failure_generation=device_source_dispatch.failure_generation+1 WHERE device_source_dispatch.failure IS NULL RETURNING failure_generation").bind(tenant).fetch_optional(c).await
    })).await?;
    if let Some(generation) = generation {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            tx.tenant_id().to_string(),
            "automation_failed",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("service:execution-inputs");
        audit.target("asset_ingress");
        let fact = rss_mdm_audit_integration::Fact::business(
            &audit,
            &format!("device-ingress:{generation}:failed"),
            200,
            "failed",
            None,
        )?;
        audit_store.append_in(tx, &fact).await?;
        audit.finalize(None);
    }
    Ok(())
}
pub async fn verify_storage(c: &mut sqlx::PgConnection) -> std::result::Result<(), sqlx::Error> {
    let valid: bool = sqlx::query_scalar(include_str!("source-changes-admission.sql"))
        .fetch_one(c)
        .await?;
    if !valid {
        return Err(sqlx::Error::Protocol(
            "Execution input checkpoint rejected".into(),
        ));
    }
    Ok(())
}

async fn relation_page_in(
    tx: &mut PgTransaction<'_>,
    messaging: &rss_reconcile_postgres::PgMessagingStore,
    source: Arc<dyn crate::source_authority::SourceAuthority>,
) -> Result<()> {
    let tenant = tx.tenant_id();
    let t = tenant.to_string();
    let (consumed,mut watermark,mut cursor):(i64,i64,Option<i64>)=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_as("SELECT relation_consumed,relation_watermark,relation_cursor FROM mdm_commands.device_source_dispatch WHERE tenant_id=$1::uuid FOR UPDATE").bind(t).fetch_one(c).await
    })).await?;
    if consumed == watermark {
        let reader = source.clone();
        watermark = tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(reader.object_change_head_on(c, tenant).await) })
            })
            .await?
            .map_err(crate::Error::from)?;
        cursor = None;
    }
    if watermark < consumed {
        return Err(crate::Error::Conflict.into());
    }
    if watermark == consumed {
        return Ok(());
    }
    let reader = source.clone();
    let after = cursor.unwrap_or(consumed);
    let changes = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(reader
                    .object_changes_on(c, tenant, after, watermark, 64)
                    .await)
            })
        })
        .await?
        .map_err(crate::Error::from)?;
    let position = changes.last().map_or(watermark, |c| c.position);
    let finished = changes.len() < 64 || position == watermark;
    let devices = changes
        .into_iter()
        .flat_map(|c| c.old_devices.into_iter().chain(c.new_devices))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    crate::wake::wake_native_batch_in(messaging, source, tx, &devices).await?;
    let t = tenant.to_string();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("UPDATE mdm_commands.device_source_dispatch SET relation_consumed=$2,relation_watermark=$3,relation_cursor=$4 WHERE tenant_id=$1::uuid").bind(t).bind(if finished{watermark}else{consumed}).bind(watermark).bind((!finished).then_some(position)).execute(c).await?;Ok(())
    })).await?;
    Ok(())
}

/// The Execution input target shares the existing owner runner and store.
pub fn target(tenant: rss_request_context::TenantId) -> rss_reconcile::Target {
    rss_reconcile::Target::new(crate::recovery_scope(tenant), "inputs").expect("input target")
}

/// Committed input progress; an absent row is initial progress, not a storage failure.
#[derive(Clone, Copy, Debug)]
pub struct IngressHealth {
    pub event_after: u64,
    pub window_open: bool,
    pub suspended: bool,
}
impl crate::ExecutionService {
    pub async fn ingress_health(
        &self,
        cutoff: std::time::Instant,
    ) -> std::result::Result<IngressHealth, crate::Error> {
        self.transactions
            .runtime
            .local_tx(self.transactions.tenant, health_deadline(cutoff), |tx| {
                Box::pin(async move {
                    health_in(tx)
                        .await
                        .map(|(event_after, window_open, suspended)| IngressHealth {
                            event_after,
                            window_open,
                            suspended,
                        })
                        .map_err(input_fault)
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(crate::Error::Unavailable(crate::Failure::CommandStorage)),
                |_| Err(crate::Error::Unavailable(crate::Failure::CommandStorage)),
                |_| Err(crate::Error::RollbackFailed),
                |_| Err(crate::Error::CommitUnknown),
                |_| Err(crate::Error::Conflict),
            )
    }
    pub async fn input_pending_count(
        &self,
        cutoff: std::time::Instant,
    ) -> std::result::Result<u64, crate::Error> {
        self.transactions.runtime.local_tx(self.transactions.tenant, health_deadline(cutoff), |tx| Box::pin(async move {
            let tenant=tx.tenant_id().to_string();
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar::<_, i64>("SELECT count(*) FROM (SELECT 1 FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT mdm.asset_visible((SELECT from_cut FROM mdm_commands.device_source_dispatch WHERE tenant_id=$1::uuid),revision) LIMIT 1001) q").bind(tenant).fetch_one(c).await
            })).await
        })).await.fold(|v|Ok(v as u64), |_| Err(crate::Error::Unavailable(crate::Failure::CommandStorage)), |_| Err(crate::Error::Unavailable(crate::Failure::CommandStorage)), |_| Err(crate::Error::RollbackFailed), |_| Err(crate::Error::CommitUnknown), |_| Err(crate::Error::Conflict))
    }
    pub(crate) async fn apply_inputs<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<rss_reconcile::ReconcileStep<()>, rss_reconcile::Error> {
        if claim.target() != &target(self.transactions.tenant) {
            return Err(rss_reconcile::Error::new(
                rss_reconcile::ErrorKind::Invariant,
            ));
        }
        control.check()?;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(control.remaining());
        let candidate = rss_mdm_inventory_service::assets::cut::capture(
            &self.transactions.audit_store,
            self.transactions.tenant,
            &budget,
        )
        .await
        .map_err(|_| {
            input_error(sqlx::Error::Protocol("asset input capture failed".into()).into())
        })?;
        self.transactions
            .runtime
            .local_tx_with_context(
                self.transactions.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (self, claim, &candidate),
                |(s, claim, candidate), tx| {
                    Box::pin(async move {
                        s.transactions
                            .audit_store
                            .bind_in(tx)
                            .await
                            .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                        s.transactions
                            .reconcile_messaging
                            .protect_in(tx, claim, (s, *candidate), |(s, candidate), tx| {
                                Box::pin(async move {
                                    advance_in(
                                        tx,
                                        &s.transactions.reconcile_messaging,
                                        s.transactions.source.clone(),
                                        candidate,
                                    )
                                    .await
                                    .map_err(input_fault)?;
                                    clear_failure_in(tx)
                                        .await
                                        .map(rss_reconcile_postgres::ProtectedStep::Ready)
                                        .map_err(input_fault)
                                })
                            })
                            .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(input_error(e)),
                |e| Err(input_error(e)),
                |_| {
                    Err(rss_reconcile::Error::new(
                        rss_reconcile::ErrorKind::RollbackFailed,
                    ))
                },
                |_| {
                    Err(rss_reconcile::Error::new(
                        rss_reconcile::ErrorKind::CommitUnknown,
                    ))
                },
                |e| Err(input_error(e)),
            )
    }
    pub(crate) async fn settle_inputs<T: rss_reconcile::Timer>(
        &self,
        claim: &rss_reconcile_postgres::PgClaim,
        completion: rss_reconcile::Completion,
        control: &rss_reconcile::Control<'_, T>,
    ) -> std::result::Result<rss_reconcile::ReconcileStep<()>, rss_reconcile::Error> {
        if !matches!(
            completion,
            rss_reconcile::Completion::Converged | rss_reconcile::Completion::Suspended { .. }
        ) {
            return Ok(rss_reconcile::ReconcileStep::Ready(()));
        }
        self.transactions
            .runtime
            .local_tx_with_context(
                self.transactions.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    control.remaining(),
                ),
                (self, claim),
                |(s, claim), tx| {
                    Box::pin(async move {
                        s.transactions
                            .audit_store
                            .bind_in(tx)
                            .await
                            .map_err(rss_transactional_messaging_postgres::PgError::from)?;
                        s.transactions
                            .reconcile_messaging
                            .protect_in(tx, claim, s, |s, tx| {
                                Box::pin(async move {
                                    if completion == rss_reconcile::Completion::Converged {
                                        clear_failure_in(tx)
                                            .await
                                            .map(rss_reconcile_postgres::ProtectedStep::Ready)
                                            .map_err(input_fault)
                                    } else {
                                        fail_in(tx, &s.transactions.audit_store)
                                            .await
                                            .map(rss_reconcile_postgres::ProtectedStep::Ready)
                                            .map_err(input_fault)
                                    }
                                })
                            })
                            .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(input_error(e)),
                |e| Err(input_error(e)),
                |_| {
                    Err(rss_reconcile::Error::new(
                        rss_reconcile::ErrorKind::RollbackFailed,
                    ))
                },
                |_| {
                    Err(rss_reconcile::Error::new(
                        rss_reconcile::ErrorKind::CommitUnknown,
                    ))
                },
                |e| Err(input_error(e)),
            )
    }
}
fn input_fault(error: crate::transaction::Fault) -> rss_transactional_messaging_postgres::PgError {
    match error {
        crate::transaction::Fault::Storage(e) => e,
        crate::transaction::Fault::Sql(e) => e.into(),
        crate::transaction::Fault::Request(_) => {
            sqlx::Error::Protocol("Execution input rejected".into()).into()
        }
    }
}
fn input_error(error: rss_transactional_messaging_postgres::PgError) -> rss_reconcile::Error {
    rss_reconcile::Error::new(
        if error.kind() == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost {
            rss_reconcile::ErrorKind::Fenced
        } else {
            rss_reconcile::ErrorKind::Transient
        },
    )
}
#[allow(
    clippy::disallowed_methods,
    reason = "monotonic input health read budget"
)]
fn health_deadline(
    cutoff: std::time::Instant,
) -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        cutoff.saturating_duration_since(std::time::Instant::now()),
    )
}
