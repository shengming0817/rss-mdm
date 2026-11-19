//! Only expired protocol sessions and cached responses are disposable; I01 and audit facts remain.
//! ref: PostgreSQL 17 SELECT FOR UPDATE SKIP LOCKED; sqlx 0.9 Transaction rollback-on-drop.
use crate::{Error, database::db};
use rss_runtime::{ManagedTask, ManagedTaskRegistration};
use sqlx::Row;
use std::{sync::Arc, time::Duration};

pub async fn prune_management(
    execution: rss_transactional_messaging::fence::ExecutionBinding,
    database: &crate::Store,
    store: &rss_mdm_audit_integration::AuditStore,
    tenant: &str,
) -> Result<u64, Error> {
    // This is only a non-locking hint. Any candidate is re-read under Audit then
    // business locks below; a concurrent new expiry is picked up on the next tick.
    let mut hint = database.begin_read(tenant).await?;
    let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND expected_epoch=$2 AND expires_at<clock_timestamp())")
        .bind(tenant).bind(execution.epoch().get()).fetch_one(&mut *hint).await.map_err(db)?;
    hint.rollback().await.map_err(db)?;
    if !pending {
        return Ok(0);
    }
    let audit = rss_mdm_audit_integration::RequestAudit::new(
        rss_mdm_audit_integration::Origin::Background,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        execution,
        "collection_finish",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_service("service:management-retention");
    let budget = rss_mdm_audit_integration::budget::AuditBudget::retirement(None);
    let attempt = store
        .write(
            audit.binding()?,
            &budget.source_control(),
            (store, tenant, &audit),
            |(store, tenant, audit), tx| {
                Box::pin(async move {
                    let mut facts = Vec::new();
                    let count = tx
                        .with_connection_context(
                            &mut (audit.binding()?, *tenant, &mut facts),
                            |(execution, tenant, facts), c| {
                                Box::pin(prune_on(*execution, c, tenant, facts))
                            },
                        )
                        .await?;
                    for fact in &facts {
                        store.append(tx, fact).await.map_err(Error::from)?;
                    }
                    audit.mark_commit_started();
                    Ok(count)
                })
            },
        )
        .await;
    let result = crate::operations::settle(attempt, &audit);
    audit.finalize(
        result
            .as_ref()
            .err()
            .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
    );
    result
}
async fn prune_on(
    execution: rss_transactional_messaging::fence::ExecutionBinding,
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
) -> Result<u64, Error> {
    let expired=sqlx::query("SELECT device,protocol_epoch,session_id FROM mdm_access.management_sessions WHERE expected_epoch=current_setting('rss.execution_epoch')::bigint AND tenant_id=$1::uuid AND expires_at<clock_timestamp() ORDER BY expires_at,device,protocol_epoch,session_id LIMIT 32 FOR UPDATE SKIP LOCKED")
        .bind(tenant).fetch_all(&mut *tx).await.map_err(db)?;
    let mut devices = Vec::<rss_mdm_agent_wire::DeviceId>::new();
    let mut epochs = Vec::<uuid::Uuid>::new();
    let mut sessions = Vec::<String>::new();
    for row in expired {
        let device: rss_mdm_agent_wire::DeviceId = row
            .try_get::<uuid::Uuid, _>("device")
            .and_then(|id| {
                rss_mdm_agent_wire::DeviceId::try_from(id)
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))
            })
            .map_err(db)?;
        let epoch: uuid::Uuid = row.try_get("protocol_epoch").map_err(db)?;
        let session: String = row.try_get("session_id").map_err(db)?;
        crate::collection::terminate_session(
            execution, tx, facts, tenant, &device, epoch, &session, "timeout",
        )
        .await?;
        devices.push(device);
        epochs.push(epoch);
        sessions.push(session);
    }
    if devices.is_empty() {
        return Ok(0);
    }
    sqlx::query("DELETE FROM mdm_access.management_messages x USING unnest($2::uuid[],$3::uuid[],$4::text[]) k(device,protocol_epoch,session_id) WHERE x.tenant_id=$1::uuid AND x.device=k.device AND x.protocol_epoch=k.protocol_epoch AND x.session_id=k.session_id")
        .bind(tenant).bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).bind(&epochs).bind(&sessions).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("DELETE FROM mdm_windows.trust_deliveries x USING unnest($2::uuid[],$3::uuid[],$4::text[]) k(device,protocol_epoch,session_id) WHERE x.tenant_id=$1::uuid AND x.device=k.device AND x.protocol_epoch=k.protocol_epoch AND x.session::text=k.session_id")
        .bind(tenant).bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).bind(&epochs).bind(&sessions).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("DELETE FROM mdm_windows.push_queries x USING unnest($2::uuid[],$3::uuid[],$4::text[]) k(device,protocol_epoch,session_id) WHERE x.tenant_id=$1::uuid AND x.device=k.device AND x.protocol_epoch=k.protocol_epoch AND x.session::text=k.session_id")
        .bind(tenant).bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).bind(&epochs).bind(&sessions).execute(&mut *tx).await.map_err(db)?;
    let count=sqlx::query("DELETE FROM mdm_access.management_sessions x USING unnest($2::uuid[],$3::uuid[],$4::text[]) k(device,protocol_epoch,session_id) WHERE x.tenant_id=$1::uuid AND x.device=k.device AND x.protocol_epoch=k.protocol_epoch AND x.session_id=k.session_id")
        .bind(tenant).bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).bind(&epochs).bind(&sessions).execute(tx).await.map_err(db)?.rows_affected();

    Ok(count)
}

pub fn registration(
    app: Arc<crate::HttpState>,
    notify: Arc<tokio::sync::Notify>,
) -> ManagedTaskRegistration {
    let (task, _) = ManagedTask::prepare("mdm-management-retention", Duration::from_secs(10));
    task.into_registration(move |stop| async move {
        rss_mdm_work_page::run_grouped(
            std::num::NonZeroUsize::new(2).expect("parallel retention tenants"),
            Duration::from_secs(5),
            &stop,
            &notify,
            (
                |(tenant, _)| tenant,
                |after| {
                    let access = &app.access;
                    async move {
                        let rows = access
                            .retention_scopes(after)
                            .await
                            .map_err(|_| eprintln!("mdm_retention_discovery_failed"))?;
                        let next = if rows.is_empty() {
                            access
                                .next_session_expiry(after.is_none())
                                .await
                                .map_err(|_| eprintln!("mdm_retention_expiry_query_failed"))?
                        } else {
                            None
                        };
                        Ok(rss_mdm_work_page::Page { rows, next })
                    }
                },
            ),
            |(tenant, epoch)| {
                let app = app.clone();
                async move {
                    let tenant = rss_request_context::TenantId::parse(&tenant.to_string())
                        .map_err(|_| ())?;
                    let epoch =
                        rss_transactional_messaging::fence::Epoch::new(epoch).map_err(|_| ())?;
                    let execution = rss_transactional_messaging::fence::ExecutionBinding::new(
                        app.storage,
                        tenant,
                        epoch,
                    );
                    let count = prune_management(
                        execution,
                        &app.access,
                        &app.audit_store,
                        &tenant.to_string(),
                    )
                    .await
                    .map_err(|_| eprintln!("mdm_management_retention_failed"))?;
                    Ok(if count > 0 {
                        Duration::ZERO
                    } else {
                        Duration::from_millis(100)
                    })
                }
            },
            |_| {},
        )
        .await;
        Ok(())
    })
}
