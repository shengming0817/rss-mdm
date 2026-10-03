//! Only expired protocol sessions and cached responses are disposable; I01 and audit facts remain.
//! ref: PostgreSQL 17 SELECT FOR UPDATE SKIP LOCKED; sqlx 0.9 Transaction rollback-on-drop.
use crate::{Error, database::db};
use rss_runtime::{ManagedTask, ManagedTaskRegistration};
use sqlx::Row;
use std::{sync::Arc, time::Duration};

pub async fn prune_management(
    database: &crate::Store,
    store: &rss_mdm_audit_integration::AuditStore,
    tenant: &str,
) -> Result<u64, Error> {
    // This is only a non-locking hint. Any candidate is re-read under Audit then
    // business locks below; a concurrent new expiry is picked up on the next tick.
    let mut hint = database.begin_read(tenant).await?;
    let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND expires_at<clock_timestamp())")
        .bind(tenant).fetch_one(&mut *hint).await.map_err(db)?;
    hint.rollback().await.map_err(db)?;
    if !pending {
        return Ok(0);
    }
    let audit = rss_mdm_audit_integration::RequestAudit::new(tenant.into(), "collection_finish");
    audit.identify_service("service:management-retention");
    let budget = rss_mdm_audit_integration::budget::AuditBudget::retirement(None);
    let control = budget.control();
    let attempt = store
        .write(
            rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
            &control,
            (store, tenant, &audit),
            |(store, tenant, audit), tx| {
                Box::pin(async move {
                    let mut facts = Vec::new();
                    let count = tx
                        .with_connection_context(
                            &mut (*tenant, &mut facts),
                            |(tenant, facts), c| Box::pin(prune_on(c, tenant, facts)),
                        )
                        .await?;
                    for fact in &facts {
                        store.append(tx, fact, false).await.map_err(Error::from)?;
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
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
) -> Result<u64, Error> {
    let expired=sqlx::query("SELECT registration::text,session_id FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND expires_at<clock_timestamp() ORDER BY expires_at,registration,session_id LIMIT 32 FOR UPDATE SKIP LOCKED")
            .bind(tenant).fetch_all(&mut *tx).await.map_err(db)?;
    let mut registrations = Vec::<String>::new();
    let mut sessions = Vec::<String>::new();
    for row in expired {
        let registration: String = row.try_get("registration").map_err(db)?;
        let session: String = row.try_get("session_id").map_err(db)?;
        crate::collection::terminate_session(tx, facts, tenant, &registration, &session, "timeout")
            .await?;
        registrations.push(registration);
        sessions.push(session);
    }
    if registrations.is_empty() {
        return Ok(0);
    }
    sqlx::query("DELETE FROM mdm_access.management_messages m USING unnest($2::text[],$3::text[]) k(registration,session_id) WHERE m.tenant_id=$1::uuid AND m.registration=k.registration::uuid AND m.session_id=k.session_id")
            .bind(tenant).bind(&registrations).bind(&sessions).execute(&mut *tx).await.map_err(db)?;
    sqlx::query("DELETE FROM mdm_windows.push_queries q USING unnest($2::text[],$3::text[]) k(registration,session_id) WHERE q.tenant_id=$1::uuid AND q.registration=k.registration::uuid AND q.session::text=k.session_id")
        .bind(tenant).bind(&registrations).bind(&sessions).execute(&mut *tx).await.map_err(db)?;
    let count=sqlx::query("DELETE FROM mdm_access.management_sessions s USING unnest($2::text[],$3::text[]) k(registration,session_id) WHERE s.tenant_id=$1::uuid AND s.registration=k.registration::uuid AND s.session_id=k.session_id")
            .bind(tenant).bind(&registrations).bind(&sessions).execute(&mut *tx).await.map_err(db)?.rows_affected();
    Ok(count)
}

pub fn registration(
    database: Arc<crate::Store>,
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    tenant: String,
    notify: std::sync::Arc<tokio::sync::Notify>,
) -> ManagedTaskRegistration {
    let (task, _) = ManagedTask::prepare("mdm-management-retention", Duration::from_secs(10));
    task.into_registration(move |token| async move {
        let mut failures = 0u64;
        loop {
            if token.is_cancelled() { return Ok(()); }
            let result = sweep(&database, &audit_store, &tenant).await;
            match result {
                Ok((count, nearest)) => {
                    failures = 0;
                    if count > 0 {
                        eprintln!("{}", serde_json::json!({"event":"mdm_management_retention","sessions":count}));
                        continue;
                    }
                    wait(&notify, &token, nearest).await;
                }
                Err(_) => {
                    failures = failures.saturating_add(1);
                    if failures.is_power_of_two() { eprintln!("{}",serde_json::json!({"event":"mdm_management_retention_failure","kind":"access_store","count":failures})); }
                    tokio::select! { () = token.cancelled() => return Ok(()), () = tokio::time::sleep(Duration::from_secs(1)) => {} }
                }
            }
        }
    })
}

async fn next_expiry(database: &crate::Store, tenant: &str) -> Result<Option<Duration>, Error> {
    let mut tx = database.begin_read(tenant).await?;
    let millis: Option<i64> = sqlx::query_scalar("SELECT ceil(extract(epoch FROM min(expires_at)-clock_timestamp())*1000)::bigint FROM mdm_access.management_sessions WHERE tenant_id=$1::uuid AND expires_at>clock_timestamp()")
        .bind(tenant).fetch_one(&mut *tx).await.map_err(db)?;
    tx.rollback().await.map_err(db)?;
    Ok(millis.map(|ms| Duration::from_millis(ms.max(1) as u64)))
}

pub async fn sweep(
    database: &crate::Store,
    store: &rss_mdm_audit_integration::AuditStore,
    tenant: &str,
) -> Result<(u64, Option<Duration>), Error> {
    let count = prune_management(database, store, tenant).await?;
    let nearest = if count == 0 {
        next_expiry(database, tenant).await?
    } else {
        None
    };
    Ok((count, nearest))
}

async fn wait(
    notify: &tokio::sync::Notify,
    stop: &tokio_util::sync::CancellationToken,
    nearest: Option<Duration>,
) {
    let recovery = Duration::from_secs(5);
    tokio::select! {biased; ()=stop.cancelled()=>{},()=notify.notified()=>{},()=tokio::time::sleep(nearest.unwrap_or(recovery).min(recovery))=>{}}
}
