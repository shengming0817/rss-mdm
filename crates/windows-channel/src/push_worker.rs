//! Work-driven discovery, followed by authoritative claim and fenced WNS settlement.
//! ref: PostgreSQL LISTEN/NOTIFY; sqlx 0.9 sqlx-postgres/src/listener.rs.
use crate::participants::WakeDemand;
use crate::push::{PushOutcome, RetryAfter};
use crate::{Error, Failure, RequestAudit, Store, Windows, database::db};
use rss_mdm_audit_integration::{AuditStore, Fact};
use rss_mdm_native_protection::Protector;
use rss_request_context::TenantId;
use sqlx::Row;
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;
use uuid::Uuid;

const RECONCILE: Duration = Duration::from_secs(60);
const FAILURE_RETRY: Duration = Duration::from_secs(5);

/// Actual discovery and transaction counts from one sweep; no command delivery claims.
#[derive(Default, Debug)]
pub struct WakeScan {
    pub candidates: usize,
    pub transactions: usize,
    pub sent: usize,
    pub failures: usize,
    next: Option<Instant>,
}
impl WakeScan {
    fn due(&mut self, at: Instant) {
        self.next = Some(self.next.map_or(at, |previous| previous.min(at)));
    }
}
struct Wake {
    id: Uuid,
    device: String,
    revision: i64,
    uri: zeroize::Zeroizing<String>,
}
fn audit(tenant: &str, id: Uuid, device: &str) -> RequestAudit {
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Background,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        tenant.into(),
        "windows_push",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_service("windows-push");
    audit.target_device(device);
    audit.operation(
        id,
        "windows_push",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target(device);
    audit
}
pub async fn cycle(
    w: &Windows,
    eligibility: &dyn WakeDemand,
    key: &Protector,
    dbase: &Store,
    store: &AuditStore,
    tenant: &str,
) -> Result<WakeScan, Error> {
    let mut scan = WakeScan::default();
    let Some(push) = &w.push else { return Ok(scan) };
    let mut after = String::new();
    loop {
        let mut read = dbase.begin_read(tenant).await?;
        let candidates = eligibility.candidates(&mut read, &after).await?;
        let count = candidates.len();
        scan.candidates += count;
        let Some(last) = candidates.last().cloned() else {
            read.rollback().await.map_err(db)?;
            return Ok(scan);
        };
        // Always advance by the raw work page, including absent or disabled routes.
        after = last;
        if let Some(revision) = push.material_revision
            && !crate::wns_materials::is_selected(&mut read, tenant, revision).await?
        {
            return Err(Error::Conflict);
        }
        let rows = sqlx::query("SELECT p.device, p.revision, CAST(EXTRACT(EPOCH FROM GREATEST(p.next_push, COALESCE(p.lease_until, p.next_push)) - clock_timestamp()) AS double precision) AS wait_seconds FROM mdm_windows.push_channels AS p INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.id) = (p.tenant_id, p.device) WHERE p.tenant_id = CAST($1 AS uuid) AND p.device = ANY($2) AND p.configuration = $3 AND p.attempt_until > clock_timestamp() AND (p.outcome IS NULL OR p.outcome IN ('accepted', 'retryable', 'unknown')) AND r.state = 'active' ORDER BY p.device")
            .bind(tenant).bind(&candidates).bind(push.configuration.as_slice()).fetch_all(&mut *read).await.map_err(db)?;
        read.rollback().await.map_err(db)?;
        for row in rows {
            let seconds: f64 = row.try_get("wait_seconds").map_err(db)?;
            if seconds > 0.0 {
                scan.due(
                    push.now() + Duration::from_secs_f64(seconds.min(RECONCILE.as_secs_f64())),
                );
                continue;
            }
            scan.transactions += 1;
            match attempt(w, eligibility, key, store, tenant, row).await {
                Ok(Some(delay)) => {
                    scan.sent += 1;
                    scan.due(push.now() + delay);
                }
                Ok(None) => (),
                Err(error) => {
                    if matches!(
                        error,
                        Error::Unavailable(Failure::Database) | Error::RollbackFailed
                    ) {
                        return Err(error);
                    }
                    scan.failures += 1;
                    scan.due(push.now() + FAILURE_RETRY);
                }
            }
        }
        if count < 32 {
            return Ok(scan);
        }
    }
}
async fn attempt(
    w: &Windows,
    eligibility: &dyn WakeDemand,
    key: &Protector,
    store: &AuditStore,
    tenant: &str,
    row: sqlx::postgres::PgRow,
) -> Result<Option<Duration>, Error> {
    let Some(push) = &w.push else { return Ok(None) };
    let revision: i64 = row.try_get("revision").map_err(db)?;
    let device: String = row.try_get("device").map_err(db)?;
    let id = Uuid::new_v4();
    let audit = audit(tenant, id, &device);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(3));
    let outcome=store.write(TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
            &budget.source_control(),(store,&audit,eligibility,tenant,device.as_str(),revision,id,push.configuration,push.material_revision),|inputs,tx|Box::pin(async move {
                let (store,audit,eligibility,tenant,device,revision,id,configuration,material_revision)=*inputs;
                let sealed=tx.with_connection_context(&mut (eligibility,tenant,device,revision,id,configuration,material_revision),|(eligibility,tenant,device,revision,id,configuration,material_revision),c|Box::pin(async move {
                    if !eligibility.pending(c, device).await? { return Ok::<_,Error>(None) }
                    sqlx::query_scalar::<_,Vec<u8>>("UPDATE mdm_windows.push_channels SET lease_id = $5, lease_until = clock_timestamp() + CAST('30 seconds' AS interval), settled_id = NULL WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND revision = $3 AND configuration = $4 AND attempt_until > clock_timestamp() AND next_push <= clock_timestamp() AND (lease_until IS NULL OR lease_until <= clock_timestamp()) AND (outcome IS NULL OR outcome IN ('accepted', 'retryable', 'unknown')) AND (CAST($6 AS bigint) IS NULL OR EXISTS (SELECT 1 FROM mdm_wns.versions AS w WHERE w.tenant_id = CAST($1 AS uuid) AND w.revision = $6 AND w.selected AND NOT w.revoked AND w.qualified_at IS NOT NULL)) RETURNING uri")
                        .bind(*tenant).bind(*device).bind(*revision).bind(configuration.as_slice()).bind(*id).bind(*material_revision).fetch_optional(c).await.map_err(db)
                })).await?;
                if sealed.is_some() {

                    let fact=Fact::observation(audit, &format!("windows-push:{id}:lease"), 200, "success", None).map_err(Error::from)?;
                    store.append(tx, &fact).await.map_err(Error::from)?;audit.mark_commit_started();
                }
                Ok(sealed)
            })).await;
    let sealed = crate::operations::settle(outcome, &audit);
    audit.finalize(
        sealed
            .as_ref()
            .err()
            .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
    );
    let Some(sealed) = sealed? else {
        return Ok(None);
    };
    let aad = crate::protection::native_aad(
        TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
        "windows.push.channel",
        &(&device, push.configuration),
    )?;
    let uri = key
        .open_bytes(&sealed, &aad)
        .map_err(|_| Error::Unavailable(Failure::Protocol))?;
    let uri = zeroize::Zeroizing::new(
        String::from_utf8(uri.expose().to_vec())
            .map_err(|_| Error::Unavailable(Failure::Protocol))?,
    );
    let wake = Wake {
        id,
        device: device.to_string(),

        revision,
        uri,
    };
    let receipt = push.send(&wake.uri).await.unwrap_or(crate::push::Receipt {
        status: 0,
        outcome: PushOutcome::Unknown,
        retry_after: None,
    });
    settle(store, key, tenant, &wake, receipt).await.map(Some)
}
async fn settle(
    store: &AuditStore,
    key: &Protector,
    tenant: &str,
    wake: &Wake,
    receipt: crate::push::Receipt,
) -> Result<Duration, Error> {
    let status = receipt.status;
    let outcome = receipt.outcome;
    let retry_after = receipt.retry_after;
    let audit = audit(tenant, wake.id, &wake.device);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(3));
    let result=store.write(TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
            &budget.source_control(),(store,&audit,key,tenant,wake,status,outcome,retry_after),|inputs,tx|Box::pin(async move {
        let (store,audit,key,tenant,wake,status,outcome,retry_after)=*inputs;
        let changed=tx.with_connection_context(&mut (key,tenant,wake,status,outcome,retry_after),|(key,tenant,wake,status,outcome,retry_after),c|Box::pin(async move {
            let row=sqlx::query("SELECT revision, configuration, digest, lease_id, settled_id, failures, status, outcome FROM mdm_windows.push_channels WHERE tenant_id = CAST($1 AS uuid) AND device = $2 FOR UPDATE")
                .bind(*tenant).bind(&wake.device).fetch_optional(&mut *c).await.map_err(db)?;
            let Some(row)=row else {return Ok::<_,Error>(None)};

            let revision: i64 = row.try_get("revision").map_err(db)?;
            if revision != wake.revision {
                // Only definitive endpoint invalidation crosses binding revisions.
                // A receipt for the previous URI cannot poison its replacement.
                if *outcome != PushOutcome::Unregistered || !matches!(*status, 404 | 410) {
                    return Ok(None);
                }
                let configuration: [u8; 32] = row.try_get::<Vec<u8>, _>("configuration").map_err(db)?.try_into().map_err(|_| Error::Malformed)?;
                let aad = crate::protection::native_aad(TenantId::parse(tenant).map_err(|_| Error::Malformed)?, "windows.push.channel", &(&wake.device, configuration))?;
                if key.verify_mac(wake.uri.as_bytes(), &aad, &row.try_get::<Vec<u8>, _>("digest").map_err(db)?).is_err() {
                    return Ok(None);
                }
                if row.try_get::<Option<String>, _>("outcome").map_err(db)?.as_deref() == Some("unregistered") {
                    return Ok(Some((false, RECONCILE)));
                }
                sqlx::query("UPDATE mdm_windows.push_channels SET lease_id = NULL, lease_until = NULL, settled_id = $3, status = $4, outcome = 'unregistered', failures = 0 WHERE tenant_id = CAST($1 AS uuid) AND device = $2")
                    .bind(*tenant).bind(&wake.device).bind(wake.id).bind(i32::from(*status)).execute(c).await.map_err(db)?;
                return Ok(Some((true, RECONCILE)));
            }

            if row.try_get::<Option<Uuid>,_>("settled_id").map_err(db)?==Some(wake.id) {
                if row.try_get::<Option<i32>,_>("status").map_err(db)?!=Some(i32::from(*status)) || row.try_get::<Option<String>,_>("outcome").map_err(db)?.as_deref()!=Some(outcome.as_str()) {return Err(Error::Conflict)}
                return Ok(Some((false, RECONCILE)));
            }
            if row.try_get::<Option<Uuid>,_>("lease_id").map_err(db)?!=Some(wake.id) {return Ok(None)}
            let failures=if matches!(*outcome, PushOutcome::Retryable | PushOutcome::Unknown) {(row.try_get::<i32,_>("failures").map_err(db)?+1).min(6)} else {0};
            let (retry_seconds,retry_at)=match *retry_after {
                Some(RetryAfter::Seconds(seconds))=>(i64::from(seconds),None),
                Some(RetryAfter::Date(at))=>(0,Some(at)),
                None=>(0,None),
            };
            let delay=if matches!(*outcome, PushOutcome::Retryable | PushOutcome::Unknown) {(15i64*(1<<failures)).max(retry_seconds)} else {120};
            let wait: f64 = sqlx::query_scalar("UPDATE mdm_windows.push_channels SET lease_id = NULL, lease_until = NULL, settled_id = $4, status = $5, outcome = $6, failures = $7, next_push = GREATEST(clock_timestamp() + make_interval(secs => CAST($8 AS double precision)), to_timestamp(CAST($9 AS double precision))) WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND revision = $3 RETURNING CAST(GREATEST(0, EXTRACT(EPOCH FROM next_push - clock_timestamp())) AS double precision)")
                .bind(*tenant).bind(&wake.device).bind(wake.revision).bind(wake.id).bind(i32::from(*status)).bind(outcome.as_str()).bind(failures).bind(delay as f64).bind(retry_at.map(|at|at as f64)).fetch_one(c).await.map_err(db)?;
            Ok(Some((true, Duration::from_secs_f64(wait.min(RECONCILE.as_secs_f64())))))
        })).await?;
        if let Some((changed,_))=changed {

            let fact=Fact::observation(audit, &format!("windows-push:{}:settle",wake.id), 200, "success", None).and_then(|f|f.with_details(serde_json::json!({"status":status,"outcome":outcome,"channelRevision":wake.revision,"retryAfter":retry_after}))).map_err(Error::from)?;
            (if !changed { Ok(()) } else { store.append(tx, &fact).await }).map_err(Error::from)?;audit.mark_commit_started();
        }
        Ok(changed.map_or(RECONCILE, |(_, wait)| wait))
    })).await;
    let result = crate::operations::settle(result, &audit);
    audit.finalize(
        result
            .as_ref()
            .err()
            .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
    );
    result
}
pub fn registration(
    w: Arc<Windows>,
    eligibility: Arc<dyn WakeDemand>,
    key: Arc<Protector>,
    database: Arc<Store>,
    store: Arc<AuditStore>,
    tenant: String,
    notify: Arc<tokio::sync::Notify>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("windows-wns", Duration::from_secs(8));
    task.into_registration(move |stop| async move {
        let Some(push) = &w.push else { return Ok(()) };
        let mut reconcile = tokio::time::interval_at(push.now() + RECONCILE, RECONCILE);
        reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut failures = 0u64;
        loop {
            let result = tokio::select! { biased;
                () = stop.cancelled() => return Ok(()),
                result = cycle(&w, eligibility.as_ref(), &key, &database, &store, &tenant) => result,
            };
            let next = match result {
                Ok(scan) => {
                    if scan.failures == 0 { failures = 0; } else { failures = failures.saturating_add(1); }
                    scan.next
                }
                Err(_) => {
                    failures = failures.saturating_add(1);
                    Some(push.now() + FAILURE_RETRY)
                }
            };
            if failures.is_power_of_two() {
                eprintln!("{}", serde_json::json!({"event":"windows_push_unavailable","consecutive_failures":failures}));
            }
            wait(&notify, &stop, &mut reconcile, next).await;

        }
    })
}

async fn wait(
    notify: &tokio::sync::Notify,
    stop: &tokio_util::sync::CancellationToken,
    reconcile: &mut tokio::time::Interval,
    next: Option<Instant>,
) {
    let retry = async {
        match next {
            Some(at) => tokio::time::sleep_until(at).await,
            None => std::future::pending::<()>().await,
        }
    };
    // A fixed interval cannot be postponed by a stream of hints.
    tokio::select! { biased;
        () = stop.cancelled() => {},
        _ = reconcile.tick() => {},
        () = retry => {},
        () = notify.notified() => {},
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[allow(
        clippy::disallowed_methods,
        reason = "test observes the paused Tokio runtime clock"
    )]
    #[tokio::test(start_paused = true)]
    async fn hints_cannot_postpone_reconciliation_and_wait_keeps_early_permit() {
        let notify = tokio::sync::Notify::new();
        let stop = tokio_util::sync::CancellationToken::new();
        let start = Instant::now();
        let mut interval = tokio::time::interval_at(start + RECONCILE, RECONCILE);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        for _ in 0..59 {
            tokio::time::advance(Duration::from_secs(1)).await;
            notify.notify_one();
            wait(&notify, &stop, &mut interval, None).await;
        }
        wait(&notify, &stop, &mut interval, None).await;
        assert_eq!(Instant::now(), start + RECONCILE);
        let next = Instant::now() + Duration::from_secs(2);
        wait(&notify, &stop, &mut interval, Some(next)).await;
        assert_eq!(Instant::now(), next);
        notify.notify_one();
        wait(&notify, &stop, &mut interval, None).await;
        assert_eq!(Instant::now(), next);
        stop.cancel();
        wait(&notify, &stop, &mut interval, None).await;
        assert_eq!(Instant::now(), next);
    }
}
