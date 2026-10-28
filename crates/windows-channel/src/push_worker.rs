//! Work-driven discovery, followed by authoritative claim and fenced WNS settlement.
//! ref: PostgreSQL LISTEN/NOTIFY; sqlx 0.9 sqlx-postgres/src/listener.rs.
use crate::push::{PushOutcome, RetryAfter};
use crate::{Error, Failure, RequestAudit, Store, Windows, database::db};
use rss_mdm_audit_integration::{AuditStore, Fact};
use rss_mdm_execution_service::ExecutionService;
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
    registration: Uuid,
    generation: i64,
    revision: i64,
    uri: zeroize::Zeroizing<String>,
}
fn audit(tenant: &str, id: Uuid, registration: Uuid) -> RequestAudit {
    let audit = RequestAudit::new(
        tenant.into(),
        "windows_push",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_service("windows-push");
    audit.registration(registration);
    audit.operation(
        id,
        "windows_push",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target(&registration.to_string());
    audit
}
pub async fn cycle(
    w: &Windows,
    eligibility: &ExecutionService,
    key: &Protector,
    dbase: &Store,
    store: &AuditStore,
    tenant: &str,
) -> Result<WakeScan, Error> {
    let mut scan = WakeScan::default();
    let Some(push) = &w.push else { return Ok(scan) };
    let mut after = Uuid::nil();
    loop {
        let mut read = dbase.begin_read(tenant).await?;
        let candidates = eligibility
            .windows_wake_candidates_in(&mut read, after)
            .await?;
        let count = candidates.len();
        scan.candidates += count;
        let Some(last) = candidates.last().copied() else {
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
        let rows = sqlx::query("SELECT p.registration,p.generation,p.revision,r.device,extract(epoch FROM (greatest(p.next_push,coalesce(p.lease_until,p.next_push))-clock_timestamp()))::double precision AS wait_seconds FROM mdm_windows.push_channels p JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(p.tenant_id,p.registration,p.generation) WHERE p.tenant_id=$1::uuid AND p.registration=ANY($2) AND p.configuration=$3 AND p.attempt_until>clock_timestamp() AND (p.outcome IS NULL OR p.outcome IN ('accepted','retryable','unknown')) AND r.state='active' ORDER BY p.registration")
            .bind(tenant).bind(&candidates).bind(push.configuration.as_slice()).fetch_all(&mut *read).await.map_err(db)?;
        read.rollback().await.map_err(db)?;
        for row in rows {
            let seconds: f64 = row.try_get("wait_seconds").map_err(db)?;
            if seconds > 0.0 {
                scan.due(
                    Instant::now() + Duration::from_secs_f64(seconds.min(RECONCILE.as_secs_f64())),
                );
                continue;
            }
            scan.transactions += 1;
            match attempt(w, eligibility, key, store, tenant, row).await {
                Ok(Some(delay)) => {
                    scan.sent += 1;
                    scan.due(Instant::now() + delay);
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
                    scan.due(Instant::now() + FAILURE_RETRY);
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
    eligibility: &ExecutionService,
    key: &Protector,
    store: &AuditStore,
    tenant: &str,
    row: sqlx::postgres::PgRow,
) -> Result<Option<Duration>, Error> {
    let Some(push) = &w.push else { return Ok(None) };
    let registration: Uuid = row.try_get("registration").map_err(db)?;
    let generation: i64 = row.try_get("generation").map_err(db)?;
    let revision: i64 = row.try_get("revision").map_err(db)?;
    let device: String = row.try_get("device").map_err(db)?;
    let id = Uuid::new_v4();
    let audit = audit(tenant, id, registration);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(3));
    let outcome=store.write(TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
            &budget.source_control(),(store,&audit,eligibility,tenant,device.as_str(),registration,generation,revision,id,push.configuration,push.material_revision),|inputs,tx|Box::pin(async move {
                let (store,audit,eligibility,tenant,device,registration,generation,revision,id,configuration,material_revision)=*inputs;
                let sealed=tx.with_connection_context(&mut (eligibility,tenant,device,registration,generation,revision,id,configuration,material_revision),|(eligibility,tenant,device,registration,generation,revision,id,configuration,material_revision),c|Box::pin(async move {
                    if !eligibility.windows_wake_pending_in(c, device, *registration, *generation).await? { return Ok::<_,Error>(None) }
                    sqlx::query_scalar::<_,Vec<u8>>("UPDATE mdm_windows.push_channels SET lease_id=$6,lease_until=clock_timestamp()+interval '30 seconds',settled_id=NULL WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND revision=$4 AND configuration=$5 AND attempt_until>clock_timestamp() AND next_push<=clock_timestamp() AND (lease_until IS NULL OR lease_until<=clock_timestamp()) AND (outcome IS NULL OR outcome IN ('accepted','retryable','unknown')) AND ($7::bigint IS NULL OR EXISTS(SELECT 1 FROM mdm_wns.versions w WHERE w.tenant_id=$1::uuid AND w.revision=$7 AND w.selected AND NOT w.revoked AND w.qualified_at IS NOT NULL)) RETURNING uri")
                        .bind(*tenant).bind(*registration).bind(*generation).bind(*revision).bind(configuration.as_slice()).bind(*id).bind(*material_revision).fetch_optional(c).await.map_err(db)
                })).await?;
                if sealed.is_some() {

                    let fact=Fact::business(audit, &format!("windows-push:{id}:lease"), 200, "success", None).map_err(Error::from)?;
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
        &(registration, generation, push.configuration),
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
        registration,
        generation,
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
    let audit = audit(tenant, wake.id, wake.registration);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(3));
    let result=store.write(TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
            &budget.source_control(),(store,&audit,key,tenant,wake,status,outcome,retry_after),|inputs,tx|Box::pin(async move {
        let (store,audit,key,tenant,wake,status,outcome,retry_after)=*inputs;
        let changed=tx.with_connection_context(&mut (key,tenant,wake,status,outcome,retry_after),|(key,tenant,wake,status,outcome,retry_after),c|Box::pin(async move {
            let row=sqlx::query("SELECT generation,revision,configuration,digest,lease_id,settled_id,failures,status,outcome FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND registration=$2 FOR UPDATE")
                .bind(*tenant).bind(wake.registration).fetch_optional(&mut *c).await.map_err(db)?;
            let Some(row)=row else {return Ok::<_,Error>(None)};
            let generation: i64 = row.try_get("generation").map_err(db)?;
            let revision: i64 = row.try_get("revision").map_err(db)?;
            if generation != wake.generation || revision != wake.revision {
                // Only definitive endpoint invalidation crosses binding revisions.
                // A receipt for the previous URI cannot poison its replacement.
                if *outcome != PushOutcome::Unregistered || !matches!(*status, 404 | 410) {
                    return Ok(None);
                }
                let configuration: [u8; 32] = row.try_get::<Vec<u8>, _>("configuration").map_err(db)?.try_into().map_err(|_| Error::Malformed)?;
                let aad = crate::protection::native_aad(TenantId::parse(tenant).map_err(|_| Error::Malformed)?, "windows.push.channel", &(wake.registration, generation, configuration))?;
                if key.verify_mac(wake.uri.as_bytes(), &aad, &row.try_get::<Vec<u8>, _>("digest").map_err(db)?).is_err() {
                    return Ok(None);
                }
                if row.try_get::<Option<String>, _>("outcome").map_err(db)?.as_deref() == Some("unregistered") {
                    return Ok(Some((false, RECONCILE)));
                }
                sqlx::query("UPDATE mdm_windows.push_channels SET lease_id=NULL,lease_until=NULL,settled_id=$3,status=$4,outcome='unregistered',failures=0 WHERE tenant_id=$1::uuid AND registration=$2")
                    .bind(*tenant).bind(wake.registration).bind(wake.id).bind(i32::from(*status)).execute(c).await.map_err(db)?;
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
            let wait: f64 = sqlx::query_scalar("UPDATE mdm_windows.push_channels SET lease_id=NULL,lease_until=NULL,settled_id=$5,status=$6,outcome=$7,failures=$8,next_push=greatest(clock_timestamp()+make_interval(secs=>$9::double precision),to_timestamp($10::double precision)) WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND revision=$4 RETURNING greatest(0,extract(epoch FROM (next_push-clock_timestamp())))::double precision")
                .bind(*tenant).bind(wake.registration).bind(wake.generation).bind(wake.revision).bind(wake.id).bind(i32::from(*status)).bind(outcome.as_str()).bind(failures).bind(delay as f64).bind(retry_at.map(|at|at as f64)).fetch_one(c).await.map_err(db)?;
            Ok(Some((true, Duration::from_secs_f64(wait.min(RECONCILE.as_secs_f64())))))
        })).await?;
        if let Some((changed,_))=changed {

            let fact=Fact::business(audit, &format!("windows-push:{}:settle",wake.id), 200, "success", None).and_then(|f|f.with_details(serde_json::json!({"status":status,"outcome":outcome,"channelRevision":wake.revision,"retryAfter":retry_after}))).map_err(Error::from)?;
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
    eligibility: Arc<ExecutionService>,
    key: Arc<Protector>,
    database: Arc<Store>,
    store: Arc<AuditStore>,
    tenant: String,
    notify: Arc<tokio::sync::Notify>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("windows-wns", Duration::from_secs(8));
    task.into_registration(move |stop| async move {
        let mut reconcile = tokio::time::interval_at(Instant::now() + RECONCILE, RECONCILE);
        reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut failures = 0u64;
        loop {
            let result = tokio::select! { biased;
                () = stop.cancelled() => return Ok(()),
                result = cycle(&w, &eligibility, &key, &database, &store, &tenant) => result,
            };
            let next = match result {
                Ok(scan) => {
                    if scan.failures == 0 { failures = 0; } else { failures = failures.saturating_add(1); }
                    scan.next
                }
                Err(_) => {
                    failures = failures.saturating_add(1);
                    Some(Instant::now() + FAILURE_RETRY)
                }
            };
            if failures.is_power_of_two() {
                eprintln!("{}", serde_json::json!({"event":"windows_push_unavailable","consecutive_failures":failures}));
            }
            // A fixed interval cannot be postponed by a stream of hints.
            tokio::select! { biased;
                () = stop.cancelled() => return Ok(()),
                _ = reconcile.tick() => {},
                () = tokio::time::sleep_until(next.unwrap_or_else(|| Instant::now() + RECONCILE)) => {},
                () = notify.notified() => {},
            }
        }
    })
}
