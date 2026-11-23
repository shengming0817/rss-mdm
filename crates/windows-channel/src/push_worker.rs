//! Work-driven discovery, followed by authoritative claim and fenced WNS settlement.
//! ref: PostgreSQL LISTEN/NOTIFY; sqlx 0.9 sqlx-postgres/src/listener.rs.
use crate::participants::WakeDemand;
use crate::push::{PushOutcome, RetryAfter};
use crate::{Error, Failure, RequestAudit, Windows, database::db};
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
    device: rss_mdm_agent_wire::DeviceId,
    revision: i64,
    uri: zeroize::Zeroizing<String>,
    material_revision: Option<i64>,
}
fn audit(
    execution: rss_transactional_messaging::fence::ExecutionBinding,
    id: Uuid,
    device: &rss_mdm_agent_wire::DeviceId,
) -> RequestAudit {
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Background,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        execution,
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
    audit.target_device(device);
    audit
}
async fn cycle(
    execution: rss_transactional_messaging::fence::ExecutionBinding,
    w: &Windows,
    eligibility: &dyn WakeDemand,
    app: &crate::HttpState,
    candidates: &[rss_mdm_agent_wire::DeviceId],
    stop: &tokio_util::sync::CancellationToken,
) -> Result<WakeScan, Error> {
    let mut scan = WakeScan {
        candidates: candidates.len(),
        ..Default::default()
    };
    let Some(push) = &w.push else { return Ok(scan) };
    let tenant_string = execution.tenant().to_string();
    let tenant = tenant_string.as_str();
    let mut read = app.access.begin_read(tenant).await?;
    if let Some(revision) = push.material_revision
        && !crate::wns_materials::is_selected(&mut read, tenant, revision).await?
    {
        return Err(Error::Conflict);
    }
    let rows = sqlx::query("SELECT p.device, p.revision, CAST(EXTRACT(EPOCH FROM GREATEST(p.next_push, COALESCE(p.lease_until, p.next_push)) - clock_timestamp()) AS double precision) AS wait_seconds FROM mdm_windows.push_channels AS p INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.id) = (p.tenant_id, p.device) WHERE p.tenant_id = CAST($1 AS uuid) AND p.device = ANY($2) AND p.configuration = $3 AND p.attempt_until > clock_timestamp() AND (p.outcome IS NULL OR p.outcome IN ('accepted', 'retryable', 'unknown') OR (p.outcome='rejected' AND p.material_revision IS DISTINCT FROM $4)) AND r.state = 'active' ORDER BY p.device")
            .bind(tenant).bind(candidates.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).bind(push.configuration.as_slice()).bind(push.material_revision).fetch_all(&mut *read).await.map_err(db)?;
    read.rollback().await.map_err(db)?;
    for row in rows {
        if stop.is_cancelled() {
            break;
        }
        let seconds: f64 = row.try_get("wait_seconds").map_err(db)?;
        if seconds > 0.0 {
            scan.due(push.now() + Duration::from_secs_f64(seconds.min(RECONCILE.as_secs_f64())));
            continue;
        }
        // OAuth may wait for another channel's refresh. Acquire the durable lease only afterwards.
        let bearer =
            tokio::select! {biased; ()=stop.cancelled()=>break, token=push.bearer()=>token.ok()};
        if stop.is_cancelled() {
            break;
        }
        scan.transactions += 1;
        match attempt(
            execution,
            w,
            eligibility,
            &app.protection,
            &app.audit_store,
            tenant,
            (row, bearer),
        )
        .await
        {
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
    Ok(scan)
}
async fn attempt(
    execution: rss_transactional_messaging::fence::ExecutionBinding,
    w: &Windows,
    eligibility: &dyn WakeDemand,
    key: &Protector,
    store: &AuditStore,
    tenant: &str,
    (row, bearer): (sqlx::postgres::PgRow, Option<zeroize::Zeroizing<String>>),
) -> Result<Option<Duration>, Error> {
    let Some(push) = &w.push else { return Ok(None) };
    let revision: i64 = row.try_get("revision").map_err(db)?;
    let device: rss_mdm_agent_wire::DeviceId = row
        .try_get::<uuid::Uuid, _>("device")
        .and_then(|id| {
            rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
        })
        .map_err(db)?;
    let id = Uuid::new_v4();
    let audit = audit(execution, id, &device);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(3));
    let outcome=store.write(
            audit.binding()?,
            &budget.source_control(),(store,&audit,eligibility,tenant,&device,revision,id,push.configuration,push.material_revision),|inputs,tx|Box::pin(async move {
                let (store,audit,eligibility,tenant,device,revision,id,configuration,material_revision)=*inputs;
                let sealed=tx.with_connection_context(&mut (audit.binding()?,eligibility,tenant,device,revision,id,configuration,material_revision),|(execution,eligibility,tenant,device,revision,id,configuration,material_revision),c|Box::pin(async move {
                    if !eligibility.pending(*execution, c, device).await? { return Ok::<_,Error>(None) }
                    sqlx::query_scalar::<_,Vec<u8>>("UPDATE mdm_windows.push_channels SET lease_id = $5, outcome=CASE WHEN outcome='rejected' AND material_revision IS DISTINCT FROM $6 THEN NULL ELSE outcome END, material_revision=$6, lease_until = clock_timestamp() + CAST('30 seconds' AS interval), settled_id = NULL WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND revision = $3 AND configuration = $4 AND attempt_until > clock_timestamp() AND next_push <= clock_timestamp() AND (lease_until IS NULL OR lease_until <= clock_timestamp()) AND (outcome IS NULL OR outcome IN ('accepted', 'retryable', 'unknown') OR (outcome='rejected' AND material_revision IS DISTINCT FROM $6)) AND EXISTS (SELECT FROM mdm_wns.versions w JOIN mdm_wns.heads h ON (h.tenant_id,h.desired_revision)=(w.tenant_id,w.revision) WHERE w.tenant_id=$1::uuid AND w.revision=$6 AND w.selected AND NOT w.revoked AND w.qualified_at IS NOT NULL AND mdm_wns.provider_available(w.sid_digest) FOR SHARE OF h,w) RETURNING uri")
                        .bind(*tenant).bind(device.into_uuid()).bind(*revision).bind(configuration.as_slice()).bind(*id).bind(*material_revision).fetch_optional(c).await.map_err(db)
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
        device,

        revision,
        uri,
        material_revision: push.material_revision,
    };
    let receipt = match bearer {
        Some(token) => push
            .send(&wake.uri, token.as_str())
            .await
            .unwrap_or(crate::push::Receipt {
                status: 0,
                outcome: PushOutcome::Unknown,
                retry_after: None,
            }),
        None => crate::push::Receipt {
            status: 0,
            outcome: PushOutcome::Retryable,
            retry_after: None,
        },
    };
    settle(execution, store, key, tenant, &wake, receipt)
        .await
        .map(Some)
}
async fn settle(
    execution: rss_transactional_messaging::fence::ExecutionBinding,
    store: &AuditStore,
    key: &Protector,
    tenant: &str,
    wake: &Wake,
    receipt: crate::push::Receipt,
) -> Result<Duration, Error> {
    let status = receipt.status;
    let outcome = receipt.outcome;
    let retry_after = receipt.retry_after;
    let audit = audit(execution, wake.id, &wake.device);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(3));
    let result=store.write(
            audit.binding()?,
            &budget.source_control(),(store,&audit,key,tenant,wake,status,outcome,retry_after),|inputs,tx|Box::pin(async move {
        let (store,audit,key,tenant,wake,status,outcome,retry_after)=*inputs;
        let changed=tx.with_connection_context(&mut (key,tenant,wake,status,outcome,retry_after),|(key,tenant,wake,status,outcome,retry_after),c|Box::pin(async move {
            let row=sqlx::query("SELECT revision, configuration, digest, lease_id, settled_id, failures, status, outcome FROM mdm_windows.push_channels WHERE tenant_id = CAST($1 AS uuid) AND device = $2 FOR UPDATE")
                .bind(*tenant).bind(wake.device.into_uuid()).fetch_optional(&mut *c).await.map_err(db)?;
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
                    .bind(*tenant).bind(wake.device.into_uuid()).bind(wake.id).bind(i32::from(*status)).execute(c).await.map_err(db)?;
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
                .bind(*tenant).bind(wake.device.into_uuid()).bind(wake.revision).bind(wake.id).bind(i32::from(*status)).bind(outcome.as_str()).bind(failures).bind(delay as f64).bind(retry_at.map(|at|at as f64)).fetch_one(c).await.map_err(db)?;
            Ok(Some((true, Duration::from_secs_f64(wait.min(RECONCILE.as_secs_f64())))))
        })).await?;
        if let Some((changed,_))=changed {

            let fact=Fact::observation(audit, &format!("windows-push:{}:settle",wake.id), 200, "success", None).and_then(|f|f.with_details(serde_json::json!({"status":status,"outcome":outcome,"channelRevision":wake.revision,"materialRevision":wake.material_revision,"retryAfter":retry_after}))).map_err(Error::from)?;
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
    app: Arc<crate::HttpState>,
    eligibility: Arc<dyn WakeDemand>,
    limits: rss_mdm_work_page::external::Limits,
    notify: Arc<tokio::sync::Notify>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("windows-wns", Duration::from_secs(12));
    task.into_registration(move |stop| async move {
        let result: Result<(), std::convert::Infallible> = rss_mdm_work_page::run_limited(
            limits.total,
            RECONCILE,
            &stop,
            &notify,
            (
                |key: &(Uuid, Uuid, Vec<u8>)| {
                    limits.push_quotas(key.0, key.2.clone(), (key.0, key.1))
                },
                |after| {
                    let (app, eligibility) = (&app, &eligibility);
                    async move {
                        let rows = eligibility
                            .candidates(&app.access.pool, after.map(|(t, d, _)| (t, d)))
                            .await
                            .map_err(|_| {
                                eprintln!("windows_push_discovery_failed");
                                rss_mdm_work_page::Failure::Retry
                            })?;
                        let next = if rows.is_empty() {
                            sqlx::query_scalar::<_, Option<f64>>(
                                "SELECT mdm_wns.next_provider_wakeup()",
                            )
                            .fetch_one(&app.access.pool)
                            .await
                            .map_err(|_| rss_mdm_work_page::Failure::Retry)?
                            .map(|s| Duration::from_secs_f64(s.clamp(0., RECONCILE.as_secs_f64())))
                        } else {
                            None
                        };
                        Ok(rss_mdm_work_page::Page { rows, next })
                    }
                },
            ),
            |(tenant, device, credential), stop| {
                let (app, eligibility) = (app.clone(), eligibility.clone());
                async move {
                    let result = async {
                        let tenant =
                            TenantId::parse(&tenant.to_string()).map_err(|_| Error::Malformed)?;
                        let execution = app.execution(tenant);
                        let windows = app.windows(execution).await?;
                        if !windows.push.as_ref().is_some_and(|push| {
                            push.credential().as_slice() == credential.as_slice()
                        }) {
                            return Ok(Duration::ZERO);
                        }
                        let device = rss_mdm_agent_wire::DeviceId::try_from(device)
                            .map_err(|_| Error::Malformed)?;
                        let scan = cycle(
                            execution,
                            &windows,
                            eligibility.as_ref(),
                            &app,
                            &[device],
                            &stop,
                        )
                        .await?;
                        Ok::<_, Error>(scan.next.map_or(RECONCILE, |due| {
                            due.saturating_duration_since(
                                windows
                                    .push
                                    .as_ref()
                                    .expect("scan with a push deadline")
                                    .now(),
                            )
                        }))
                    }
                    .await;
                    result.map_err(|_| {
                        eprintln!(
                            "{}",
                            serde_json::json!({"event":"windows_push_unavailable","tenant":tenant})
                        );
                        rss_mdm_work_page::Failure::Retry
                    })
                }
            },
            |_| {},
        )
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(never) => match never {},
        }
    })
}
