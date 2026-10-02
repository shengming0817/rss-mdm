//! Claim and settle a channel lease; pending execution authority participates in the same transaction.
use crate::push::PushOutcome;
use crate::{Error, Failure, RequestAudit, Store, Windows, database::db};
use rss_mdm_audit_integration::{AuditStore, Fact};
use rss_mdm_native_protection::Protector;
use rss_request_context::TenantId;

/// The worker consumes only current pending-work eligibility on its original connection.
pub trait WakeEligibility: Send + Sync {
    fn pending_in<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        device: &'a str,
        registration: Uuid,
        generation: i64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, Error>> + Send + 'a>>;
}
use sqlx::Row;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
struct Wake {
    id: Uuid,
    registration: Uuid,
    generation: i64,
    revision: i64,
    uri: zeroize::Zeroizing<String>,
}
fn audit(tenant: &str, id: Uuid, registration: Uuid) -> RequestAudit {
    let audit = RequestAudit::new(tenant.into(), "windows_push");
    audit.identify_service("windows-push");
    audit.registration(registration);
    audit.operation(id, "windows_push");
    audit.target(&registration.to_string());
    audit
}
pub async fn cycle(
    w: &Windows,
    eligibility: &dyn WakeEligibility,
    key: &Protector,
    dbase: &Store,
    store: &AuditStore,
    tenant: &str,
) -> Result<bool, Error> {
    let Some(push) = &w.push else {
        return Ok(false);
    };
    let mut after = Uuid::nil();
    loop {
        let mut read = dbase.begin_read(tenant).await?;
        let rows=sqlx::query("SELECT p.registration,p.generation,p.revision,r.device FROM mdm_windows.push_channels p JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(p.tenant_id,p.registration,p.generation) WHERE p.tenant_id=$1::uuid AND p.registration>$2 AND p.configuration=$3 AND p.expires_at>clock_timestamp() AND p.next_push<=clock_timestamp() AND (p.lease_until IS NULL OR p.lease_until<=clock_timestamp()) AND (p.outcome IS NULL OR p.outcome IN ('accepted','retryable','unknown')) AND r.state='active' ORDER BY p.registration LIMIT 32")
            .bind(tenant).bind(after).bind(push.configuration.as_slice()).fetch_all(&mut *read).await.map_err(db)?;
        read.rollback().await.map_err(db)?;
        let count = rows.len();
        for row in rows {
            let registration: Uuid = row.try_get("registration").map_err(db)?;
            after = registration;
            let generation: i64 = row.try_get("generation").map_err(db)?;
            let revision: i64 = row.try_get("revision").map_err(db)?;
            let device: String = row.try_get("device").map_err(db)?;
            let id = Uuid::new_v4();
            let audit = audit(tenant, id, registration);
            let budget =
                rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(3));
            let control = budget.control();
            let outcome=store.write(TenantId::parse(tenant).map_err(|_| Error::Malformed)?,&control,(store,&audit,eligibility,tenant,device.as_str(),registration,generation,revision,id,push.configuration),|inputs,tx|Box::pin(async move {
                let (store,audit,eligibility,tenant,device,registration,generation,revision,id,configuration)=*inputs;
                let sealed=tx.with_connection_context(&mut (eligibility,tenant,device,registration,generation,revision,id,configuration),|(eligibility,tenant,device,registration,generation,revision,id,configuration),c|Box::pin(async move {
                    if !eligibility.pending_in(c, device, *registration, *generation).await? { return Ok::<_,Error>(None) }
                    if !crate::device::store::active_source_in(c,tenant,*registration,rss_mdm_inventory::ReportSource::MdmWindows).await? {return Ok::<_,Error>(None)}
                    sqlx::query_scalar::<_,Vec<u8>>("UPDATE mdm_windows.push_channels SET lease_id=$6,lease_until=clock_timestamp()+interval '30 seconds',settled_id=NULL WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND revision=$4 AND configuration=$5 AND expires_at>clock_timestamp() AND next_push<=clock_timestamp() AND (lease_until IS NULL OR lease_until<=clock_timestamp()) AND (outcome IS NULL OR outcome IN ('accepted','retryable','unknown')) RETURNING uri")
                        .bind(*tenant).bind(*registration).bind(*generation).bind(*revision).bind(configuration.as_slice()).bind(*id).fetch_optional(c).await.map_err(db)
                })).await?;
                if sealed.is_some() {
                    let input=serde_json::to_vec(&(registration,generation,revision,id)).map_err(|_|Error::Malformed)?;
                    let fact=Fact::business(audit,&format!("windows-push:{id}:lease"),&input,200,"success",None).map_err(Error::from)?;
                    store.append(tx,&fact,false).await.map_err(Error::from)?;audit.mark_commit_started();
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
            let Some(sealed) = sealed? else { continue };
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
            settle(store, tenant, &wake, receipt).await?;
            return Ok(true);
        }
        if count < 32 {
            return Ok(false);
        }
    }
}
async fn settle(
    store: &AuditStore,
    tenant: &str,
    wake: &Wake,
    receipt: crate::push::Receipt,
) -> Result<(), Error> {
    let status = receipt.status;
    let outcome = receipt.outcome;
    let retry_after = i64::try_from(receipt.retry_after.map_or(0, |wait| wait.as_secs()))
        .map_err(|_| Error::Malformed)?;
    let audit = audit(tenant, wake.id, wake.registration);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(3));
    let control = budget.control();
    let result=store.write(TenantId::parse(tenant).map_err(|_| Error::Malformed)?,&control,(store,&audit,tenant,wake,status,outcome,retry_after),|inputs,tx|Box::pin(async move {
        let (store,audit,tenant,wake,status,outcome,retry_after)=*inputs;
        let changed=tx.with_connection_context(&mut (tenant,wake,status,outcome,retry_after),|(tenant,wake,status,outcome,retry_after),c|Box::pin(async move {
            let row=sqlx::query("SELECT lease_id,settled_id,failures,status,outcome FROM mdm_windows.push_channels WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND revision=$4 FOR UPDATE")
                .bind(*tenant).bind(wake.registration).bind(wake.generation).bind(wake.revision).fetch_optional(&mut *c).await.map_err(db)?;
            let Some(row)=row else {return Ok::<_,Error>(None)};
            if row.try_get::<Option<Uuid>,_>("settled_id").map_err(db)?==Some(wake.id) {
                if row.try_get::<Option<i32>,_>("status").map_err(db)?!=Some(i32::from(*status)) || row.try_get::<Option<String>,_>("outcome").map_err(db)?.as_deref()!=Some(outcome.as_str()) {return Err(Error::Conflict)}
                return Ok(Some(false));
            }
            if row.try_get::<Option<Uuid>,_>("lease_id").map_err(db)?!=Some(wake.id) {return Ok(None)}
            let failures=if matches!(*outcome, PushOutcome::Retryable | PushOutcome::Unknown) {(row.try_get::<i32,_>("failures").map_err(db)?+1).min(6)} else {0};
            let delay=if matches!(*outcome, PushOutcome::Retryable | PushOutcome::Unknown) {(15i64*(1<<failures)).max(*retry_after)} else {120};
            sqlx::query("UPDATE mdm_windows.push_channels SET lease_id=NULL,lease_until=NULL,settled_id=$5,status=$6,outcome=$7,failures=$8,next_push=clock_timestamp()+make_interval(secs=>$9::double precision) WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND revision=$4")
                .bind(*tenant).bind(wake.registration).bind(wake.generation).bind(wake.revision).bind(wake.id).bind(i32::from(*status)).bind(outcome.as_str()).bind(failures).bind(delay as f64).execute(c).await.map_err(db)?;
            Ok(Some(true))
        })).await?;
        if let Some(changed)=changed {
            let input=serde_json::to_vec(&(wake.registration,wake.revision,wake.id,status,outcome,retry_after)).map_err(|_|Error::Malformed)?;
            let fact=Fact::business(audit,&format!("windows-push:{}:settle",wake.id),&input,200,"success",None).and_then(|f|f.with_details(serde_json::json!({"status":status,"outcome":outcome,"channelRevision":wake.revision,"retryAfterSeconds":retry_after}))).map_err(Error::from)?;
            store.append(tx,&fact,!changed).await.map_err(Error::from)?;audit.mark_commit_started();
        }
        Ok(())
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
    eligibility: Arc<dyn WakeEligibility>,
    key: Arc<Protector>,
    database: Arc<Store>,
    store: Arc<AuditStore>,
    tenant: String,
    notify: Arc<tokio::sync::Notify>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("windows-wns", Duration::from_secs(8));
    task.into_registration(move|stop|async move {
        let mut failures=0u64;
        loop {
            let result=tokio::select! {biased;()=stop.cancelled()=>return Ok(()),result=cycle(&w,eligibility.as_ref(),&key,&database,&store,&tenant)=>result};
            match result {Ok(true)=>{failures=0;continue},Ok(false)=>failures=0,Err(_)=>{failures=failures.saturating_add(1);if failures.is_power_of_two() {eprintln!("{}",serde_json::json!({"event":"windows_push_unavailable","consecutive_failures":failures}));}}}
            tokio::select! {biased; ()=stop.cancelled()=>return Ok(()), ()=notify.notified()=>{}, ()=tokio::time::sleep(Duration::from_secs(5))=>{}}
        }
    })
}
