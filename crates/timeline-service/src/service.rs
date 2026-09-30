use crate::{Coverage, Error, FactView, Page, Query, cursor, project};
use rss_mdm_audit_integration::{AuditStore, budget::AuditBudget};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_request_context::TenantId;
use sha2::{Digest, Sha256};
use sqlx::{Acquire, PgPool, Row};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;
/// Borrows the App-owned pool. Owns only the product projection and managed task.
pub struct Timeline {
    pool: PgPool,
    audit: Arc<AuditStore>,
    tenant: TenantId,
    key: ring::hmac::Key,
    healthy: AtomicBool,
}
struct Projected {
    view: FactView,
    devices: Vec<String>,
}
struct Window {
    indexed: i64,
    source: i64,
    generation: Uuid,
    healthy: bool,
}
impl Timeline {
    pub fn new(
        pool: PgPool,
        audit: Arc<AuditStore>,
        tenant: TenantId,
        secret: &[u8],
    ) -> Result<Self, Error> {
        if secret.len() != 32 {
            return Err(Error::Integrity);
        }
        Ok(Self {
            pool,
            audit,
            tenant,
            key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret),
            healthy: AtomicBool::new(true),
        })
    }
    /// Initialize only rebuildable product coordinates. Does not append an Audit fact.
    pub async fn initialize(&self) -> Result<(), Error> {
        let mut connection = None;
        let result=tokio::time::timeout(Duration::from_secs(5),async{
            connection=Some(self.pool.acquire().await?);
            let mut tx=connection.as_mut().ok_or(Error::Storage)?.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','2000',true),set_config('lock_timeout','1000',true)").bind(self.tenant.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO mdm_timeline.checkpoints(tenant_id,generation) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(self.tenant.to_string()).bind(Uuid::new_v4()).execute(&mut *tx).await?;
            tx.commit().await?;Ok::<_,Error>(())
        }).await.map_err(|_|Error::Deadline).and_then(|v|v);
        if result.is_err()
            && let Some(c) = &mut connection
        {
            c.close_on_drop()
        }
        result
    }
    pub fn registration(self: Arc<Self>) -> rss_runtime::ManagedTaskRegistration {
        let (task, _) =
            rss_runtime::ManagedTask::prepare("device-timeline", Duration::from_secs(20));
        task.into_registration(move|stop|async move{
            while !stop.is_cancelled(){
                let result=self.catch_up().await;
                self.healthy.store(result.is_ok(),Ordering::Release);
                match result {
                    Ok(n) if n>0=>continue,
                    Err(Error::Integrity)=>return Err(rss_runtime::ShutdownError::new(Error::Integrity)),
                    Err(_)=>eprintln!("{}",serde_json::json!({"event":"timeline_projection_unavailable"})),
                    _=>{},
                }
                tokio::select!{()=stop.cancelled()=>break,()=tokio::time::sleep(Duration::from_secs(1))=>{}}
            }
            Ok(())
        })
    }
    /// Consume one bounded source batch. Concurrent workers serialize only the index commit.
    pub async fn catch_up(&self) -> Result<usize, Error> {
        let result = self.catch_up_inner().await;
        self.healthy.store(result.is_ok(), Ordering::Release);
        if result.is_err() {
            let _ = self.mark_unhealthy().await;
        }
        result
    }
    async fn mark_unhealthy(&self) -> Result<(), Error> {
        let mut connection = None;
        let result=tokio::time::timeout(Duration::from_secs(3),async{
            connection=Some(self.pool.acquire().await?);
            let mut tx=connection.as_mut().ok_or(Error::Storage)?.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','1000',true),set_config('lock_timeout','1000',true)").bind(self.tenant.to_string()).execute(&mut *tx).await?;
            sqlx::query("UPDATE mdm_timeline.checkpoints SET healthy=false WHERE tenant_id=$1::uuid").bind(self.tenant.to_string()).execute(&mut *tx).await?;
            tx.commit().await?;Ok::<_,Error>(())
        }).await.map_err(|_|Error::Deadline).and_then(|v|v);
        if result.is_err()
            && let Some(c) = &mut connection
        {
            c.close_on_drop()
        }
        result
    }
    async fn catch_up_inner(&self) -> Result<usize, Error> {
        let (after, last_source, _, healthy) = self.checkpoint().await?;
        let budget = AuditBudget::new(Duration::from_secs(5));
        let control = budget.control();
        let attempt=self.audit.read(self.tenant,&control,(self,after),|(service,after),tx|Box::pin(async move{
            let head=tx.read_page(rss_audit_postgres::Cursor::start(service.tenant),rss_audit_postgres::ReadLimit::new(1,131072).map_err(|_|Error::Integrity)?).await.map_err(audit_error)?;
            let through=source_through(&head);
            if through<*after{return Err(Error::Integrity)}
            if through==*after{return Ok((Vec::new(),through))}
            let cursor=if *after<0{rss_audit_postgres::Cursor::start(service.tenant)}else{rss_audit_postgres::Cursor::resume(service.tenant,*after as u64,through as u64).map_err(|_|Error::Integrity)?};
            let page=tx.read_page(cursor,rss_audit_postgres::ReadLimit::new(64,8388608).map_err(|_|Error::Integrity)?).await.map_err(audit_error)?;
            let through=source_through(&page);let mut batch=Vec::new();
            for record in page.records(){
                let decoded=rss_audit_core::decode_untrusted(record.prepared().canonical_bytes()).map_err(|_|Error::Integrity)?;
                let mut view=project(decoded.event())?;
                view.position=record.position();view.recorded_at=decoded.recorded_at().unix_seconds();
                let tenant=service.tenant.to_string();
                let mut context=(tenant,view);
                let devices=tx.with_connection_context(&mut context,|(tenant,view),c|Box::pin(async move{
                    if view.supported&&let Some(op)=view.operation_id&&matches!(view.action.as_str(),"command_cancel"|"command_approve"|"command_dispatch"|"command_reconcile"){
                        view.related_operation_ids=rss_mdm_flow_service::execution::timeline::related_operations_in(c,tenant,&view.actor,op).await?;
                    }
                    correlate(c,tenant,view).await
                })).await?;
                batch.push(Projected{view:context.1,devices});
            }
            Ok::<_,Error>((batch,through))
        })).await;
        let (batch, through) = attempt.fold(
            |v| Ok(v.into_value()),
            |_| Err(Error::Storage),
            transaction_error,
            |_| Err(Error::Storage),
            |_| Err(Error::Storage),
            |_| Err(Error::Storage),
        )?;
        if batch.is_empty() && last_source == through && healthy {
            return Ok(0);
        }
        self.write_batch(after, &batch, through).await
    }
    async fn checkpoint(&self) -> Result<(i64, i64, Uuid, bool), Error> {
        let budget = AuditBudget::new(Duration::from_secs(3));
        let control = budget.control();
        self.audit.read(self.tenant,&control,self,|service,tx|Box::pin(async move{
            let tenant=service.tenant.to_string();
            tx.with_connection(|c|Box::pin(async move{
                sqlx::query_as("SELECT position,source_through,generation,healthy FROM mdm_timeline.checkpoints WHERE tenant_id=$1::uuid")
                    .bind(tenant).fetch_optional(c).await?.ok_or(Error::Storage)
            })).await
        })).await.fold(|v|Ok(v.into_value()),|_|Err(Error::Storage),transaction_error,|_|Err(Error::Storage),|_|Err(Error::Storage),|_|Err(Error::Storage))
    }
    async fn write_batch(
        &self,
        after: i64,
        batch: &[Projected],
        through: i64,
    ) -> Result<usize, Error> {
        let mut connection = None;
        let result=tokio::time::timeout(Duration::from_secs(5),async{
            connection=Some(self.pool.acquire().await?);
            let mut tx=connection.as_mut().ok_or(Error::Storage)?.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','2000',true),set_config('lock_timeout','1000',true)")
                .bind(self.tenant.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO mdm_timeline.checkpoints(tenant_id,generation) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING")
                .bind(self.tenant.to_string()).bind(Uuid::new_v4()).execute(&mut *tx).await?;
            let position:i64=sqlx::query_scalar("SELECT position FROM mdm_timeline.checkpoints WHERE tenant_id=$1::uuid FOR UPDATE")
                .bind(self.tenant.to_string()).fetch_one(&mut *tx).await?;
            if position!=after{tx.rollback().await?;return Ok(0)}
            for row in batch{
                let doc=serde_json::to_value(&row.view).map_err(|_|Error::Integrity)?;
                let bytes=serde_json::to_vec(&doc).map_err(|_|Error::Integrity)?;
                sqlx::query("INSERT INTO mdm_timeline.facts(tenant_id,position,source,event_id,recorded_at,instance_id,operation_id,actor,action,outcome,devices,operations,document,digest) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
                    .bind(self.tenant.to_string()).bind(row.view.position as i64).bind(&row.view.source).bind(&row.view.event_id)
                    .bind(row.view.recorded_at).bind(row.view.instance_id).bind(row.view.operation_id).bind(&row.view.actor).bind(&row.view.action)
                    .bind(&row.view.audit_outcome).bind(&row.devices).bind(&row.view.related_operation_ids).bind(doc).bind(Sha256::digest(&bytes).to_vec()).execute(&mut *tx).await?;
            }
            let next=batch.last().map_or(after,|v|v.view.position as i64);
            sqlx::query("UPDATE mdm_timeline.checkpoints SET position=$2,source_through=$3,healthy=true WHERE tenant_id=$1::uuid")
                .bind(self.tenant.to_string()).bind(next).bind(through.max(next)).execute(&mut *tx).await?;
            tx.commit().await?;Ok::<_,Error>(batch.len())
        }).await.map_err(|_|Error::Deadline).and_then(|v|v);
        if result.is_err()
            && let Some(c) = &mut connection
        {
            c.close_on_drop()
        }
        result
    }
    /// Use the already loaded administrator proof; no session/rules reload occurs here.
    pub async fn query(
        &self,
        proof: &AuthorizedPrincipal,
        family: &str,
        query: &Query,
    ) -> Result<Page, Error> {
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        proof
            .require(Permission::AuthorizationRead, None)
            .map_err(|_| Error::Forbidden)?;
        query.validate()?;
        if !self.healthy.load(Ordering::Acquire) {
            return Err(Error::Storage);
        }
        let budget = AuditBudget::new(Duration::from_secs(5));
        let control = budget.control();
        self.audit.read(self.tenant,&control,(self,proof,family,query),|ctx,tx|Box::pin(async move{
            let tenant=ctx.0.tenant.to_string();
            let checkpoint:(i64,Uuid,bool)=tx.with_connection(move|c|Box::pin(async move{
                sqlx::query_as("SELECT position,generation,healthy FROM mdm_timeline.checkpoints WHERE tenant_id=$1::uuid").bind(tenant).fetch_one(c).await
            })).await?;
            // Read the source head after the checkpoint: concurrent appends cannot make a
            // newer projection appear to exceed an older, previously observed source head.
            let head=tx.read_page(rss_audit_postgres::Cursor::start(ctx.0.tenant),rss_audit_postgres::ReadLimit::new(1,131072).map_err(|_|Error::Integrity)?).await.map_err(audit_error)?;
            let mut context=(*ctx,Window{indexed:checkpoint.0,generation:checkpoint.1,healthy:checkpoint.2,source:source_through(&head)});
            tx.with_connection_context(&mut context,|(ctx,window),c|Box::pin(async move{
                let (service,proof,family,query)=*ctx;
                service.page_in(c,proof,family,query,window).await
            })).await
        })).await.fold(|v|Ok(v.into_value()),|_|Err(Error::Storage),transaction_error,|_|Err(Error::Storage),|_|Err(Error::Storage),|_|Err(Error::Storage))
    }
    async fn page_in(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        family: &str,
        query: &Query,
        window: &Window,
    ) -> Result<Page, Error> {
        let tenant = self.tenant.to_string();
        let tenant = tenant.as_str();
        let Window {
            indexed,
            source,
            generation,
            healthy,
        } = *window;
        if !healthy {
            return Err(Error::Storage);
        }
        if indexed > source {
            return Err(Error::Integrity);
        }
        let mut through = indexed;
        let mut after = None;
        let mut after_position = None;
        if let Some(token) = &query.cursor {
            let token = cursor::decode(&self.key, token)?;
            if token.tenant != tenant
                || token.instance != proof.instance_id()
                || token.family != family
                || token.query != query.binding()
                || token.generation != generation
                || token.through > indexed
                || token.through < 0
                || token.after_position < 0
                || token.after_position > token.through
                || token.after_at < 0
            {
                return Err(Error::Conflict);
            }
            through = token.through;
            after = Some(token.after_at);
            after_position = Some(token.after_position);
        }
        let limit = query.limit.unwrap_or(50);
        let mut rows=sqlx::query("SELECT document,digest,position,recorded_at FROM mdm_timeline.facts WHERE tenant_id=$1::uuid AND position<=$2 AND (instance_id=$3::uuid OR (instance_id IS NULL AND document->>'supported'='true' AND document->>'actorKind' IN ('service','device','unidentified'))) AND ($4::text IS NULL OR devices @> ARRAY[$4]) AND ($5::uuid IS NULL OR operation_id=$5 OR operations @> ARRAY[$5]) AND ($6::text IS NULL OR actor=$6) AND ($7::text IS NULL OR action=$7) AND ($8::text IS NULL OR outcome=$8) AND ($9::bigint IS NULL OR recorded_at>=$9) AND ($10::bigint IS NULL OR recorded_at<$10) AND ($11::bigint IS NULL OR (recorded_at,position)<($11,$12)) ORDER BY recorded_at DESC,position DESC LIMIT $13")
            .bind(tenant).bind(through).bind(proof.instance_id()).bind(&query.device).bind(query.operation_id)
            .bind(&query.actor).bind(&query.action).bind(&query.outcome).bind(query.from).bind(query.until).bind(after).bind(after_position).bind((limit+1) as i64).fetch_all(c).await?;
        let more = rows.len() > limit;
        rows.truncate(limit);
        let mut items = Vec::new();
        for row in rows {
            let doc: serde_json::Value = row.try_get("document")?;
            let bytes = serde_json::to_vec(&doc).map_err(|_| Error::Integrity)?;
            if Sha256::digest(&bytes).as_slice() != row.try_get::<Vec<u8>, _>("digest")? {
                return Err(Error::Integrity);
            }
            let view: FactView = serde_json::from_value(doc).map_err(|_| Error::Integrity)?;
            if view.position as i64 != row.try_get::<i64, _>("position")?
                || view.recorded_at != row.try_get::<i64, _>("recorded_at")?
            {
                return Err(Error::Integrity);
            }
            items.push(view);
        }
        let next_cursor = if more {
            items
                .last()
                .map(|last| {
                    cursor::encode(
                        &self.key,
                        &cursor::Cursor {
                            tenant: tenant.into(),
                            instance: proof.instance_id().into(),
                            family: family.into(),
                            query: query.binding(),
                            generation,
                            through,
                            after_at: last.recorded_at,
                            after_position: last.position as i64,
                        },
                    )
                })
                .transpose()?
        } else {
            None
        };
        Ok(Page {
            items,
            next_cursor,
            coverage: Coverage {
                indexed_through: (through >= 0).then_some(through as u64),
                source_through: (source >= 0).then_some(source as u64),
                complete: through == source,
            },
        })
    }
}
fn source_through(page: &rss_audit_postgres::Page) -> i64 {
    page.next()
        .and_then(|v| v.continuation())
        .map(|(_, v)| v as i64)
        .or_else(|| page.records().last().map(|v| v.position() as i64))
        .unwrap_or(-1)
}
async fn correlate(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    view: &FactView,
) -> Result<Vec<String>, Error> {
    if !view.supported {
        return Ok(Vec::new());
    }
    let mut devices = std::collections::BTreeSet::new();
    if let Some(device) = &view.device_id
        && rss_mdm_registration_service::device::read::exists(c, tenant.into(), device.clone())
            .await?
    {
        devices.insert(device.clone());
    }
    if let Some(reg) = view.registration_id
        && let Some(device) =
            rss_mdm_registration_service::device::read::timeline_device_in(c, tenant, reg).await?
    {
        devices.insert(device);
    }
    if let Some(request) = view.registration_request_id
        && let Some(device) =
            rss_mdm_registration_service::device::read::timeline_enrollment_in(c, tenant, request)
                .await?
    {
        devices.insert(device);
    }
    if let Some(op) = view.operation_id {
        if matches!(
            view.action.as_str(),
            "command_accept"
                | "command_dispatch"
                | "command_cancel"
                | "command_reconcile"
                | "command_read"
                | "device_action"
        ) {
            devices.extend(
                rss_mdm_flow_service::execution::timeline::devices_in(c, tenant, op).await?,
            );
        }
        if view.action == "management_write"
            && view.source == "mdm.business"
            && let Some(device) = rss_mdm_inventory_service::assets::timeline_device_in(
                c,
                tenant,
                &view.actor,
                op,
                &view.event_id,
            )
            .await?
        {
            devices.insert(device);
        }
    }
    for operation in &view.related_operation_ids {
        devices.extend(
            rss_mdm_flow_service::execution::timeline::devices_in(c, tenant, *operation).await?,
        );
    }
    if matches!(
        view.action.as_str(),
        "registration_bind"
            | "credential_revoke"
            | "enrollment_create"
            | "enrollment_read"
            | "enrollment_resume"
            | "enrollment_cancel"
            | "inventory_read"
            | "command_accept"
            | "command_approve"
            | "command_cancel"
            | "command_read"
            | "command_reconcile"
            | "device_action"
    ) && let Some(target) = &view.target
        && rss_mdm_registration_service::device::read::exists(c, tenant.into(), target.clone())
            .await?
    {
        devices.insert(target.clone());
    }
    if devices.len() > 10000 || devices.iter().any(|v| !crate::model::identifier(v)) {
        return Err(Error::Integrity);
    }
    Ok(devices.into_iter().collect())
}

fn audit_error(error: rss_audit_postgres::Error) -> Error {
    match error {
        rss_audit_postgres::Error::StorageContract
        | rss_audit_postgres::Error::Protocol(_)
        | rss_audit_postgres::Error::Conflict => Error::Integrity,
        rss_audit_postgres::Error::Deadline(_) | rss_audit_postgres::Error::Cancelled(_) => {
            Error::Deadline
        }
        _ => Error::Storage,
    }
}
fn transaction_error<R>(error: rss_audit_postgres::TransactionError<Error>) -> Result<R, Error> {
    Err(match error {
        rss_audit_postgres::TransactionError::Operation(e) => e,
        rss_audit_postgres::TransactionError::Audit(e) => audit_error(e),
        _ => Error::Storage,
    })
}
