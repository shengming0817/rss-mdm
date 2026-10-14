use crate::{Coverage, Error, FactView, Page, Query, cursor, project};
use rss_mdm_audit_integration::{
    AuditStore,
    budget::{AuditBudget, RuntimeTimer},
};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_request_context::{Clock, Deadline, TenantId};
use sha2::{Digest, Sha256};
use sqlx::{Acquire, PgPool, Row};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
/// Borrows the App-owned pool. Owns only the request-driven product projection.
pub struct Timeline {
    pool: PgPool,
    audit: Arc<AuditStore>,
    tenant: TenantId,
    key: ring::hmac::Key,
}
type Prepared = ((i64, i64, Uuid), Vec<Projected>, i64);
struct Projected {
    view: FactView,
    devices: Vec<String>,
}
struct Window {
    indexed: i64,
    source: i64,
    generation: Uuid,
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
    /// Authorized reads advance at most one source batch before reading a frozen index window.
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
        let token = query
            .cursor
            .as_ref()
            .map(|v| cursor::decode(&self.key, v))
            .transpose()?;
        // Reject immutable cursor bindings before any source read or projection write.
        if let Some(token) = &token {
            self.validate_cursor(
                proof,
                family,
                query,
                Some(token),
                token.generation,
                token.through,
            )?;
        }
        let start = RuntimeTimer.now();
        let budget = AuditBudget::new(Duration::from_secs(5));
        let total = Deadline::at(start + Duration::from_secs(2));
        let operation = Deadline::at(start + Duration::from_millis(1500));
        let control = budget.control_until(total, operation);
        if let Some((checkpoint, batch, through)) = self
            .prepare_batch(proof, family, query, token.as_ref(), &control)
            .await?
        {
            if !batch.is_empty() || checkpoint.1 != through {
                self.write_batch(checkpoint, &batch, through, total, operation)
                    .await?;
            }
        }
        let control = budget.control();
        self.audit
            .read(
                self.tenant,
                &control,
                (self, proof, family, query, token),
                |ctx, tx| {
                    Box::pin(async move {
                        let mut indexed = tx
                            .with_connection_context(ctx, |ctx, c| {
                                Box::pin(async move {
                                    ctx.0.read_index(c, ctx.1, ctx.3, ctx.4.as_ref()).await
                                })
                            })
                            .await?;
                        let head = tx
                            .read_page(
                                rss_audit_postgres::Cursor::start(ctx.0.tenant),
                                rss_audit_postgres::ReadLimit::new(1, 131072)
                                    .map_err(|_| Error::Integrity)?,
                            )
                            .await
                            .map_err(audit_error)?;
                        let source = source_through(&head);
                        if source < indexed.0.source {
                            return Err(Error::Integrity);
                        }
                        indexed.0.source = source;
                        ctx.0
                            .page_in(ctx.1, ctx.2, ctx.3, ctx.4.as_ref(), &indexed.0, indexed.1)
                    })
                },
            )
            .await
            .fold(
                |v| Ok(v.into_value()),
                transaction_error,
                transaction_error,
                transaction_error,
                transaction_error,
                transaction_error,
            )
    }
    async fn prepare_batch(
        &self,
        proof: &AuthorizedPrincipal,
        family: &str,
        query: &Query,
        token: Option<&cursor::Cursor>,
        control: &rss_audit_postgres::Control<'_, RuntimeTimer>,
    ) -> Result<Option<Prepared>, Error> {
        let attempt=self.audit.read(self.tenant,control,(self,proof,family,query,token),|(service,proof,family,query,token),tx|Box::pin(async move{
            let tenant=service.tenant.to_string();
            let checkpoint:(i64,i64,Uuid)=tx.with_connection(|c|Box::pin(async move{
                sqlx::query_as("SELECT position,source_through,generation FROM mdm_timeline.checkpoints WHERE tenant_id=$1::uuid").bind(tenant).fetch_one(c).await
            })).await?;
            let after=checkpoint.0;
            service.validate_cursor(proof,family,query,*token,checkpoint.2,after)?;
            let page=if after<0 {
                tx.read_page(rss_audit_postgres::Cursor::start(service.tenant),rss_audit_postgres::ReadLimit::new(64,8388608).map_err(|_|Error::Integrity)?).await.map_err(audit_error)?
            } else {
                let head=tx.read_page(rss_audit_postgres::Cursor::start(service.tenant),rss_audit_postgres::ReadLimit::new(1,131072).map_err(|_|Error::Integrity)?).await.map_err(audit_error)?;
                let through=source_through(&head);
                if through<after || through<checkpoint.1 {return Err(Error::Integrity)}
                if through==after {return Ok((checkpoint,Vec::new(),through))}
                let cursor=rss_audit_postgres::Cursor::resume(service.tenant,after as u64,through as u64).map_err(|_|Error::Integrity)?;
                tx.read_page(cursor,rss_audit_postgres::ReadLimit::new(64,8388608).map_err(|_|Error::Integrity)?).await.map_err(audit_error)?
            };
            let through=source_through(&page);
            if through<after || through<checkpoint.1 {return Err(Error::Integrity)}
            let mut batch=Vec::new();
            for record in page.records(){
                let decoded=rss_audit_core::decode_untrusted(record.prepared().canonical_bytes()).map_err(|_|Error::Integrity)?;
                let mut view=project(decoded.event())?;
                view.position=record.position();view.recorded_at=decoded.recorded_at().unix_seconds();
                let identity=crate::projection::execution_identity(decoded.event(),&view)?;
                let tenant=service.tenant.to_string();
                let mut context=(tenant,view,identity);
                let devices=tx.with_connection_context(&mut context,|(tenant,view,identity),c|Box::pin(async move{
                    let association=match identity {
                        Some(identity)=>rss_mdm_execution_service::timeline::association_in(c,tenant,&view.actor,*identity).await?,
                        None=>None,
                    };
                    if let Some((_,Some(operation)))=&association {view.related_operation_ids.push(*operation);}
                    let mut devices=correlate(c,tenant,view).await?;
                    if let Some((device,_))=association {
                        if !crate::model::identifier(&device) {return Err(Error::Integrity)}
                        if !devices.contains(&device) {devices.push(device);}
                    }
                    Ok(devices)
                })).await?;
                batch.push(Projected{view:context.1,devices});
            }
            Ok::<_,Error>((checkpoint,batch,through))
        })).await;
        // Only acknowledged, ordinary budget exhaustion permits a partial indexed response.
        attempt.fold(
            |v| Ok(Some(v.into_value())),
            limited_transaction,
            limited_transaction,
            |e| transaction_error(e),
            |e| transaction_error(e),
            |e| transaction_error(e),
        )
    }
    async fn write_batch(
        &self,
        checkpoint: (i64, i64, Uuid),
        batch: &[Projected],
        through: i64,
        total: Deadline,
        operation: Deadline,
    ) -> Result<(), Error> {
        if operation.is_expired(RuntimeTimer.now()) {
            return Ok(());
        }
        let mut connection =
            match tokio::time::timeout_at(operation.instant().into(), self.pool.acquire()).await {
                Ok(result) => result?,
                Err(_) => return Ok(()), // No product transaction was started.
            };
        let result = self
            .write_batch_on(
                &mut connection,
                checkpoint,
                batch,
                through,
                total,
                operation,
            )
            .await;
        if result.is_err() {
            connection.close_on_drop();
        }
        result
    }
    async fn write_batch_on(
        &self,
        connection: &mut sqlx::PgConnection,
        checkpoint: (i64, i64, Uuid),
        batch: &[Projected],
        through: i64,
        total: Deadline,
        operation: Deadline,
    ) -> Result<(), Error> {
        let mut tx = tokio::time::timeout_at(operation.instant().into(), connection.begin())
            .await
            .map_err(|_| Error::Deadline)??;
        let result=tokio::time::timeout_at(operation.instant().into(),async{
            let milliseconds=operation.remaining(RuntimeTimer.now()).unwrap_or_default().as_millis().saturating_add(1).to_string();
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)").bind(self.tenant.to_string()).bind(milliseconds).execute(&mut *tx).await.map_err(|e|projection_error(e,operation))?;
            let current:(i64,Uuid)=sqlx::query_as("SELECT position,generation FROM mdm_timeline.checkpoints WHERE tenant_id=$1::uuid FOR UPDATE").bind(self.tenant.to_string()).fetch_one(&mut *tx).await.map_err(|e|projection_error(e,operation))?;
            if current!=(checkpoint.0,checkpoint.2) {return Ok(false)}
            for row in batch {
                let doc=serde_json::to_value(&row.view).map_err(|_|Error::Integrity)?;
                let bytes=serde_json::to_vec(&doc).map_err(|_|Error::Integrity)?;
                sqlx::query("INSERT INTO mdm_timeline.facts(tenant_id,position,source,event_id,recorded_at,instance_id,operation_id,actor,action,outcome,devices,operations,document,digest) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
                    .bind(self.tenant.to_string()).bind(row.view.position as i64).bind(&row.view.source).bind(&row.view.event_id)
                    .bind(row.view.recorded_at).bind(row.view.instance_id).bind(row.view.operation_id).bind(&row.view.actor).bind(&row.view.action)
                    .bind(&row.view.audit_outcome).bind(&row.devices).bind(&row.view.related_operation_ids).bind(doc).bind(Sha256::digest(&bytes).to_vec()).execute(&mut *tx).await.map_err(|e|projection_error(e,operation))?;
            }
            let next=batch.last().map_or(checkpoint.0,|v|v.view.position as i64);
            sqlx::query("UPDATE mdm_timeline.checkpoints SET position=$2,source_through=$3 WHERE tenant_id=$1::uuid").bind(self.tenant.to_string()).bind(next).bind(through).execute(&mut *tx).await.map_err(|e|projection_error(e,operation))?;
            Ok::<_,Error>(true)
        }).await;
        match result {
            Ok(Ok(true)) => tokio::time::timeout_at(total.instant().into(), tx.commit())
                .await
                .map_err(|_| Error::Deadline)?
                .map_err(Error::from),
            other => {
                let primary = match other {
                    Ok(Err(error)) => Some(error),
                    _ => None,
                };
                let rollback = tokio::time::timeout_at(total.instant().into(), tx.rollback()).await;
                if matches!(primary, Some(Error::Integrity)) {
                    return Err(Error::Integrity);
                }
                rollback.map_err(|_| Error::Deadline)??;
                match primary {
                    Some(Error::Deadline) | None => Ok(()),
                    Some(error) => Err(error),
                }
            }
        }
    }
    fn validate_cursor(
        &self,
        proof: &AuthorizedPrincipal,
        family: &str,
        query: &Query,
        token: Option<&cursor::Cursor>,
        generation: Uuid,
        indexed: i64,
    ) -> Result<(), Error> {
        if let Some(token) = token {
            if token.tenant != self.tenant.to_string()
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
        }
        Ok(())
    }
    async fn read_index(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        query: &Query,
        token: Option<&cursor::Cursor>,
    ) -> Result<(Window, Vec<sqlx::postgres::PgRow>), Error> {
        // Checkpoint and facts share one READ COMMITTED statement snapshot, including empty pages.
        let rows=sqlx::query("SELECT cp.position AS indexed,cp.source_through,cp.generation,f.document,f.digest,f.position,f.recorded_at FROM mdm_timeline.checkpoints cp LEFT JOIN LATERAL (SELECT document,digest,position,recorded_at FROM mdm_timeline.facts WHERE tenant_id=cp.tenant_id AND position<=COALESCE($2,cp.position) AND (instance_id=$3::uuid OR (instance_id IS NULL AND document->>'supported'='true' AND document->>'actorKind' IN ('service','device','unidentified'))) AND ($4::text IS NULL OR devices @> ARRAY[$4]) AND ($5::uuid IS NULL OR operation_id=$5 OR operations @> ARRAY[$5]) AND ($6::text IS NULL OR actor=$6) AND ($7::text IS NULL OR action=$7) AND ($8::text IS NULL OR outcome=$8) AND ($9::bigint IS NULL OR recorded_at>=$9) AND ($10::bigint IS NULL OR recorded_at<$10) AND ($11::bigint IS NULL OR (recorded_at,position)<($11,$12)) ORDER BY recorded_at DESC,position DESC LIMIT $13) f ON true WHERE cp.tenant_id=$1::uuid ORDER BY f.recorded_at DESC,f.position DESC")
            .bind(self.tenant.to_string()).bind(token.map(|v|v.through)).bind(proof.instance_id()).bind(&query.device).bind(query.operation_id)
            .bind(&query.actor).bind(&query.action).bind(&query.outcome).bind(query.from).bind(query.until).bind(token.map(|v|v.after_at)).bind(token.map(|v|v.after_position)).bind((query.limit.unwrap_or(50)+1) as i64).fetch_all(c).await?;
        let first = rows.first().ok_or(Error::Storage)?;
        let window = Window {
            indexed: first.try_get("indexed")?,
            source: first.try_get("source_through")?,
            generation: first.try_get("generation")?,
        };
        Ok((window, rows))
    }
    fn page_in(
        &self,
        proof: &AuthorizedPrincipal,
        family: &str,
        query: &Query,
        token: Option<&cursor::Cursor>,
        window: &Window,
        mut rows: Vec<sqlx::postgres::PgRow>,
    ) -> Result<Page, Error> {
        let tenant = self.tenant.to_string();
        let Window {
            indexed,
            source,
            generation,
        } = *window;
        self.validate_cursor(proof, family, query, token, generation, indexed)?;
        if indexed > source {
            return Err(Error::Integrity);
        }
        let through = token.map_or(indexed, |v| v.through);
        let limit = query.limit.unwrap_or(50);
        if rows
            .first()
            .is_some_and(|v| v.try_get::<Option<i64>, _>("position").ok() == Some(None))
        {
            rows.clear();
        }
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
                            tenant: tenant.clone(),
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
    if let Some(op) = view.operation_id
        && view.action == "management_write"
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
    let device_target = matches!(
        view.action.as_str(),
        "registration_bind"
            | "credential_revoke"
            | "enrollment_create"
            | "enrollment_read"
            | "enrollment_resume"
            | "enrollment_cancel"
            | "inventory_read"
            | "device_action"
    ) || (view.source == "mdm.request"
        && matches!(
            view.action.as_str(),
            "command_accept" | "command_approve" | "command_cancel" | "command_read"
        ));
    if device_target
        && let Some(target) = &view.target
        && rss_mdm_registration_service::device::read::exists(c, tenant.into(), target.clone())
            .await?
    {
        devices.insert(target.clone());
    }
    if devices.iter().any(|v| !crate::model::identifier(v)) {
        return Err(Error::Integrity);
    }
    Ok(devices.into_iter().collect())
}

fn projection_error(error: sqlx::Error, operation: Deadline) -> Error {
    let timed_out = error
        .as_database_error()
        .and_then(|e| e.code())
        .is_some_and(|code| code == "57014" || code == "55P03");
    if timed_out && operation.is_expired(RuntimeTimer.now()) {
        Error::Deadline
    } else {
        Error::from(error)
    }
}
fn audit_error(error: rss_audit_postgres::Error) -> Error {
    if error.is_interrupted() {
        return Error::Deadline;
    }
    use rss_audit_postgres::Error as E;
    match error {
        E::Storage { .. } | E::Messaging(_) => Error::Storage,
        E::ReadBudgetExceeded => Error::Deadline,
        E::Rollback {
            operation,
            settlement,
        } => {
            let original = audit_error(*operation);
            let cleanup = audit_error(*settlement);
            if matches!(original, Error::Integrity) || matches!(cleanup, Error::Integrity) {
                Error::Integrity
            } else {
                Error::Storage
            }
        }
        _ => Error::Integrity,
    }
}
fn transaction_error<R>(error: rss_audit_postgres::TransactionError<Error>) -> Result<R, Error> {
    use rss_audit_postgres::TransactionError as E;
    Err(match error {
        E::Operation(e) => e,
        E::Audit(e) => audit_error(e),
        E::Rollback {
            operation,
            settlement,
        } => {
            let original = transaction_error::<()>(*operation).expect_err("transaction failure");
            let cleanup = audit_error(settlement);
            if matches!(original, Error::Integrity) || matches!(cleanup, Error::Integrity) {
                Error::Integrity
            } else {
                Error::Storage
            }
        }
    })
}
fn limited_transaction<R>(
    error: rss_audit_postgres::TransactionError<Error>,
) -> Result<Option<R>, Error> {
    match transaction_error::<()>(error).expect_err("transaction failure") {
        Error::Deadline => Ok(None),
        error => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rollback_failure_cannot_hide_original_integrity_failure() {
        let error = rss_audit_postgres::TransactionError::Rollback {
            operation: Box::new(rss_audit_postgres::TransactionError::Operation(
                Error::Integrity,
            )),
            settlement: rss_audit_postgres::Error::from(sqlx::Error::PoolTimedOut),
        };
        assert!(matches!(
            limited_transaction::<()>(error),
            Err(Error::Integrity)
        ));
    }
}
