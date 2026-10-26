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
/// Borrows the App-owned pool. Owns only the request-driven product projection.
pub struct Timeline {
    pub(crate) pool: PgPool,
    pub(crate) audit: Arc<AuditStore>,
    pub(crate) tenant: TenantId,
    pub(crate) key: rss_mdm_query::cursor::CursorCodec,
}
pub(crate) type Prepared = Vec<Projected>;
pub(crate) struct Projected {
    view: FactView,
    devices: Vec<String>,
    activity: Option<rss_mdm_audit_integration::activity::Activity>,
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
            key: rss_mdm_query::cursor::CursorCodec::new(secret).map_err(|_| Error::Integrity)?,
        })
    }
    /// Authorized reads fill a bounded set of missing facts before ordinary keyset navigation.
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
            .require(Permission::AuditRead, None)
            .map_err(|_| Error::Forbidden)?;
        query.validate()?;
        let token = query
            .cursor
            .as_ref()
            .map(|v| {
                self.key
                    .decode::<cursor::Cursor>(
                        &rss_contract::PageCursor::parse(v).map_err(|_| Error::Malformed)?,
                        "timeline",
                    )
                    .map_err(|_| Error::Conflict)
            })
            .transpose()?;
        // Reject immutable cursor bindings before any source read or projection write.
        if let Some(token) = &token {
            self.validate_cursor(proof, family, query, Some(token))?;
        }
        let start = RuntimeTimer.now();
        let budget = AuditBudget::new(Duration::from_secs(5));
        let total = Deadline::at(start + Duration::from_secs(2));
        let operation = Deadline::at(start + Duration::from_millis(1500));
        let control = budget.control_until(total, operation);
        if let Some(batch) = self
            .prepare_batch(proof, family, query, token.as_ref(), &control)
            .await?
            && !batch.is_empty()
        {
            self.write_batch(&batch, total, operation).await?;
        }
        let control = budget.control();
        self.audit
            .read(
                self.tenant,
                &control,
                (self, proof, family, query, token),
                |ctx, tx| {
                    Box::pin(async move {
                        let indexed = tx
                            .with_connection_context(ctx, |ctx, c| {
                                Box::pin(async move {
                                    ctx.0.read_index(c, ctx.1, ctx.3, ctx.4.as_ref()).await
                                })
                            })
                            .await?;
                        ctx.0
                            .page_in(ctx.1, ctx.2, ctx.3, ctx.4.as_ref(), indexed.0, indexed.1)
                    })
                },
            )
            .await
            .fold(
                Ok,
                transaction_error,
                transaction_error,
                transaction_error,
                transaction_error,
                transaction_error,
            )
    }
    pub(crate) async fn prepare_on(&self, c: &mut sqlx::PgConnection) -> Result<Prepared, Error> {
        let rows=sqlx::query("WITH candidates AS MATERIALIZED (SELECT r.* FROM rss_audit.records r WHERE r.tenant_id=$1::uuid AND NOT EXISTS(SELECT 1 FROM mdm_timeline.facts f WHERE f.tenant_id=r.tenant_id AND f.source=r.source_id AND f.event_id=r.event_id) ORDER BY r.position LIMIT 64), budget AS (SELECT coalesce(sum(octet_length(canonical)),0)<=8388608 AS fits FROM candidates) SELECT position,source_id,event_id,recorded_at,budget.fits,CASE WHEN budget.fits THEN canonical END AS canonical FROM candidates CROSS JOIN budget ORDER BY position")
            .bind(self.tenant.to_string()).fetch_all(&mut *c).await?;
        let mut batch = Vec::new();
        for row in rows {
            if !row.try_get::<bool, _>("fits")? {
                return Err(Error::Deadline);
            }
            let bytes: Vec<u8> = row.try_get("canonical")?;
            let decoded = rss_audit_core::decode_untrusted(&bytes).map_err(|_| Error::Integrity)?;
            let event = decoded.event();
            let id = event.identity();
            let position: i64 = row.try_get("position")?;
            if id.tenant() != self.tenant
                || position < 0
                || id.source().source_id().as_str() != row.try_get::<&str, _>("source_id")?
                || id.event_id().as_str() != row.try_get::<&str, _>("event_id")?
                || decoded.recorded_at().unix_seconds() != row.try_get::<i64, _>("recorded_at")?
            {
                return Err(Error::Integrity);
            }
            let mut view = project(event)?;
            view.position = position as u64;
            view.recorded_at = decoded.recorded_at().unix_seconds();
            let tenant = self.tenant.to_string();
            let association = match crate::projection::execution_identity(event, &view)? {
                Some(identity) => {
                    rss_mdm_execution_service::timeline::association_in(
                        c,
                        &tenant,
                        &view.actor,
                        identity,
                    )
                    .await?
                }
                None => None,
            };
            if let Some((_, Some(operation))) = &association {
                view.related_operation_ids.push(*operation);
            }
            let mut devices = correlate(c, &tenant, &view).await?;
            if let Some((device, _)) = association
                && !devices.contains(&device)
            {
                devices.push(device);
            }
            let activity = crate::activities::project_activity(c, &tenant, event, &view).await?;
            if let Some(target) = activity.as_ref().and_then(|a| a.target.as_ref())
                && !devices.contains(&target.device)
            {
                devices.push(target.device.clone());
            }
            batch.push(Projected {
                view,
                devices,
                activity,
            });
        }
        Ok(batch)
    }
    async fn prepare_batch(
        &self,
        proof: &AuthorizedPrincipal,
        family: &str,
        query: &Query,
        token: Option<&cursor::Cursor>,
        control: &rss_audit_postgres::Control<'_, RuntimeTimer>,
    ) -> Result<Option<Prepared>, Error> {
        let attempt = self
            .audit
            .read(
                self.tenant,
                control,
                (self, proof, family, query, token),
                |(service, proof, family, query, token), tx| {
                    Box::pin(async move {
                        service.validate_cursor(proof, family, query, *token)?;
                        tx.with_connection_context(service, |service, c| {
                            Box::pin(async move { service.prepare_on(c).await })
                        })
                        .await
                    })
                },
            )
            .await;
        // Only acknowledged, ordinary budget exhaustion permits a partial indexed response.
        attempt.fold(
            |v| Ok(Some(v)),
            limited_transaction,
            limited_transaction,
            transaction_error,
            transaction_error,
            transaction_error,
        )
    }
    pub(crate) async fn write_batch(
        &self,
        batch: &[Projected],
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
            .write_batch_on(&mut connection, batch, total, operation)
            .await;
        if result.is_err() {
            connection.close_on_drop();
        }
        result
    }
    async fn write_batch_on(
        &self,
        connection: &mut sqlx::PgConnection,
        batch: &[Projected],
        total: Deadline,
        operation: Deadline,
    ) -> Result<(), Error> {
        let mut tx = tokio::time::timeout_at(operation.instant().into(), connection.begin())
            .await
            .map_err(|_| Error::Deadline)??;
        let result=tokio::time::timeout_at(operation.instant().into(),async{
            let milliseconds=operation.remaining(RuntimeTimer.now()).unwrap_or_default().as_millis().saturating_add(1).to_string();
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)").bind(self.tenant.to_string()).bind(milliseconds).execute(&mut *tx).await.map_err(|e|projection_error(e,operation))?;
            let mut batch=batch.iter().collect::<Vec<_>>();
            batch.sort_by_key(|r|r.activity.as_ref().and_then(|a|a.target.as_ref()).map(|t|t.device.as_str()));
            for row in batch {
                let doc=serde_json::to_value(&row.view).map_err(|_|Error::Integrity)?;
                let bytes=serde_json::to_vec(&doc).map_err(|_|Error::Integrity)?;
                sqlx::query("INSERT INTO mdm_timeline.facts(tenant_id,position,source,event_id,recorded_at,instance_id,operation_id,actor,action,outcome,devices,operations,document,digest,activity,activity_digest) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT (tenant_id,source,event_id) DO NOTHING")
                    .bind(self.tenant.to_string()).bind(row.view.position as i64).bind(&row.view.source).bind(&row.view.event_id)
                    .bind(row.view.recorded_at).bind(row.view.instance_id).bind(row.view.operation_id).bind(&row.view.actor).bind(&row.view.action)
                    .bind(&row.view.audit_outcome).bind(&row.devices).bind(&row.view.related_operation_ids).bind(doc).bind(Sha256::digest(&bytes).to_vec()).bind(row.activity.as_ref().map(serde_json::to_value).transpose().map_err(|_|Error::Integrity)?).bind(row.activity.as_ref().map(|a|serde_json::to_value(a).and_then(|v|serde_json::to_vec(&v)).map(|b|Sha256::digest(b).to_vec())).transpose().map_err(|_|Error::Integrity)?).execute(&mut *tx).await.map_err(|e|projection_error(e,operation))?;
                if let Some(target)=row.activity.as_ref().and_then(|a|a.target.as_ref()) {
                    crate::activities::publish_in(&mut tx,self.tenant,&target.device,row.view.position as i64).await?;
                }
            }
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
                let rollback = tokio::time::timeout_at(total.instant().into(), async {
                    // ref: SQLx v0.9.0 connection/mod.rs: a dropped query can leave ErrorResponse unread.
                    loop {
                        match sqlx::Connection::flush(&mut *tx).await {
                            Ok(()) => break,
                            Err(sqlx::Error::Database(_)) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    tx.rollback().await
                })
                .await;
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
    ) -> Result<(), Error> {
        if let Some(token) = token
            && (token.tenant != self.tenant.to_string()
                || token.instance != proof.instance_id()
                || token.authority
                    != proof
                        .authorization()
                        .and_then(|s| s.query_binding(proof))
                        .map_err(|_| Error::Forbidden)?
                || token.family != family
                || token.query != query.binding()
                || token.after_position < 0
                || token.after_at < 0)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    async fn read_index(
        &self,
        c: &mut sqlx::PgConnection,
        proof: &AuthorizedPrincipal,
        query: &Query,
        token: Option<&cursor::Cursor>,
    ) -> Result<(bool, Vec<sqlx::postgres::PgRow>), Error> {
        // Authorization is reloaded after acquiring the audit read transaction, before exposing facts.
        rss_mdm_authorization_service::lock_on(c, proof.tenant_id(), proof.instance_id())
            .await
            .map_err(authorization_error)?;
        let current =
            rss_mdm_authorization_service::snapshot_on(c, proof.tenant_id(), proof.instance_id())
                .await
                .map_err(authorization_error)?;
        current
            .require(proof, Permission::AuditRead, None)
            .map_err(|e| authorization_error(e.into()))?;
        if current.query_binding(proof).map_err(authorization_error)?
            != proof
                .authorization()
                .and_then(|s| s.query_binding(proof))
                .map_err(authorization_error)?
        {
            return Err(Error::Conflict);
        }
        // Coverage and result rows share one statement snapshot, not a durable consumption offset.
        let rows=sqlx::query("WITH coverage AS (SELECT NOT EXISTS(SELECT 1 FROM rss_audit.records r WHERE r.tenant_id=$1::uuid AND NOT EXISTS(SELECT 1 FROM mdm_timeline.facts f WHERE f.tenant_id=r.tenant_id AND f.source=r.source_id AND f.event_id=r.event_id)) AS complete) SELECT coverage.complete,f.document,f.digest,f.position,f.recorded_at FROM coverage LEFT JOIN LATERAL (SELECT document,digest,position,recorded_at FROM mdm_timeline.facts WHERE tenant_id=$1::uuid AND (instance_id=$2::uuid OR (instance_id IS NULL AND document->>'supported'='true' AND document->>'actorKind' IN ('service','device','unidentified'))) AND ($3::text IS NULL OR devices @> ARRAY[$3]) AND ($4::uuid IS NULL OR operation_id=$4 OR operations @> ARRAY[$4]) AND ($5::text IS NULL OR actor=$5) AND ($6::text IS NULL OR action=$6) AND ($7::text IS NULL OR outcome=$7) AND ($8::bigint IS NULL OR recorded_at>=$8) AND ($9::bigint IS NULL OR recorded_at<$9) AND ($13::text IS NULL OR document->'target'->>'id'=$13) AND ($14::text IS NULL OR document->'target'->>'type'=$14) AND ($10::bigint IS NULL OR (recorded_at,position)<($10,$11)) ORDER BY recorded_at DESC,position DESC LIMIT $12) f ON true ORDER BY f.recorded_at DESC,f.position DESC")
            .bind(self.tenant.to_string()).bind(proof.instance_id()).bind(&query.device).bind(query.operation_id)
            .bind(&query.actor).bind(&query.action).bind(&query.outcome).bind(query.from).bind(query.until).bind(token.map(|v|v.after_at)).bind(token.map(|v|v.after_position)).bind((query.limit.unwrap_or(50)+1) as i64).bind(&query.target_id).bind(&query.target_type).fetch_all(c).await?;
        let complete = rows.first().ok_or(Error::Storage)?.try_get("complete")?;
        Ok((complete, rows))
    }
    fn page_in(
        &self,
        proof: &AuthorizedPrincipal,
        family: &str,
        query: &Query,
        token: Option<&cursor::Cursor>,
        complete: bool,
        mut rows: Vec<sqlx::postgres::PgRow>,
    ) -> Result<Page, Error> {
        let tenant = self.tenant.to_string();
        self.validate_cursor(proof, family, query, token)?;
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
                    self.key
                        .encode(
                            "timeline",
                            &cursor::Cursor {
                                tenant: tenant.clone(),
                                instance: proof.instance_id().into(),
                                authority: proof
                                    .authorization()
                                    .and_then(|s| s.query_binding(proof))
                                    .map_err(|_| Error::Forbidden)?,
                                family: family.into(),
                                query: query.binding(),
                                after_at: last.recorded_at,
                                after_position: last.position as i64,
                            },
                        )
                        .map(|v| v.as_str().to_owned())
                        .map_err(|_| Error::Conflict)
                })
                .transpose()?
        } else {
            None
        };
        Ok(Page {
            items,
            next_cursor,
            coverage: Coverage { complete },
        })
    }
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
            "command_accept" | "command_reauthorize" | "command_cancel" | "command_read"
        ));
    if device_target
        && let target = &view.target.id
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
fn source_error(error: rss_mdm_audit_integration::Error) -> Error {
    match error {
        rss_mdm_audit_integration::Error::Audit(error) => audit_error(error),
        _ => Error::Integrity,
    }
}
pub(crate) fn transaction_error<R>(
    error: rss_mdm_audit_integration::TransactionError<Error>,
) -> Result<R, Error> {
    use rss_mdm_audit_integration::TransactionError as E;
    Err(match error {
        E::Operation(e) => e,
        E::Storage(e) => source_error(e),
        E::Rollback {
            operation,
            settlement,
        } => {
            let original = transaction_error::<()>(*operation).expect_err("transaction failure");
            let cleanup = source_error(settlement);
            if matches!(original, Error::Integrity) || matches!(cleanup, Error::Integrity) {
                Error::Integrity
            } else {
                Error::Storage
            }
        }
    })
}
fn limited_transaction<R>(
    error: rss_mdm_audit_integration::TransactionError<Error>,
) -> Result<Option<R>, Error> {
    match transaction_error::<()>(error).expect_err("transaction failure") {
        Error::Deadline => Ok(None),
        error => Err(error),
    }
}

pub(crate) fn authorization_error(error: rss_mdm_authorization_service::Error) -> Error {
    use rss_mdm_authorization_service::Error as A;
    match error {
        A::Unauthorized | A::Forbidden => Error::Forbidden,
        A::Malformed => Error::Malformed,
        A::Corrupt | A::Configuration => Error::Integrity,
        A::Deadline => Error::Deadline,
        A::Conflict => Error::Conflict,
        A::Storage | A::CommitUnknown | A::RollbackFailed | A::Audit(_) => Error::Storage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rollback_failure_cannot_hide_original_integrity_failure() {
        let error = rss_mdm_audit_integration::TransactionError::Rollback {
            operation: Box::new(rss_mdm_audit_integration::TransactionError::Operation(
                Error::Integrity,
            )),
            settlement: rss_audit_postgres::Error::from(sqlx::Error::PoolTimedOut).into(),
        };
        assert!(matches!(
            limited_transaction::<()>(error),
            Err(Error::Integrity)
        ));
    }
}
