//! Product storage migration: authenticated generation directories and one cutover fact.
use crate::{
    Error, S3Storage, Storage, Store, generation::Generation, journal, location::Location, storage,
};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub expected_storage_revision: i64,
    pub target_revision: i64,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Requested,
    Preparing,
    Ready,
    Committed,
    Cancelled,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub source_generation: Uuid,
    pub target_generation: Uuid,
    pub expected_storage_revision: i64,
    pub target_revision: i64,
    pub phase: Phase,
    pub blocked_reason: Option<String>,
    pub source_objects: i64,
    pub verified_objects: i64,
    pub verified_bytes: i64,
    pub next_action: String,
    pub observed_at: Option<i64>,
}
fn row_receipt(row: &sqlx::postgres::PgRow) -> Result<Receipt, Error> {
    let phase: String = row.try_get("phase").map_err(|_| storage())?;
    Ok(Receipt {
        operation_id: row.try_get("operation_id").map_err(|_| storage())?,
        source_generation: row.try_get("source_generation").map_err(|_| storage())?,
        target_generation: row.try_get("target_generation").map_err(|_| storage())?,
        expected_storage_revision: row.try_get("expected_revision").map_err(|_| storage())?,
        target_revision: row.try_get("target_revision").map_err(|_| storage())?,
        phase: serde_json::from_value(serde_json::Value::String(phase.clone()))
            .map_err(|_| Error::Invariant)?,
        blocked_reason: row.try_get("blocked_reason").map_err(|_| storage())?,
        source_objects: 0,
        verified_objects: 0,
        verified_bytes: 0,
        observed_at: row.try_get("observed_at").map_err(|_| storage())?,
        next_action: match phase.as_str() {
            "requested" => "run_maintenance",
            "preparing" | "ready" => "resume_same_operation",
            "committed" => "observe_active_generation",
            "cancelled" => "none",
            _ => return Err(Error::Invariant),
        }
        .into(),
    })
}
pub async fn receipt(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
) -> Result<Receipt, Error> {
    let row = sqlx::query(
        "SELECT * FROM mdm_content.migrations WHERE tenant_id=$1::uuid AND operation_id=$2",
    )
    .bind(tenant.to_string())
    .bind(operation)
    .fetch_optional(&mut *c)
    .await
    .map_err(|_| storage())?
    .ok_or(Error::Conflict)?;
    let mut value = row_receipt(&row)?;
    let (source,verified,bytes):(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_content.objects WHERE tenant_id=$1::uuid AND generation=$2 AND state<>'deleted'),count(*) FILTER(WHERE state='ready'),coalesce(sum((content->>'length')::bigint) FILTER(WHERE state='ready'),0)::bigint FROM mdm_content.objects WHERE tenant_id=$1::uuid AND generation=$3")
        .bind(tenant.to_string()).bind(value.source_generation).bind(value.target_generation).fetch_one(c).await.map_err(|_|storage())?;
    value.source_objects = source;
    value.verified_objects = verified;
    value.verified_bytes = bytes;
    if value.observed_at.is_some() {
        value.next_action = "none".into();
    }
    Ok(value)
}

/// Copy one bounded page. The maintenance owner holds the mutation fence across this call.
/// The target location is also the recovery journal: no shadow mapping or second write identity.
pub(crate) async fn copy_page(
    source: &Store,
    target: &Store,
    after: Option<Uuid>,
) -> Result<Option<Uuid>, Error> {
    let mut tx = source.tx().await?;
    let rows = sqlx::query("SELECT id,owner,content,location,expires,state FROM mdm_content.objects WHERE tenant_id=$1::uuid AND generation=$2 AND state<>'deleted' AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT 16")
        .bind(source.tenant.to_string()).bind(source.generation).bind(after).fetch_all(&mut *tx).await.map_err(|_| storage())?;
    journal::commit(tx).await?;
    let mut last = None;
    for row in rows {
        let id: Uuid = row.try_get("id").map_err(|_| storage())?;
        let content = journal::decode(row.try_get("content").map_err(|_| storage())?)?;
        let source_location = Location::open(
            &source.protection,
            source.tenant,
            source.generation,
            id,
            content,
            row.try_get("location").map_err(|_| storage())?,
        )?;
        if row.try_get::<String, _>("state").map_err(|_| storage())? != "ready" {
            return Err(Error::Conflict);
        }
        let original = source_location.coordinate.ok_or(Error::CommitUnknown)?;
        let mut tx = target.tx().await?;
        let existing: Option<(serde_json::Value,String)> = sqlx::query_as("SELECT location,state FROM mdm_content.objects WHERE tenant_id=$1::uuid AND generation=$2 AND id=$3")
            .bind(target.tenant.to_string()).bind(target.generation).bind(id).fetch_optional(&mut *tx).await.map_err(|_| storage())?;
        let mut location = if let Some((document, state)) = existing {
            let location = Location::open(
                &target.protection,
                target.tenant,
                target.generation,
                id,
                content,
                document,
            )?;
            if state == "ready" {
                journal::commit(tx).await?;
                last = Some(id);
                continue;
            }
            if state != "pending" {
                return Err(Error::Invariant);
            }
            location
        } else {
            let location = Location {
                generation: target.generation,
                piece: id,
                content,
                intent: target.backend.intent_in(target.generation, id, content)?,
                coordinate: None,
            };
            sqlx::query("INSERT INTO mdm_content.objects(tenant_id,generation,id,owner,content,location,expires,state) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,'pending')")
                .bind(target.tenant.to_string()).bind(target.generation).bind(id).bind(row.try_get::<Uuid,_>("owner").map_err(|_| storage())?)
                .bind(journal::encode(&content)?).bind(location.seal(&target.protection,target.tenant)?).bind(row.try_get::<i64,_>("expires").map_err(|_|storage())?)
                .execute(&mut *tx).await.map_err(|_|storage())?;
            location
        };
        journal::commit(tx).await?;
        let deadline = target.deadline()?;
        if location.coordinate.is_none() {
            location.coordinate = target
                .backend
                .recover(&location.intent, content, deadline)
                .await?;
            if location.coordinate.is_none() {
                let bytes = source
                    .backend
                    .read(&original, content, 0, content.length, deadline, ())
                    .await?;
                location.coordinate = Some(
                    target
                        .backend
                        .write(&location.intent, content, bytes, deadline, ())
                        .await
                        .map_err(|failure| match failure {
                            crate::backend::WriteFailure::NotWritten(e)
                            | crate::backend::WriteFailure::Unresolved(e) => e,
                        })?,
                );
            }
            let mut tx = target.tx().await?;
            sqlx::query("UPDATE mdm_content.objects SET location=$4 WHERE tenant_id=$1::uuid AND generation=$2 AND id=$3 AND state='pending'")
                .bind(target.tenant.to_string()).bind(target.generation).bind(id).bind(location.seal(&target.protection,target.tenant)?)
                .execute(&mut *tx).await.map_err(|_|storage())?;
            journal::commit(tx).await?;
        }
        let exact = location.coordinate.ok_or(Error::CommitUnknown)?;
        target
            .backend
            .read(&exact, content, 0, content.length, deadline, ())
            .await?;
        let mut tx = target.tx().await?;
        sqlx::query("UPDATE mdm_content.objects SET state='ready' WHERE tenant_id=$1::uuid AND generation=$2 AND id=$3 AND state='pending'")
            .bind(target.tenant.to_string()).bind(target.generation).bind(id).execute(&mut *tx).await.map_err(|_|storage())?;
        journal::commit(tx).await?;
        last = Some(id);
    }
    Ok(last)
}

/// Build a candidate without changing the active pointer or relaxing normal admission.
pub(crate) async fn target(source: &Store, operation: &Receipt) -> Result<Store, Error> {
    let mut config = source.config.clone();
    config.storage = Storage::S3(Box::new(S3Storage {
        revision: u64::try_from(operation.target_revision).map_err(|_| Error::Malformed)?,
        max_concurrent: 1,
        connect_seconds: 5,
    }));
    let mut tx = source.tx().await?;
    let connection = crate::connections::load(
        &mut tx,
        source.tenant,
        operation.target_revision as u64,
        &source.protection,
    )
    .await?;
    journal::commit(tx).await?;
    let backend = crate::backend::Backend::open(
        &config.storage,
        source.tenant,
        source.timer.clone(),
        source.config.transfer_seconds,
        Some(std::sync::Arc::new(connection)),
    )
    .await?;
    let descriptor = Generation {
        id: operation.target_generation,
        storage: config.storage.clone(),
        backend_identity: backend.identity()?,
    };
    let mut tx = source.tx().await?;
    let document = descriptor.seal(&source.protection, source.tenant)?;
    sqlx::query("INSERT INTO mdm_content.generations(tenant_id,id,descriptor) VALUES($1::uuid,$2,$3) ON CONFLICT DO NOTHING")
        .bind(source.tenant.to_string()).bind(descriptor.id).bind(&document).execute(&mut *tx).await.map_err(|_|storage())?;
    let stored: serde_json::Value = sqlx::query_scalar(
        "SELECT descriptor FROM mdm_content.generations WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(source.tenant.to_string())
    .bind(descriptor.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| storage())?;
    if stored != document {
        return Err(Error::Conflict);
    }
    journal::commit(tx).await?;
    let target = Store {
        config,
        backend,
        generation: descriptor.id,
        ..source.clone()
    };
    target.verify_marker().await?;
    Ok(target)
}

/// Owner-only preparation. External I/O is outside transactions and target selection is deferred.
/// Returns Ready without publishing: cutover must share the product audit transaction.
pub async fn prepare(source: &Store, operation_id: Uuid) -> Result<Receipt, Error> {
    use sqlx::Connection;
    let mut connection = source.pool.acquire().await.map_err(|_| storage())?.detach();
    let result = prepare_on(source, operation_id, &mut connection).await;
    let closed = connection.close().await;
    match (result, closed) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        _ => Err(Error::Cleanup),
    }
}
async fn prepare_on(
    source: &Store,
    operation_id: Uuid,
    c: &mut PgConnection,
) -> Result<Receipt, Error> {
    use sqlx::Connection;
    sqlx::query(
        "SELECT set_config('rss.tenant_id',$1,false),set_config('statement_timeout','6000',false)",
    )
    .bind(source.tenant.to_string())
    .execute(&mut *c)
    .await
    .map_err(|_| storage())?;
    let owner: bool =
        sqlx::query_scalar("SELECT current_user='mdm_owner' AND session_user='mdm_owner'")
            .fetch_one(&mut *c)
            .await
            .map_err(|_| storage())?;
    if !owner {
        return Err(Error::Configuration);
    }
    let owns: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1,30042))")
        .bind(source.tenant.to_string())
        .fetch_one(&mut *c)
        .await
        .map_err(|_| storage())?;
    if !owns {
        return Err(Error::Conflict);
    }
    let operation = receipt(c, source.tenant, operation_id).await?;
    let request: serde_json::Value = sqlx::query_scalar(
        "SELECT request FROM mdm_content.migrations WHERE tenant_id=$1::uuid AND operation_id=$2",
    )
    .bind(source.tenant.to_string())
    .bind(operation_id)
    .fetch_one(&mut *c)
    .await
    .map_err(|_| storage())?;
    let request: serde_json::Value = journal::verify_document(
        &source.protection,
        source.tenant,
        &format!("storage-migration:{operation_id}"),
        request,
    )?;
    let input: Request =
        serde_json::from_value(request.get("input").cloned().ok_or(Error::Metadata)?)
            .map_err(|_| Error::Metadata)?;
    if input.expected_storage_revision != operation.expected_storage_revision
        || input.target_revision != operation.target_revision
    {
        return Err(Error::Invariant);
    }
    if matches!(operation.phase, Phase::Committed | Phase::Cancelled) {
        return Ok(operation);
    }
    if operation.source_generation != source.generation {
        return Err(Error::Conflict);
    }
    if operation.phase == Phase::Ready {
        target(source, &operation).await?.verify_marker().await?;
        return Ok(operation);
    }
    let target = target(source, &operation).await?;
    let mut tx = c.begin().await.map_err(|_| storage())?;
    let changed = sqlx::query("UPDATE mdm_content.settings SET maintenance='frozen',operation=$4 WHERE tenant_id=$1::uuid AND active_generation=$2 AND revision=$3 AND (operation IS NULL OR operation=$4)")
        .bind(source.tenant.to_string()).bind(source.generation).bind(operation.expected_storage_revision).bind(operation_id)
        .execute(&mut *tx).await.map_err(|_|storage())?.rows_affected();
    if changed != 1 {
        return Err(Error::Conflict);
    }
    sqlx::query("UPDATE mdm_content.migrations SET phase='preparing',blocked_reason=NULL WHERE tenant_id=$1::uuid AND operation_id=$2 AND phase IN ('requested','preparing')")
        .bind(source.tenant.to_string()).bind(operation_id).execute(&mut *tx).await.map_err(|_|storage())?;
    journal::commit(tx).await?;
    let drained: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1,30041))")
            .bind(source.tenant.to_string())
            .fetch_one(&mut *c)
            .await
            .map_err(|_| storage())?;
    if !drained {
        return blocked(c, source.tenant, operation_id, "content_operations_active").await;
    }
    if recover_deleting(source).await.is_err()
        || recover_orphan_deletions(source).await.is_err()
        || recover_source(source).await.is_err()
    {
        return blocked(c, source.tenant, operation_id, "source_outcome_unresolved").await;
    }
    let unresolved: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_content.objects WHERE tenant_id=$1::uuid AND generation=$2 AND state IN ('pending','deleting'))")
        .bind(source.tenant.to_string()).bind(source.generation).fetch_one(&mut *c).await.map_err(|_|storage())?;
    if unresolved {
        return blocked(c, source.tenant, operation_id, "source_outcome_unresolved").await;
    }
    crate::backup::validate_catalog(c, source.tenant, &source.protection).await?;
    let mut after = None;
    loop {
        match copy_page(source, &target, after).await {
            Ok(Some(next)) => after = Some(next),
            Ok(None) => break,
            Err(_) => {
                return blocked(c, source.tenant, operation_id, "target_copy_unconfirmed").await;
            }
        }
    }
    let mut tx = c.begin().await.map_err(|_| storage())?;
    let complete: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_content.objects s LEFT JOIN mdm_content.objects t ON t.tenant_id=s.tenant_id AND t.generation=$3 AND t.id=s.id WHERE s.tenant_id=$1::uuid AND s.generation=$2 AND s.state<>'deleted' AND (t.id IS NULL OR t.state<>'ready' OR t.content<>s.content)) AND NOT EXISTS(SELECT 1 FROM mdm_content.objects t LEFT JOIN mdm_content.objects s ON s.tenant_id=t.tenant_id AND s.generation=$2 AND s.id=t.id AND s.state<>'deleted' WHERE t.tenant_id=$1::uuid AND t.generation=$3 AND s.id IS NULL)")
        .bind(source.tenant.to_string()).bind(source.generation).bind(target.generation).fetch_one(&mut *tx).await.map_err(|_|storage())?;
    if !complete {
        return Err(Error::Invariant);
    }
    sqlx::query("UPDATE mdm_content.migrations SET phase='ready',blocked_reason=NULL WHERE tenant_id=$1::uuid AND operation_id=$2 AND phase='preparing'")
        .bind(source.tenant.to_string()).bind(operation_id).execute(&mut *tx).await.map_err(|_|storage())?;
    sqlx::query("UPDATE mdm_content.settings SET maintenance='switching' WHERE tenant_id=$1::uuid AND operation=$2 AND maintenance='frozen'")
        .bind(source.tenant.to_string()).bind(operation_id).execute(&mut *tx).await.map_err(|_|storage())?;
    journal::commit(tx).await?;
    receipt(c, source.tenant, operation_id).await
}
async fn blocked(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    reason: &str,
) -> Result<Receipt, Error> {
    sqlx::query("UPDATE mdm_content.migrations SET blocked_reason=$3 WHERE tenant_id=$1::uuid AND operation_id=$2")
        .bind(tenant.to_string()).bind(operation).bind(reason).execute(&mut *c).await.map_err(|_|storage())?;
    receipt(c, tenant, operation).await
}

/// Called in the authenticated management transaction, before its audit append.
pub async fn request_on(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    input: &Request,
    actor: &str,
    protection: &rss_mdm_native_protection::Protector,
) -> Result<Receipt, Error> {
    if operation.is_nil() || input.expected_storage_revision <= 0 || input.target_revision <= 0 {
        return Err(Error::Malformed);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,30043))")
        .bind(format!("{tenant}:{operation}"))
        .execute(&mut *c)
        .await
        .map_err(|_| storage())?;
    let key = format!("storage-migration:{operation}");
    if let Some(document) = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT request FROM mdm_content.migrations WHERE tenant_id=$1::uuid AND operation_id=$2",
    )
    .bind(tenant.to_string())
    .bind(operation)
    .fetch_optional(&mut *c)
    .await
    .map_err(|_| storage())?
    {
        let old: serde_json::Value = journal::verify_document(protection, tenant, &key, document)?;
        if old != serde_json::json!({"input":input,"actor":actor}) {
            return Err(Error::Conflict);
        }
        return receipt(c, tenant, operation).await;
    }
    let document = journal::sign_document(
        protection,
        tenant,
        &key,
        &serde_json::json!({"input":input,"actor":actor}),
    )?;
    sqlx::query("SELECT mdm_content.request_migration($1,$2,$3,$4,$5)")
        .bind(operation)
        .bind(input.expected_storage_revision)
        .bind(input.target_revision)
        .bind(Uuid::new_v4())
        .bind(document)
        .execute(&mut *c)
        .await
        .map_err(|_| Error::Conflict)?;
    receipt(c, tenant, operation).await
}

/// Cutover runs inside the caller's audited source transaction. All physical work is already sealed.
pub async fn cutover_on(
    c: &mut PgConnection,
    tenant: TenantId,
    operation_id: Uuid,
) -> Result<(Receipt, bool), Error> {
    let replayed: bool = sqlx::query_scalar("SELECT mdm_content.commit_migration($1)")
        .bind(operation_id)
        .fetch_one(&mut *c)
        .await
        .map_err(|_| Error::Conflict)?;
    Ok((receipt(c, tenant, operation_id).await?, replayed))
}

/// Cancellation and its audit fact share the caller's authenticated transaction.
pub(crate) async fn cancel_on(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
) -> Result<(Receipt, bool), Error> {
    sqlx::query("SELECT mdm_content.cancel_migration($1)")
        .bind(operation)
        .execute(&mut *c)
        .await
        .map_err(|_| Error::Conflict)?;
    Ok((receipt(c, tenant, operation).await?, false))
}

#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub storage_revision: i64,
    pub active_generation: Uuid,
    pub maintenance: String,
    pub operation: Option<Receipt>,
    pub history: Vec<Receipt>,
}
pub(crate) async fn directory_on(
    c: &mut PgConnection,
    tenant: TenantId,
) -> Result<Directory, Error> {
    let (storage_revision,active_generation,maintenance,operation):(i64,Uuid,String,Option<Uuid>)=sqlx::query_as("SELECT revision,active_generation,maintenance,operation FROM mdm_content.settings WHERE tenant_id=$1::uuid")
        .bind(tenant.to_string()).fetch_one(&mut *c).await.map_err(|_|storage())?;
    let operation = match operation {
        Some(id) => Some(receipt(c, tenant, id).await?),
        None => None,
    };
    let rows=sqlx::query("SELECT * FROM mdm_content.migrations WHERE tenant_id=$1::uuid ORDER BY created_at DESC,operation_id DESC LIMIT 32")
        .bind(tenant.to_string()).fetch_all(&mut *c).await.map_err(|_|storage())?;
    let mut history = Vec::new();
    for row in rows {
        history.push(
            receipt(
                c,
                tenant,
                row.try_get("operation_id").map_err(|_| storage())?,
            )
            .await?,
        );
    }
    Ok(Directory {
        storage_revision,
        active_generation,
        maintenance,
        operation,
        history,
    })
}

async fn recover_source(source: &Store) -> Result<(), Error> {
    let mut tx = source.tx().await?;
    let rows=sqlx::query("SELECT id,content,location FROM mdm_content.objects WHERE tenant_id=$1::uuid AND generation=$2 AND state='pending' ORDER BY id LIMIT 16")
        .bind(source.tenant.to_string()).bind(source.generation).fetch_all(&mut *tx).await.map_err(|_|storage())?;
    journal::commit(tx).await?;
    for row in rows {
        let id: Uuid = row.try_get("id").map_err(|_| storage())?;
        let content = journal::decode(row.try_get("content").map_err(|_| storage())?)?;
        let mut location = Location::open(
            &source.protection,
            source.tenant,
            source.generation,
            id,
            content,
            row.try_get("location").map_err(|_| storage())?,
        )?;
        let deadline = source.deadline()?;
        let coordinate = match location.coordinate.clone() {
            Some(value) => Some(value),
            None => {
                source
                    .backend
                    .recover(&location.intent, content, deadline)
                    .await?
            }
        }
        .ok_or(Error::CommitUnknown)?;
        source
            .backend
            .read(&coordinate, content, 0, content.length, deadline, ())
            .await?;
        location.coordinate = Some(coordinate);
        let mut tx = source.tx().await?;
        sqlx::query("UPDATE mdm_content.objects SET location=$4,state='ready' WHERE tenant_id=$1::uuid AND generation=$2 AND id=$3 AND state='pending'")
            .bind(source.tenant.to_string()).bind(source.generation).bind(id).bind(location.seal(&source.protection,source.tenant)?)
            .execute(&mut *tx).await.map_err(|_|storage())?;
        journal::commit(tx).await?;
    }
    Ok(())
}

async fn recover_deleting(source: &Store) -> Result<(), Error> {
    let mut tx = source.tx().await?;
    let rows=sqlx::query("SELECT class,sha256,length,document FROM mdm_content.manifests WHERE tenant_id=$1::uuid AND state='deleting' ORDER BY class,sha256 LIMIT 16")
        .bind(source.tenant.to_string()).fetch_all(&mut *tx).await.map_err(|_|storage())?;
    journal::commit(tx).await?;
    for row in rows {
        let class: String = row.try_get("class").map_err(|_| storage())?;
        let digest: Vec<u8> = row.try_get("sha256").map_err(|_| storage())?;
        let length: i64 = row.try_get("length").map_err(|_| storage())?;
        let key = format!(
            "{class}:{}:{length}",
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let manifest: crate::journal::Manifest =
            source.unsign(&key, row.try_get("document").map_err(|_| storage())?)?;
        for piece in manifest.pieces {
            let mut tx = source.tx().await?;
            let (document,state):(serde_json::Value,String)=sqlx::query_as("SELECT location,state FROM mdm_content.objects WHERE tenant_id=$1::uuid AND generation=$2 AND id=$3")
                .bind(source.tenant.to_string()).bind(source.generation).bind(piece.id).fetch_one(&mut *tx).await.map_err(|_|storage())?;
            journal::commit(tx).await?;
            if state == "deleted" {
                continue;
            }
            let location = Location::open(
                &source.protection,
                source.tenant,
                source.generation,
                piece.id,
                piece.content,
                document,
            )?;
            if !source
                .backend
                .delete(
                    location.coordinate.as_ref().ok_or(Error::CommitUnknown)?,
                    source.deadline()?,
                    (),
                )
                .await?
            {
                return Err(Error::CommitUnknown);
            }
            let mut tx = source.tx().await?;
            sqlx::query("UPDATE mdm_content.objects SET state='deleted' WHERE tenant_id=$1::uuid AND generation=$2 AND id=$3")
                .bind(source.tenant.to_string()).bind(source.generation).bind(piece.id).execute(&mut *tx).await.map_err(|_|storage())?;
            journal::commit(tx).await?;
        }
        let mut tx = source.tx().await?;
        sqlx::query("UPDATE mdm_content.manifests SET state='deleted' WHERE tenant_id=$1::uuid AND class=$2 AND sha256=$3 AND length=$4 AND state='deleting'")
            .bind(source.tenant.to_string()).bind(class).bind(digest).bind(length).execute(&mut *tx).await.map_err(|_|storage())?;
        journal::commit(tx).await?;
    }
    Ok(())
}

async fn recover_orphan_deletions(source: &Store) -> Result<(), Error> {
    let mut tx = source.tx().await?;
    let rows=sqlx::query("SELECT o.id,o.content,o.location FROM mdm_content.objects o WHERE o.tenant_id=$1::uuid AND o.generation=$2 AND o.state='deleting' AND NOT EXISTS(SELECT 1 FROM mdm_content.manifests m WHERE m.tenant_id=o.tenant_id AND m.state<>'deleted' AND m.document->'value'->'pieces' @> jsonb_build_array(jsonb_build_object('id',o.id))) ORDER BY o.id LIMIT 16")
        .bind(source.tenant.to_string()).bind(source.generation).fetch_all(&mut *tx).await.map_err(|_|storage())?;
    journal::commit(tx).await?;
    for row in rows {
        let id: Uuid = row.try_get("id").map_err(|_| storage())?;
        let content = journal::decode(row.try_get("content").map_err(|_| storage())?)?;
        let mut location = Location::open(
            &source.protection,
            source.tenant,
            source.generation,
            id,
            content,
            row.try_get("location").map_err(|_| storage())?,
        )?;
        let deadline = source.deadline()?;
        if location.coordinate.is_none() {
            location.coordinate = source
                .backend
                .recover(&location.intent, content, deadline)
                .await?;
        }
        let exact = location.coordinate.as_ref().ok_or(Error::CommitUnknown)?;
        let mut tx = source.tx().await?;
        sqlx::query("UPDATE mdm_content.objects SET location=$4 WHERE tenant_id=$1::uuid AND generation=$2 AND id=$3 AND state='deleting'")
            .bind(source.tenant.to_string()).bind(source.generation).bind(id).bind(location.seal(&source.protection,source.tenant)?).execute(&mut *tx).await.map_err(|_|storage())?;
        journal::commit(tx).await?;
        if !source.backend.delete(exact, deadline, ()).await? {
            return Err(Error::CommitUnknown);
        }
        let mut tx = source.tx().await?;
        sqlx::query("UPDATE mdm_content.objects SET state='deleted' WHERE tenant_id=$1::uuid AND generation=$2 AND id=$3 AND state='deleting'")
            .bind(source.tenant.to_string()).bind(source.generation).bind(id).execute(&mut *tx).await.map_err(|_|storage())?;
        journal::commit(tx).await?;
    }
    Ok(())
}

/// Validate the bounded definer bodies and their exact executable role sets at admission.
pub async fn verify_contract(c: &mut PgConnection) -> Result<bool, Error> {
    for (signature, tag, role) in [
        (
            "mdm_content.request_migration(uuid,bigint,bigint,uuid,jsonb)",
            "$migration$",
            "mdm_access",
        ),
        (
            "mdm_content.cancel_migration(uuid)",
            "$cancel$",
            "mdm_access",
        ),
        (
            "mdm_content.commit_migration(uuid)",
            "$commit_migration$",
            "mdm_access",
        ),
        (
            "mdm_content.observe_generation(uuid)",
            "$observe$",
            "mdm_flow_runtime",
        ),
        (
            "mdm_content.record_marker(uuid,jsonb)",
            "$marker$",
            "mdm_flow_runtime",
        ),
    ] {
        let body = crate::RELATIONS_SQL
            .split(tag)
            .nth(1)
            .ok_or(Error::Invariant)?;
        let valid:bool=sqlx::query_scalar("SELECT count(*)=1 AND coalesce(bool_and(p.prosrc=$2 AND p.proowner='mdm_owner'::regrole AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp'] AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 OR a.is_grantable OR pg_get_userbyid(a.grantee) NOT IN ('mdm_owner',$3))),false) FROM pg_proc p WHERE p.oid=to_regprocedure($1)")
            .bind(signature).bind(body).bind(role).fetch_one(&mut *c).await.map_err(|_|storage())?;
        if !valid {
            return Ok(false);
        }
    }
    Ok(true)
}
