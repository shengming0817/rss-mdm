use super::*;
use crate::{database::db, device::DevicePrincipal};
use rss_observation::{Batch, Scope};
use sqlx::{Row, postgres::PgRow};
use uuid::Uuid;

// All restore paths use this shape before minting a Run or recovery capability.
macro_rules! selection {
    ($filter:literal) => {
        concat!("SELECT tenant_id::text,registration::text,source,epoch::text,id::text,scope,sequence,started_at,sealed_at,attempts,result,reason,batch,digest FROM mdm_access.collection_runs WHERE ", $filter)
    };
}

/// Recheck the principal inside the transaction accepting device input. Lock order matches revoke.

#[derive(PartialEq, Eq)]
pub struct Run {
    pub id: Uuid,
    pub scope: Scope,
    pub sequence: u64,
    pub started_at: i64,
    pub sealed_at: Option<i64>,
    pub attempts: Attempts,
    pub result: RunResult,
    pub reason: Option<FinishReason>,
    batch: Option<Batch>,
}
fn restored_scope(row: &PgRow) -> Result<Scope, Error> {
    let scope = serde_json::from_str::<Scope>(&row.try_get::<String, _>("scope").map_err(db)?)
        .map_err(|_| corrupt())?;
    if scope.tenant().to_string() != row.try_get::<String, _>("tenant_id").map_err(db)?
        || scope.registration().as_str() != row.try_get::<String, _>("registration").map_err(db)?
        || scope.source().as_str() != row.try_get::<String, _>("source").map_err(db)?
        || scope.epoch().as_str() != row.try_get::<String, _>("epoch").map_err(db)?
        || rss_mdm_inventory::Source::parse(scope.source().as_str()).is_err()
    {
        return Err(corrupt());
    }
    Ok(scope)
}

fn restored_batch(
    row: &PgRow,
    scope: &Scope,
    definition: &rss_mdm_inventory::CollectionDefinition,
) -> Result<(Uuid, u64, Option<Batch>), Error> {
    let id =
        Uuid::parse_str(&row.try_get::<String, _>("id").map_err(db)?).map_err(|_| corrupt())?;
    let sequence =
        u64::try_from(row.try_get::<i64, _>("sequence").map_err(db)?).map_err(|_| corrupt())?;
    let batch = row
        .try_get::<Option<Vec<u8>>, _>("batch")
        .map_err(db)?
        .map(|b| {
            let batch = Batch::decode(&b).map_err(|_| corrupt())?;
            let digest = fingerprint(&batch, scope)?;
            if batch.encode() != b
                || batch.id().as_str() != id.to_string()
                || batch.sequence() != sequence
                || batch.coverage() != &definition.coverage().map_err(|_| corrupt())?
                || Some(digest) != row.try_get::<Option<String>, _>("digest").map_err(db)?
            {
                return Err(corrupt());
            }
            let reference = rss_mdm_inventory::CollectionReference::from_batch(definition, &batch)
                .map_err(|_| corrupt())?;
            let progress: Attempts = serde_json::from_str(row.try_get("attempts").map_err(db)?)
                .map_err(|_| corrupt())?;
            use sha2::{Digest, Sha256};
            if format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&progress).map_err(|_| corrupt())?)
            ) != reference.digest()
            {
                return Err(corrupt());
            }
            Ok(batch)
        })
        .transpose()?;
    Ok((id, sequence, batch))
}

impl Run {
    pub fn from_row(row: PgRow) -> Result<Self, Error> {
        let scope = restored_scope(&row)?;
        let attempts: Attempts =
            serde_json::from_str(row.try_get("attempts").map_err(db)?).map_err(|_| corrupt())?;
        attempts
            .definition()
            .validate_scope(&scope)
            .map_err(|_| corrupt())?;
        let (id, sequence, batch) = restored_batch(&row, &scope, attempts.definition())?;
        Ok(Self {
            id,
            scope,
            sequence,
            batch,
            started_at: row.try_get("started_at").map_err(db)?,
            sealed_at: row.try_get("sealed_at").map_err(db)?,
            attempts,
            result: RunResult::parse(&row.try_get::<String, _>("result").map_err(db)?)?,
            reason: row
                .try_get::<Option<String>, _>("reason")
                .map_err(db)?
                .as_deref()
                .map(FinishReason::parse)
                .transpose()?,
        })
    }
    pub fn batch(&self) -> Option<&Batch> {
        self.batch.as_ref()
    }
}
pub(super) fn fingerprint(batch: &Batch, scope: &Scope) -> Result<String, Error> {
    Ok(batch
        .fingerprint(scope)
        .map_err(|_| corrupt())?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Persist a pending native run on the caller's transaction after registration allocation.
pub async fn start_in(
    tx: &mut sqlx::PgConnection,
    scope: &Scope,
    sequence: i64,
    definition: rss_mdm_inventory::CollectionDefinition,
) -> Result<Uuid, Error> {
    if scope.source().as_str() != "mdm.windows" || sequence < 0 {
        return Err(Error::Malformed);
    }
    definition
        .validate_scope(scope)
        .map_err(|_| Error::Malformed)?;
    rss_mdm_inventory_postgres::register_collection_in(tx, scope.tenant(), &definition)
        .await
        .map_err(|_| corrupt())?;
    let attempts = Attempts::new(definition);
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::uuid,$6,$7,floor(extract(epoch FROM clock_timestamp()))::bigint,$8,'pending')")
        .bind(scope.tenant().to_string()).bind(id.to_string()).bind(scope.registration().as_str()).bind(scope.source().as_str()).bind(scope.epoch().as_str()).bind(scope.encode().map_err(|_| corrupt())?).bind(sequence)
        .bind(serde_json::to_string(&attempts).expect("closed attempts")).execute(tx).await.map_err(db)?;
    Ok(id)
}
pub async fn save_attempts_in(tx: &mut sqlx::PgConnection, run: &Run) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_access.collection_runs SET attempts=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid AND sealed_at IS NULL")
        .bind(run.scope.tenant().to_string()).bind(run.id.to_string()).bind(serde_json::to_string(&run.attempts).expect("closed attempts")).execute(tx).await.map_err(db)?;
    Ok(())
}
pub async fn seal(
    tx: &mut sqlx::PgConnection,
    run: &mut Run,
    reason: &str,
) -> Result<Option<rss_mdm_audit_integration::Fact>, Error> {
    run.attempts.finish();
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
    let body = run.attempts.body().map_err(|_| corrupt())?;
    let result = match body {
        Some(Body::Snapshot(_)) => "snapshot",
        Some(Body::Partial(_)) => "partial",
        _ => "failed",
    };
    let batch = if body.is_some() {
        Some(
            rss_mdm_inventory_postgres::seal_collection_in(
                tx,
                rss_mdm_inventory_postgres::CollectionCompletion {
                    scope: &run.scope,
                    run: &run.id.to_string(),
                    sequence: run.sequence,
                    observed_at: run
                        .attempts
                        .fields()
                        .values()
                        .filter_map(|f| f.received_at)
                        .max()
                        .ok_or_else(corrupt)?,
                    progress: &run.attempts,
                },
            )
            .await
            .map_err(|_| corrupt())?,
        )
    } else {
        None
    };
    let digest = batch
        .as_ref()
        .map(|b| fingerprint(b, &run.scope))
        .transpose()?;
    let changed = sqlx::query("UPDATE mdm_access.collection_runs SET attempts=$3,result=$4,reason=$5,batch=$6,digest=$7,sealed_at=$8,delivery_pending=$9 WHERE tenant_id=$1::uuid AND id=$2::uuid AND sealed_at IS NULL")
        .bind(run.scope.tenant().to_string()).bind(run.id.to_string()).bind(serde_json::to_string(&run.attempts).expect("closed attempts")).bind(result).bind(reason)
        .bind(batch.as_ref().map(|b| b.encode())).bind(&digest).bind(now).bind(batch.is_some()).execute(&mut *tx).await.map_err(db)?.rows_affected();
    if changed == 0 {
        return Ok(None);
    }
    if batch.is_some() {
        crate::wake::notify(tx).await.map_err(db)?;
    }
    // The terminal fact is audited in the caller's transaction. Its owner records commit
    // uncertainty (HTTP envelope or retention task); this helper never commits independently.
    let audit = rss_mdm_audit_integration::RequestAudit::new(
        run.scope.tenant().to_string(),
        "collection_finish",
    );
    audit.operation(run.id, "collection_finish");
    audit.registration(Uuid::parse_str(run.scope.registration().as_str()).map_err(|_| corrupt())?);
    audit.identify_service("service:collection-finalizer");
    let details = serde_json::json!({"collectionResult":result,"reason":reason,"batchDigest":digest,"sealedAt":now});
    let fingerprint = serde_json::to_vec(&details).expect("closed collection outcome");
    let fact = rss_mdm_audit_integration::Fact::business(
        &audit,
        &format!("collection:{}:finish", run.id),
        &fingerprint,
        200,
        if result == "failed" {
            "failed"
        } else {
            "success"
        },
        None,
    )
    .and_then(|fact| fact.with_details(details))
    .map_err(Error::from);
    audit.finalize(None);
    fact.map(Some)
}
/// Terminalize accepted facts before disposing protocol state. Never accepts new device input.
pub async fn terminate(
    tx: &mut sqlx::PgConnection,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    tenant: &str,
    registration: &str,
    reason: &str,
) -> Result<(), Error> {
    let rows = sqlx::query(selection!("tenant_id=$1::uuid AND registration=$2::uuid AND sealed_at IS NULL ORDER BY sequence FOR UPDATE"))
        .bind(tenant).bind(registration).fetch_all(&mut *tx).await.map_err(db)?;
    for row in rows {
        facts.extend(seal(tx, &mut Run::from_row(row)?, reason).await?);
    }
    Ok(())
}
/// Only a persisted server-authored sealed run can mint this recovery capability.
/// It deliberately has no wire constructor or Deserialize implementation.
pub struct DurableReport {
    scope: Scope,
    batch: Batch,
}
impl DurableReport {
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn batch(&self) -> &Batch {
        &self.batch
    }
}

pub async fn agent_report_in(
    connection: &mut sqlx::PgConnection,
    scope: &Scope,
    id: Uuid,
) -> Result<Option<(DurableReport, i64)>, Error> {
    let row = sqlx::query(selection!("tenant_id=$1::uuid AND registration=$2::uuid AND source=$3 AND epoch=$4::uuid AND id=$5::uuid"))
            .bind(scope.tenant().to_string()).bind(scope.registration().as_str()).bind(scope.source().as_str()).bind(scope.epoch().as_str()).bind(id.to_string())
            .fetch_optional(connection).await.map_err(db)?;
    row.map(|row| {
        let received_at = row.try_get("sealed_at").map_err(db)?;
        Ok((durable_report(row)?, received_at))
    })
    .transpose()
}

pub async fn collection(
    database: &crate::Store,
    scope: &Scope,
    id: Option<Uuid>,
) -> Result<Option<Run>, Error> {
    let mut tx = database.begin(&scope.tenant().to_string()).await?;
    let row = sqlx::query(selection!("tenant_id=$1::uuid AND registration=$2::uuid AND source=$3 AND epoch=$4::uuid AND scope::jsonb->>'dataset'='inventory' AND ($5::uuid IS NULL OR id=$5::uuid) ORDER BY sequence DESC LIMIT 1"))
            .bind(scope.tenant().to_string()).bind(scope.registration().as_str()).bind(scope.source().as_str()).bind(scope.epoch().as_str()).bind(id.map(|v| v.to_string()))
            .fetch_optional(&mut *tx).await.map_err(db)?;
    let run = row.map(Run::from_row).transpose()?;
    tx.commit().await.map_err(db)?;
    Ok(run)
}

fn durable_report(row: PgRow) -> Result<DurableReport, Error> {
    let scope = restored_scope(&row)?;
    let attempts: Attempts =
        serde_json::from_str(row.try_get("attempts").map_err(db)?).map_err(|_| corrupt())?;
    attempts
        .definition()
        .validate_scope(&scope)
        .map_err(|_| corrupt())?;
    let (_, _, batch) = restored_batch(&row, &scope, attempts.definition())?;
    if row
        .try_get::<Option<i64>, _>("sealed_at")
        .map_err(db)?
        .is_none()
    {
        return Err(corrupt());
    }
    let batch = batch.ok_or_else(corrupt)?;
    Ok(DurableReport { scope, batch })
}

pub async fn load_on(c: &mut sqlx::PgConnection, tenant: &str, id: Uuid) -> Result<Run, Error> {
    Run::from_row(
        sqlx::query(selection!("tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE"))
            .bind(tenant)
            .bind(id.to_string())
            .fetch_one(c)
            .await
            .map_err(db)?,
    )
}

/// The durable delivery queue consumed by the Inventory worker.
pub struct Delivery {
    audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
    database: std::sync::Arc<crate::Store>,
}
impl Delivery {
    pub fn new(
        database: std::sync::Arc<crate::Store>,
        audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
    ) -> Self {
        Self {
            database,
            audit_store,
        }
    }
    /// Bounded count of real pending delivery rows; 1001 is the overflow sentinel.
    pub async fn pending_count(&self, tenant: &str) -> Result<u64, Error> {
        let mut tx = self.database.begin_read(tenant).await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND delivery_pending LIMIT 1001) q")
            .bind(tenant).fetch_one(&mut *tx).await.map_err(db)?;
        tx.rollback().await.map_err(db)?;
        Ok(count as u64)
    }
    pub async fn pending_reports(&self, tenant: &str) -> Result<Vec<DurableReport>, Error> {
        let mut tx = self.database.begin_read(tenant).await?;
        let rows = sqlx::query(selection!("tenant_id=$1::uuid AND delivery_pending ORDER BY registration,source,epoch,sequence,id LIMIT 32"))
            .bind(tenant).fetch_all(&mut *tx).await.map_err(db)?;
        tx.rollback().await.map_err(db)?;
        rows.into_iter().map(durable_report).collect()
    }
    pub async fn expire_timed(&self, tenant: &str) -> Result<usize, Error> {
        let mut hint = self.database.begin_read(tenant).await?;
        let due: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND sealed_at IS NULL AND deadline<=clock_timestamp())")
            .bind(tenant).fetch_one(&mut *hint).await.map_err(db)?;
        hint.rollback().await.map_err(db)?;
        if !due {
            return Ok(0);
        }
        let audit =
            rss_mdm_audit_integration::RequestAudit::new(tenant.into(), "collection_finish");
        audit.identify_service("service:inventory-delivery");
        let budget = rss_mdm_audit_integration::budget::AuditBudget::retirement(None);
        let control = budget.control();
        let attempt = self
            .audit_store
            .write(
                rss_request_context::TenantId::parse(tenant).map_err(|_| corrupt())?,
                &control,
                (&self.audit_store, tenant, &audit),
                |(store, tenant, audit), tx| {
                    Box::pin(async move {
                        let mut facts = Vec::new();
                        let count = tx
                            .with_connection_context(
                                &mut (*tenant, &mut facts),
                                |(tenant, facts), c| {
                                    Box::pin(async move { expire_timed(c, facts, tenant).await })
                                },
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
    pub async fn next_expiry(&self, tenant: &str) -> Result<Option<std::time::Duration>, Error> {
        let mut tx = self.database.begin_read(tenant).await?;
        let millis: Option<i64> = sqlx::query_scalar("SELECT ceil(extract(epoch FROM min(deadline)-clock_timestamp())*1000)::bigint FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND sealed_at IS NULL AND deadline>clock_timestamp()")
            .bind(tenant).fetch_one(&mut *tx).await.map_err(db)?;
        tx.rollback().await.map_err(db)?;
        Ok(millis.map(|ms| std::time::Duration::from_millis(ms.max(1) as u64)))
    }
    pub async fn delivered(&self, report: &DurableReport) -> Result<(), Error> {
        let mut tx = self
            .database
            .begin(&report.scope.tenant().to_string())
            .await?;
        sqlx::query("UPDATE mdm_access.collection_runs SET delivery_pending=false WHERE tenant_id=$1::uuid AND id=$2::uuid AND digest=$3 AND delivery_pending")
            .bind(report.scope.tenant().to_string())
            .bind(report.batch.id().as_str())
            .bind(fingerprint(&report.batch, &report.scope)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)
    }
}

pub async fn allocate_commands_in(
    c: &mut sqlx::PgConnection,
    p: &DevicePrincipal,
    count: i64,
) -> std::result::Result<u32, Error> {
    let n = crate::device::store::allocate_request_ids_in(
        c,
        p,
        rss_mdm_inventory::ReportSource::MdmWindows,
        count,
        i64::from(u32::MAX),
    )
    .await
    .map_err(db)?;
    n.try_into()
        .map_err(|_| Error::Unavailable(crate::Failure::Protocol))
}

pub async fn expire_timed(
    c: &mut sqlx::PgConnection,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    tenant: &str,
) -> Result<usize, Error> {
    let ids=sqlx::query_as::<_,(String,String)>("SELECT id::text,scope::jsonb->>'dataset' FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND sealed_at IS NULL AND deadline<=clock_timestamp() ORDER BY deadline,id LIMIT 32 FOR UPDATE SKIP LOCKED")
        .bind(tenant).fetch_all(&mut *c).await.map_err(db)?;
    let count = ids.len();
    for (id, dataset) in ids {
        if dataset == rss_mdm_inventory::builtin::AGENT_INSTALLATION.as_str() {
            facts.extend(
                super::channel::abandon_in(
                    c,
                    tenant,
                    Uuid::parse_str(&id).map_err(|_| super::corrupt())?,
                    "timeout",
                )
                .await?,
            );
            continue;
        }
        let mut run = load_on(
            c,
            tenant,
            Uuid::parse_str(&id).map_err(|_| super::corrupt())?,
        )
        .await?;
        facts.extend(seal(c, &mut run, "timeout").await?);
    }
    Ok(count)
}

/// Freeze published field versions when a native adapter admits a run.
pub async fn freeze_in(
    c: &mut sqlx::PgConnection,
    scope: &Scope,
    version: u64,
    keys: &[rss_mdm_inventory::FieldKey],
) -> Result<rss_mdm_inventory::CollectionDefinition, Error> {
    let catalog = rss_mdm_inventory_postgres::catalog_in(c, scope.tenant())
        .await
        .map_err(|_| corrupt())?;
    let fields = keys
        .iter()
        .map(|key| catalog.definition(*key).cloned())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::Malformed)?;
    use sha2::{Digest, Sha256};
    let version = format!(
        "{version}.{:x}",
        Sha256::digest(serde_json::to_vec(&fields).map_err(|_| corrupt())?)
    );
    let definition = rss_mdm_inventory::CollectionDefinition::new(
        scope.dataset().as_str(),
        version,
        rss_mdm_inventory::Source::parse(scope.source().as_str()).map_err(|_| Error::Malformed)?,
        fields,
    )
    .map_err(|_| Error::Malformed)?;
    rss_mdm_inventory_postgres::register_collection_in(c, scope.tenant(), &definition)
        .await
        .map_err(|_| corrupt())?;
    Ok(definition)
}
