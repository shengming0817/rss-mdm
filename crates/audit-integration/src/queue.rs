//! MDM-owned source receipts and backlog accounting inside the caller's RSS transaction.
use crate::{Error, source::FrozenFact};
use rss_transactional_messaging::outbox::{AppendOutcome, OutboxWriter};
use rss_transactional_messaging_postgres::{PgOutboxWriter, PgTransaction};
use sqlx::Row;

#[derive(Clone, Copy, Debug)]
pub struct BacklogLimits {
    events: i64,
    bytes: i64,
}
impl Default for BacklogLimits {
    fn default() -> Self {
        Self {
            events: 100_000,
            bytes: 1_073_741_824,
        }
    }
}
impl BacklogLimits {
    pub fn new(events: u64, bytes: u64) -> Result<Self, Error> {
        let events = i64::try_from(events).map_err(|_| Error::Admission)?;
        let bytes = i64::try_from(bytes).map_err(|_| Error::Admission)?;
        if events < 1 || bytes < 1 {
            return Err(Error::Admission);
        }
        Ok(Self { events, bytes })
    }
    pub fn events(self) -> u64 {
        self.events as u64
    }
    pub fn bytes(self) -> u64 {
        self.bytes as u64
    }
    fn reserved(self) -> Self {
        Self {
            events: self.events / 10 + i64::from(self.events % 10 != 0),
            bytes: self.bytes / 10 + i64::from(self.bytes % 10 != 0),
        }
    }
}
pub(crate) struct StagedFact {
    pub(crate) frozen: FrozenFact,
    pub(crate) existing: Option<bool>,
}

pub(crate) async fn append(
    tx: &mut PgTransaction<'_>,
    writer: &PgOutboxWriter,
    frozen: &FrozenFact,
    existing: Option<bool>,
    limits: BacklogLimits,
) -> Result<(), Error> {
    writer
        .validate_transaction(tx)
        .map_err(rss_audit_postgres::Error::from)?;
    let id = frozen.identity()?;
    if tx.tenant_id() != id.tenant() {
        return Err(Error::Receipt);
    }
    let tenant = id.tenant().to_string();
    let source = id.source().source_id().as_str().to_owned();
    let event = id.event_id().as_str().to_owned();
    let saved = tx.with_connection_context(&mut (&tenant, &source, &event), |(tenant, source, event), c| Box::pin(async move {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::text,$3::text)::text,2891))")
            .bind(*tenant).bind(*source).bind(*event).execute(&mut *c).await?;
        sqlx::query("SELECT fingerprint,source_bytes,message_id,projected_at FROM mdm_audit.receipts WHERE tenant_id=$1::uuid AND source_id=$2 AND event_id=$3")
            .bind(*tenant).bind(*source).bind(*event).fetch_optional(c).await
    })).await.map_err(rss_audit_postgres::Error::from)?;
    let message = frozen.message()?;
    let message_id = message.message_id().as_str().to_owned();
    if let Some(row) = saved {
        let bytes: Vec<u8> = row.try_get("source_bytes")?;
        let fingerprint: Vec<u8> = row.try_get("fingerprint")?;
        let saved = FrozenFact::decode(&bytes)?;
        if existing == Some(false)
            || !saved.same_facts(frozen)
            || fingerprint != frozen.fingerprint()
        {
            return Err(Error::Receipt);
        }
        let message = saved.message()?;
        if row.try_get::<String, _>("message_id")? != message_id {
            return Err(Error::Receipt);
        }
        let outcome = writer
            .append(tx, message)
            .await
            .map_err(rss_transactional_messaging_postgres::PgError::from)
            .map_err(rss_audit_postgres::Error::from)?;
        if !matches!(outcome, AppendOutcome::AlreadyPresent) {
            return Err(Error::Receipt);
        }
        return Ok(());
    }
    if existing == Some(true) {
        return Err(Error::Receipt);
    }
    let size = i64::try_from(frozen.bytes().len()).map_err(|_| Error::Receipt)?;
    let reserved = reserve(tx, limits, size, frozen.reserve_eligible()).await?;
    let outcome = writer
        .append(tx, message)
        .await
        .map_err(rss_transactional_messaging_postgres::PgError::from)
        .map_err(rss_audit_postgres::Error::from)?;
    if !matches!(outcome, AppendOutcome::Inserted) {
        return Err(Error::Receipt);
    }
    tx.with_connection_context(&mut (tenant, source, event, frozen, message_id), |(tenant, source, event, frozen, message), c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_audit.receipts(tenant_id,source_id,event_id,fingerprint,source_bytes,message_id,reserved,enqueued_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,floor(extract(epoch FROM clock_timestamp()))::bigint)")
            .bind(&*tenant).bind(&*source).bind(&*event).bind(frozen.fingerprint().as_slice())
            .bind(frozen.bytes()).bind(&*message).bind(reserved).execute(c).await?;
        Ok(())
    })).await.map_err(rss_audit_postgres::Error::from)?;
    Ok(())
}

async fn reserve(
    tx: &mut PgTransaction<'_>,
    limits: BacklogLimits,
    size: i64,
    eligible: bool,
) -> Result<bool, Error> {
    let tenant = tx.tenant_id().to_string();
    let held = tx.with_connection_context(&mut tenant.clone(), |tenant, c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_audit.backlog(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING")
            .bind(&*tenant).execute(&mut *c).await?;
        Ok(())
    })).await.map_err(rss_audit_postgres::Error::from);
    held?;
    if charge(tx, &tenant, limits, size, false).await? {
        return Ok(false);
    }
    if !eligible {
        return Err(Error::BacklogFull);
    }
    if charge(tx, &tenant, limits.reserved(), size, true).await? {
        return Ok(true);
    }
    Err(Error::ReserveExhausted)
}
async fn charge(
    tx: &mut PgTransaction<'_>,
    mut tenant: &str,
    limits: BacklogLimits,
    size: i64,
    reserved: bool,
) -> Result<bool, Error> {
    // Static SQL choices are product quota classes, never caller-supplied column names.
    let sql = if reserved {
        "UPDATE mdm_audit.backlog SET reserved_events=reserved_events+1,reserved_bytes=reserved_bytes+$2 WHERE tenant_id=$1::uuid AND reserved_events<$3 AND reserved_bytes<=$4-$2"
    } else {
        "UPDATE mdm_audit.backlog SET events=events+1,bytes=bytes+$2 WHERE tenant_id=$1::uuid AND events<$3 AND bytes<=$4-$2"
    };
    let affected = tx
        .with_connection_context(&mut tenant, |tenant, c| {
            Box::pin(async move {
                Ok(sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(*tenant)
                    .bind(size)
                    .bind(limits.events)
                    .bind(limits.bytes)
                    .execute(c)
                    .await?
                    .rows_affected())
            })
        })
        .await
        .map_err(rss_audit_postgres::Error::from)?;
    Ok(affected == 1)
}

/// Part of the local projection effect, so this marker and quota release share the sink commit.
/// A controlled transport replay may carry a new message ID, but never new source facts.
pub(crate) async fn projected(
    tx: &mut PgTransaction<'_>,
    frozen: &FrozenFact,
    recorded_at: i64,
    inserted: bool,
) -> Result<(), Error> {
    let id = frozen.identity()?;
    if tx.tenant_id() != id.tenant() {
        return Err(Error::Receipt);
    }
    let mut key = (
        id.tenant().to_string(),
        id.source().source_id().as_str().to_owned(),
        id.event_id().as_str().to_owned(),
    );
    let row = tx.with_connection_context(&mut key, |(tenant, source, event), c| Box::pin(async move {
        sqlx::query("SELECT fingerprint,source_bytes,projected_at,reserved FROM mdm_audit.receipts WHERE tenant_id=$1::uuid AND source_id=$2 AND event_id=$3 FOR UPDATE")
            .bind(&*tenant).bind(&*source).bind(&*event).fetch_optional(c).await
    })).await.map_err(rss_audit_postgres::Error::from)?.ok_or(Error::Receipt)?;
    if row.try_get::<Vec<u8>, _>("source_bytes")? != frozen.bytes()
        || row.try_get::<Vec<u8>, _>("fingerprint")? != frozen.fingerprint()
    {
        return Err(Error::Receipt);
    }
    match (inserted, row.try_get::<Option<i64>, _>("projected_at")?) {
        (false, Some(previous)) if previous == recorded_at => return Ok(()),
        (true, None) => {}
        _ => return Err(Error::Receipt),
    }
    let reserved: bool = row.try_get("reserved")?;
    let size = i64::try_from(frozen.bytes().len()).map_err(|_| Error::Receipt)?;
    let changed = tx.with_connection_context(&mut key, |(tenant, source, event), c| Box::pin(async move {
        let sql = if reserved {
            "UPDATE mdm_audit.backlog SET reserved_events=reserved_events-1,reserved_bytes=reserved_bytes-$2 WHERE tenant_id=$1::uuid AND reserved_events>0 AND reserved_bytes>=$2"
        } else {
            "UPDATE mdm_audit.backlog SET events=events-1,bytes=bytes-$2 WHERE tenant_id=$1::uuid AND events>0 AND bytes>=$2"
        };
        let released = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(&*tenant).bind(size).execute(&mut *c).await?.rows_affected();
        if released != 1 { return Ok(false); }
        let marked = sqlx::query("UPDATE mdm_audit.receipts SET projected_at=$4 WHERE tenant_id=$1::uuid AND source_id=$2 AND event_id=$3 AND projected_at IS NULL")
            .bind(&*tenant).bind(&*source).bind(&*event).bind(recorded_at).execute(c).await?.rows_affected();
        Ok(marked == 1)
    })).await.map_err(rss_audit_postgres::Error::from)?;
    if !changed {
        return Err(Error::Receipt);
    }
    Ok(())
}
