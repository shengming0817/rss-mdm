use super::*;
use crate::{AccessStore, access_store::db, device::DevicePrincipal};
use rss_mdm_windows_mdm::{
    CodecLimits,
    syncml::{self, Command, Item},
};
use rss_observation::{Batch, Scope};
use sqlx::{Row, postgres::PgRow};
use uuid::Uuid;

// All restore paths use this shape before minting a Run or recovery capability.
macro_rules! selection {
    ($filter:literal) => {
        concat!("SELECT tenant_id::text,registration::text,source,epoch::text,id::text,scope,sequence,started_at,sealed_at,attempts,result,reason,batch,digest,request,request_message,first_command FROM mdm_access.collection_runs WHERE ", $filter)
    };
}

/// Recheck the principal inside the transaction accepting device input. Lock order matches revoke.
pub(crate) async fn revalidate(
    tx: &mut sqlx::PgConnection,
    principal: &DevicePrincipal,
) -> Result<Scope, Error> {
    revalidate_source(tx, principal, rss_mdm_inventory::ReportSource::MdmWindows).await
}

pub(crate) async fn revalidate_source(
    tx: &mut sqlx::PgConnection,
    principal: &DevicePrincipal,
    source: rss_mdm_inventory::ReportSource,
) -> Result<Scope, Error> {
    if principal.channel() != source.channel() {
        return Err(Error::Forbidden);
    }
    let tenant = principal.tenant().to_string();
    let registration = principal.registration().to_string();
    crate::device::store::lock_channel(tx, &tenant, principal.device(), principal.channel())
        .await?;
    let live = sqlx::query("SELECT device,generation FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2::uuid AND channel=$3 AND state='active'")
        .bind(&tenant).bind(&registration).bind(principal.channel().as_str()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    if live.try_get::<String, _>("device").map_err(db)? != principal.device()
        || live.try_get::<i64, _>("generation").map_err(db)? != principal.generation()
    {
        return Err(Error::Unauthorized);
    }
    sqlx::query("SELECT id FROM mdm_access.credentials WHERE tenant_id=$1::uuid AND registration=$2::uuid AND id=$3::uuid AND state='active'")
        .bind(&tenant).bind(&registration).bind(principal.credential().to_string()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    let row = sqlx::query("SELECT epoch::text FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source=$3 AND enabled AND coverage=$4 FOR UPDATE")
        .bind(&tenant).bind(&registration).bind(source.as_str()).bind(crate::device::coverage_key()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Forbidden)?;
    crate::device::scope(
        principal.tenant(),
        principal.registration(),
        source.as_str(),
        Uuid::parse_str(&row.try_get::<String, _>("epoch").map_err(db)?).map_err(|_| corrupt())?,
    )
}

#[derive(PartialEq, Eq)]
pub(crate) struct Run {
    pub id: Uuid,
    pub scope: Scope,
    pub sequence: u64,
    pub started_at: i64,
    pub sealed_at: Option<i64>,
    pub attempts: Attempts,
    pub result: RunResult,
    pub reason: Option<FinishReason>,
    batch: Option<Batch>,
    request: Vec<u8>,
    request_message: u32,
    first_command: u32,
}
fn restored_scope(row: &PgRow) -> Result<Scope, Error> {
    let scope = serde_json::from_str::<Scope>(&row.try_get::<String, _>("scope").map_err(db)?)
        .map_err(|_| corrupt())?;
    if scope.tenant().to_string() != row.try_get::<String, _>("tenant_id").map_err(db)?
        || scope.registration().as_str() != row.try_get::<String, _>("registration").map_err(db)?
        || scope.source().as_str() != row.try_get::<String, _>("source").map_err(db)?
        || scope.epoch().as_str() != row.try_get::<String, _>("epoch").map_err(db)?
        || scope.dataset().as_str() != rss_mdm_inventory::DATASET
    {
        return Err(corrupt());
    }
    Ok(scope)
}

fn restored_batch(row: &PgRow, scope: &Scope) -> Result<(Uuid, u64, Option<Batch>), Error> {
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
                || batch.coverage() != &rss_mdm_inventory::coverage()
                || Some(digest) != row.try_get::<Option<String>, _>("digest").map_err(db)?
            {
                return Err(corrupt());
            }
            rss_mdm_inventory::validate(&batch).map_err(|_| corrupt())?;
            Ok(batch)
        })
        .transpose()?;
    Ok((id, sequence, batch))
}

impl Run {
    fn from_row(row: PgRow) -> Result<Self, Error> {
        let scope = restored_scope(&row)?;
        let (id, sequence, batch) = restored_batch(&row, &scope)?;
        Ok(Self {
            id,
            scope,
            sequence,
            batch,
            started_at: row.try_get("started_at").map_err(db)?,
            sealed_at: row.try_get("sealed_at").map_err(db)?,
            attempts: serde_json::from_str(&row.try_get::<String, _>("attempts").map_err(db)?)
                .map_err(|_| corrupt())?,
            result: RunResult::parse(&row.try_get::<String, _>("result").map_err(db)?)?,
            reason: row
                .try_get::<Option<String>, _>("reason")
                .map_err(db)?
                .as_deref()
                .map(FinishReason::parse)
                .transpose()?,
            request: row.try_get("request").map_err(db)?,
            request_message: row
                .try_get::<i64, _>("request_message")
                .map_err(db)?
                .try_into()
                .map_err(|_| corrupt())?,
            first_command: row
                .try_get::<i64, _>("first_command")
                .map_err(db)?
                .try_into()
                .map_err(|_| corrupt())?,
        })
    }
    pub(crate) fn batch(&self) -> Option<&Batch> {
        self.batch.as_ref()
    }
}
fn fingerprint(batch: &Batch, scope: &Scope) -> Result<String, Error> {
    Ok(batch
        .fingerprint(scope)
        .map_err(|_| corrupt())?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

pub(crate) async fn create(
    tx: &mut sqlx::PgConnection,
    scope: &Scope,
    response: &mut syncml::Message,
) -> Result<Uuid, Error> {
    let row = sqlx::query("UPDATE mdm_access.report_sources SET next_sequence=next_sequence+1,next_command=next_command+$4 WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source='mdm.windows' AND epoch=$3::uuid AND enabled AND next_sequence<9223372036854775807 AND next_command<=$5 RETURNING next_sequence-1 AS sequence,next_command-$4 AS command")
        .bind(scope.tenant().to_string()).bind(scope.registration().as_str()).bind(scope.epoch().as_str())
        .bind(FIELD_COUNT as i64).bind(i64::from(u32::MAX) - FIELD_COUNT as i64 + 1)
        .fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::Conflict)?;
    let first: i64 = row.try_get("command").map_err(db)?;
    for (index, key) in FieldKey::observed().enumerate() {
        response.commands.push(Command::Get {
            id: first as u32 + index as u32,
            meta: None,
            items: vec![Item {
                source: None,
                target: Some(uri(key).into()),
                meta: None,
                data: None,
            }],
        });
    }
    let (request, _) =
        syncml::encode_request(response, &CodecLimits::default()).map_err(|_| corrupt())?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,session_id,request_message,first_command,request,started_at,attempts,result) VALUES($1::uuid,$2::uuid,$3::uuid,'mdm.windows',$4::uuid,$5,$6,$7,$8,$9,$10,floor(extract(epoch FROM clock_timestamp()))::bigint,$11,'pending')")
        .bind(scope.tenant().to_string()).bind(id.to_string()).bind(scope.registration().as_str()).bind(scope.epoch().as_str()).bind(scope.encode().map_err(|_| corrupt())?)
        .bind(row.try_get::<i64,_>("sequence").map_err(db)?).bind(response.header.session_id.to_string()).bind(i64::from(response.header.message_id)).bind(first).bind(request)
        .bind(serde_json::to_string(&Attempts::default()).expect("closed attempts")).execute(&mut *tx).await.map_err(db)?;
    Ok(id)
}
pub(crate) async fn accept(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
    message: &syncml::Message,
    previous: &str,
) -> Result<bool, Error> {
    let row = sqlx::query(selection!("tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE"))
        .bind(tenant)
        .bind(id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
    let mut run = Run::from_row(row)?;
    if run.sealed_at.is_some() {
        if message
            .commands
            .iter()
            .any(|c| matches!(c, Command::Results(_)))
        {
            return Err(Error::Conflict);
        }
        return Ok(true);
    }
    let limits = CodecLimits::default();
    let previous = syncml::decode(previous.as_bytes(), &limits).map_err(|_| corrupt())?;
    let (_, sent) = syncml::encode_request(&previous, &limits).map_err(|_| corrupt())?;
    let mut expected =
        syncml::Expected::new(sent, message.header.message_id, &limits).map_err(|_| corrupt())?;
    if previous.header.message_id != run.request_message {
        let sent = syncml::decode(&run.request, &limits).map_err(|_| corrupt())?;
        let (_, sent) = syncml::encode_request(&sent, &limits).map_err(|_| corrupt())?;
        expected.record_sent(sent, &limits).map_err(|_| corrupt())?;
    }
    let correlated = syncml::correlate(&expected, message, &limits).map_err(|_| Error::Conflict)?;
    let received_at: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
    run.attempts.apply(
        &correlated,
        run.request_message,
        run.first_command,
        received_at,
    )?;
    let terminal = run.attempts.complete() || message.header.message_id == 8;
    if terminal {
        let reason = if run.attempts.complete() {
            "complete"
        } else {
            "message_budget"
        };
        seal(tx, &mut run, reason).await?;
    } else {
        sqlx::query("UPDATE mdm_access.collection_runs SET attempts=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid AND sealed_at IS NULL")
            .bind(tenant).bind(id.to_string()).bind(serde_json::to_string(&run.attempts).expect("closed attempts")).execute(&mut *tx).await.map_err(db)?;
    }
    Ok(terminal)
}
async fn seal(tx: &mut sqlx::PgConnection, run: &mut Run, reason: &str) -> Result<(), Error> {
    run.attempts.finish();
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
    let body = run.attempts.body();
    let result = match body {
        Some(Body::Snapshot(_)) => "snapshot",
        Some(Body::Partial(_)) => "partial",
        _ => "failed",
    };
    let batch = body
        .map(|body| {
            Batch::new(
                Id::new(run.id.to_string()).map_err(|_| corrupt())?,
                run.sequence,
                rss_contract::Timepoint::try_from(
                    run.attempts
                        .fields
                        .iter()
                        .filter_map(|field| field.received_at)
                        .max()
                        .ok_or_else(corrupt)?,
                )
                .map_err(|_| corrupt())?,
                rss_mdm_inventory::coverage(),
                body,
            )
            .map_err(|_| corrupt())
        })
        .transpose()?;
    let digest = batch
        .as_ref()
        .map(|b| fingerprint(b, &run.scope))
        .transpose()?;
    sqlx::query("UPDATE mdm_access.collection_runs SET attempts=$3,result=$4,reason=$5,batch=$6,digest=$7,sealed_at=$8,delivery_pending=$9 WHERE tenant_id=$1::uuid AND id=$2::uuid AND sealed_at IS NULL")
        .bind(run.scope.tenant().to_string()).bind(run.id.to_string()).bind(serde_json::to_string(&run.attempts).expect("closed attempts")).bind(result).bind(reason)
        .bind(batch.as_ref().map(|b| b.encode())).bind(digest).bind(now).bind(batch.is_some()).execute(&mut *tx).await.map_err(db)?;
    // The terminal fact is audited in the caller's transaction. Its owner records commit
    // uncertainty (HTTP envelope or retention task); this helper never commits independently.
    let audit = crate::audit::Audit::new(run.scope.tenant().to_string(), "collection_finish");
    audit.operation(run.id, "collection_finish");
    audit.registration(Uuid::parse_str(run.scope.registration().as_str()).map_err(|_| corrupt())?);
    let result = crate::access_store::append_on_connection(tx, &audit, 200, "success", None).await;
    audit.finalize(
        result
            .as_ref()
            .err()
            .map(|_| crate::audit::FailureReason::Transaction),
    );
    result
}
/// Terminalize accepted facts before disposing protocol state. Never accepts new device input.
pub(crate) async fn terminate(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    registration: &str,
    reason: &str,
) -> Result<(), Error> {
    terminate_session(tx, tenant, registration, None, reason).await
}
pub(crate) async fn terminate_session(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    registration: &str,
    session: Option<&str>,
    reason: &str,
) -> Result<(), Error> {
    let rows = sqlx::query(selection!("tenant_id=$1::uuid AND registration=$2::uuid AND sealed_at IS NULL AND ($3::text IS NULL OR session_id=$3) ORDER BY sequence FOR UPDATE"))
        .bind(tenant).bind(registration).bind(session).fetch_all(&mut *tx).await.map_err(db)?;
    for row in rows {
        seal(tx, &mut Run::from_row(row)?, reason).await?;
    }
    Ok(())
}
/// Only a persisted server-authored sealed run can mint this recovery capability.
/// It deliberately has no wire constructor or Deserialize implementation.
pub(crate) struct DurableReport {
    scope: Scope,
    batch: Batch,
}
impl DurableReport {
    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }
    pub(crate) fn batch(&self) -> &Batch {
        &self.batch
    }
}
impl AccessStore {
    pub(crate) async fn pending_reports(&self, tenant: &str) -> Result<Vec<DurableReport>, Error> {
        let mut tx = self.begin(tenant).await?;
        let rows = sqlx::query(selection!("tenant_id=$1::uuid AND delivery_pending ORDER BY registration,source,epoch,sequence,id LIMIT 32"))
            .bind(tenant).fetch_all(&mut *tx).await.map_err(db)?;
        let reports: Vec<DurableReport> = rows
            .into_iter()
            .map(durable_report)
            .collect::<Result<_, Error>>()?;
        tx.commit().await.map_err(db)?;
        Ok(reports)
    }

    pub(crate) async fn agent_report_in(
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
    pub(crate) async fn delivered(&self, report: &DurableReport) -> Result<(), Error> {
        let mut tx = self.begin(&report.scope.tenant().to_string()).await?;
        sqlx::query("UPDATE mdm_access.collection_runs SET delivery_pending=false WHERE tenant_id=$1::uuid AND id=$2::uuid AND digest=$3 AND delivery_pending")
            .bind(report.scope.tenant().to_string())
            .bind(report.batch.id().as_str())
            .bind(fingerprint(&report.batch, &report.scope)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)
    }
    pub(crate) async fn collection(
        &self,
        scope: &Scope,
        id: Option<Uuid>,
    ) -> Result<Option<Run>, Error> {
        let mut tx = self.begin(&scope.tenant().to_string()).await?;
        let row = sqlx::query(selection!("tenant_id=$1::uuid AND registration=$2::uuid AND source=$3 AND epoch=$4::uuid AND ($5::uuid IS NULL OR id=$5::uuid) ORDER BY sequence DESC LIMIT 1"))
            .bind(scope.tenant().to_string()).bind(scope.registration().as_str()).bind(scope.source().as_str()).bind(scope.epoch().as_str()).bind(id.map(|v| v.to_string()))
            .fetch_optional(&mut *tx).await.map_err(db)?;
        let run = row.map(Run::from_row).transpose()?;
        tx.commit().await.map_err(db)?;
        Ok(run)
    }
}

fn durable_report(row: PgRow) -> Result<DurableReport, Error> {
    let scope = restored_scope(&row)?;
    let (_, _, batch) = restored_batch(&row, &scope)?;
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
