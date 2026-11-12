//! Windows durable receipt and effect evidence, independent of business status.
use crate::participants::AttemptPhase;
use crate::{Error, Failure, native};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgConnection, Row};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;
type Result<T> = std::result::Result<T, Error>;
fn stored<T, E>(v: std::result::Result<T, E>) -> Result<T> {
    v.map_err(|_| Error::Unavailable(Failure::Protocol))
}
pub struct Read {
    pub id: Uuid,
    pub device: rss_mdm_agent_wire::DeviceId,
    pub request: rss_mdm_windows_mdm::native::Execution,
    pub values: bool,
}
pub struct Evidence {
    pub receipts: Vec<WindowsReceipt>,
    pub assessment: rss_mdm_windows_mdm::native::verification::EffectAssessment,
}
pub struct InstallationRead {
    pub id: Uuid,
    pub device: rss_mdm_agent_wire::DeviceId,
    pub snapshot: Option<Uuid>,
}
#[derive(Debug, Default, PartialEq, Eq)]
pub enum InstallationDelivery {
    #[default]
    Unknown,
    Acknowledged,
    Rejected,
}
#[derive(Default)]
pub struct Installation {
    pub channel_state: Option<serde_json::Value>,
    pub delivery: InstallationDelivery,
}
pub struct Results {
    pub protection: Arc<rss_mdm_native_protection::Protector>,
}
impl Results {
    pub async fn installations(
        &self,
        c: &mut PgConnection,
        tenant: TenantId,
        reads: &[InstallationRead],
    ) -> Result<BTreeMap<Uuid, Installation>> {
        if reads.is_empty() {
            return Ok(BTreeMap::new());
        }
        if reads.len() > 1000 {
            return Err(Error::Malformed);
        }
        let inputs = reads
            .iter()
            .map(|r| {
                serde_json::json!({
                    "operation": r.id, "device": r.device, "snapshot": r.snapshot,
                })
            })
            .collect::<Vec<_>>();
        let rows = sqlx::query(INSTALLATIONS)
            .bind(tenant.to_string())
            .bind(serde_json::json!(inputs))
            .fetch_all(c)
            .await?;
        rss_mdm_query_postgres::observe_rows("windows.installations", &rows)?;
        let mut output = BTreeMap::new();
        for row in rows {
            if !row.try_get::<bool, _>("within_budget")? {
                return Err(Error::Conflict);
            }
            if let Some(id) = row.try_get::<Option<Uuid>, _>("operation")? {
                output.insert(
                    id,
                    Installation {
                        channel_state: row.try_get("channel_state")?,
                        delivery: match row.try_get::<Option<i32>, _>("delivery_status")? {
                            Some(200 | 202) => InstallationDelivery::Acknowledged,
                            Some(n) if n >= 400 => InstallationDelivery::Rejected,
                            _ => InstallationDelivery::Unknown,
                        },
                    },
                );
            }
        }
        Ok(output)
    }

    pub async fn observations(
        &self,
        c: &mut PgConnection,
        tenant: TenantId,
        reads: &[Read],
    ) -> Result<BTreeMap<Uuid, Evidence>> {
        let ids = reads.iter().map(|r| r.id).collect::<Vec<_>>();
        let receipts = read_evidence_rows_on(c, tenant, WINDOWS_RECEIPTS, ids.clone()).await?;
        let platforms = read_evidence_rows_on(c, tenant, WINDOWS_PLATFORMS, ids.clone()).await?;
        let endpoints = read_evidence_rows_on(c, tenant, WINDOWS_ENDPOINTS, ids).await?;
        let mut result = BTreeMap::new();
        for op in reads {
            let rows = receipts.get(&op.id).map(Vec::as_slice).unwrap_or(&[]);
            let state = platforms
                .get(&op.id)
                .and_then(|v| v.first())
                .map(|r| r.try_get::<Option<Value>, _>("platform"))
                .transpose()
                .map_err(crate::database::db)?
                .flatten();
            let endpoint = endpoints.get(&op.id).and_then(|v| v.first());
            let assessment = effect_from_rows(&self.protection, tenant, op, rows, state, endpoint)?;
            result.insert(
                op.id,
                windows_from_rows(&self.protection, tenant, op, rows, assessment, op.values)?,
            );
        }
        Ok(result)
    }
    pub async fn received(
        &self,
        c: &mut PgConnection,
        p: &rss_mdm_registration_service::DevicePrincipal,
        session: u32,
        after: Option<Uuid>,
    ) -> Result<Vec<Uuid>> {
        sqlx::query_scalar("SELECT DISTINCT a.operation FROM mdm_windows.attempts AS a INNER JOIN mdm_windows.attempt_items AS i ON (i.tenant_id, i.attempt) = (a.tenant_id, a.id) WHERE a.tenant_id = CAST($1 AS uuid) AND a.device = $2 AND a.credential = $3 AND a.session = $4 AND i.receipt_accepted AND (CAST($5 AS uuid) IS NULL OR a.operation > $5) ORDER BY a.operation LIMIT 64").bind(p.tenant().to_string()).bind(p.device().into_uuid()).bind(p.credential()).bind(i64::from(session)).bind(after).fetch_all(c).await.map_err(crate::database::db)
    }
    pub async fn settlement(
        &self,
        c: &mut PgConnection,
        tenant: TenantId,
        id: Uuid,
        complete: bool,
    ) -> Result<rss_mdm_windows_mdm::native::receipt::Settlement> {
        let rows=sqlx::query("SELECT a.phase,i.kind,i.status,i.value IS NOT NULL AS has_value,i.receipt_accepted,i.result_accepted FROM mdm_windows.attempts a JOIN mdm_windows.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) WHERE a.tenant_id=$1::uuid AND a.operation=$2 AND a.ordinal=(SELECT max(last.ordinal) FROM mdm_windows.attempts last WHERE last.tenant_id=a.tenant_id AND last.operation=a.operation AND last.phase=a.phase) ORDER BY i.command,i.item_ordinal").bind(tenant.to_string()).bind(id).fetch_all(c).await.map_err(crate::database::db)?;
        let evidence = rows
            .iter()
            .map(|row| {
                native::item_evidence(
                    row,
                    AttemptPhase::parse(
                        &row.try_get::<String, _>("phase")
                            .map_err(crate::database::db)?,
                    )?
                    .receipt_role(),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(rss_mdm_windows_mdm::native::receipt::settle(
            &evidence, complete,
        ))
    }
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsReceipt {
    pub phase: AttemptPhase,
    pub ordinal: i64,
    pub session: i64,
    pub message: i64,
    pub command: i64,
    pub parent_command: Option<i64>,
    pub item: i32,
    pub kind: String,
    pub uri: Option<String>,
    pub status: Option<i32>,
    pub value: Option<String>,
    pub accepted: Option<bool>,
    pub received_at: Option<i64>,
    pub result_accepted: Option<bool>,
    pub result_received_at: Option<i64>,
    pub frames: Vec<WindowsFrame>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub redacted: bool,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsFrame {
    pub message: i64,
    pub command: i64,
    pub start_byte: i64,
    pub end_byte: i64,
    pub total_bytes: i64,
    pub status: Option<i32>,
    pub accepted: Option<bool>,
    pub received_at: Option<i64>,
}
fn windows_from_rows(
    protection: &rss_mdm_native_protection::Protector,
    tenant: TenantId,
    op: &Read,
    rows: &[sqlx::postgres::PgRow],
    assessment: rss_mdm_windows_mdm::native::verification::EffectAssessment,
    native_values: bool,
) -> Result<Evidence> {
    let mut receipts = Vec::with_capacity(rows.len());
    for row in rows {
        let value = if !native_values {
            None
        } else {
            result_value(protection, tenant, op, row)?
        };
        let receipt = WindowsReceipt {
            phase: AttemptPhase::parse(&row.try_get::<String, _>("phase")?)?,
            ordinal: row.try_get("ordinal")?,
            session: row.try_get("session")?,
            message: row.try_get("message")?,
            command: row.try_get("command")?,
            parent_command: row.try_get("parent_command")?,
            item: row.try_get("item_ordinal")?,
            kind: row.try_get("kind")?,
            uri: row.try_get("uri")?,
            status: row.try_get("status")?,
            value,
            accepted: row.try_get("receipt_accepted")?,
            received_at: row.try_get("received_at")?,
            result_accepted: row.try_get("result_accepted")?,
            result_received_at: row.try_get("result_received_at")?,
            frames: stored(serde_json::from_value(row.try_get::<Value, _>("frames")?))?,
            redacted: !native_values,
        };
        receipts.push(receipt);
    }
    Ok(Evidence {
        receipts,
        assessment,
    })
}
fn result_value(
    protection: &rss_mdm_native_protection::Protector,
    tenant: TenantId,
    op: &Read,
    row: &sqlx::postgres::PgRow,
) -> Result<Option<String>> {
    let Some(sealed) = row.try_get::<Option<Vec<u8>>, _>("value")? else {
        return Ok(None);
    };
    let aad = native::result_aad(
        tenant,
        &op.device,
        row.try_get("protocol_epoch")?,
        row.try_get("attempt")?,
        row.try_get("command")?,
        row.try_get("item_ordinal")?,
    )?;
    let plain = protection
        .open_bytes(&sealed, &aad)
        .map_err(|_| Error::Unavailable(Failure::Protocol))?;
    Ok(Some(
        String::from_utf8(plain.expose().to_vec()).map_err(|_| Error::Malformed)?,
    ))
}
fn effect_from_rows(
    protection: &rss_mdm_native_protection::Protector,
    tenant: TenantId,
    op: &Read,
    receipts: &[sqlx::postgres::PgRow],
    state: Option<Value>,
    endpoint: Option<&sqlx::postgres::PgRow>,
) -> Result<rss_mdm_windows_mdm::native::verification::EffectAssessment> {
    use rss_mdm_windows_mdm::native::{
        Context, Execution,
        verification::{EffectAssessment, EffectFact, EffectState},
    };
    let Execution::SyncMl { request } = &op.request else {
        return Ok(EffectAssessment {
            state: EffectState::Unverifiable,
            reason: Some("software_requires_installation_evidence"),
        });
    };
    let Some(state) = state else {
        return Ok(EffectAssessment::waiting("missing_target_evidence"));
    };
    let context: Context = stored(serde_json::from_value(state))?;
    let plan = request
        .effect_plan(context)
        .map_err(|_| Error::Unsupported)?;
    if plan.readback().is_none() {
        return Ok(plan.assess(&[]));
    }
    let rows = completed_rows(receipts)?;
    let addresses = request
        .management_addresses()
        .map_err(|_| Error::Malformed)?;
    if !addresses.is_empty() {
        let Some(endpoint) = endpoint else {
            return Ok(EffectAssessment::waiting(
                "management_address_reconnect_required",
            ));
        };
        let session = endpoint.try_get::<i64, _>("session")?.to_string();
        let credential: Uuid = endpoint.try_get("credential")?;
        let message: i64 = endpoint.try_get("message")?;
        let plain = protection
            .open_bytes(
                &endpoint.try_get::<Vec<u8>, _>("response")?,
                &crate::protection::native_aad(
                    tenant,
                    "windows.management.response",
                    &(
                        &op.device,
                        endpoint.try_get::<Uuid, _>("protocol_epoch")?,
                        credential,
                        &session,
                        message,
                    ),
                )?,
            )
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        let reply = rss_mdm_windows_mdm::syncml::decode(
            plain.expose(),
            &rss_mdm_windows_mdm::CodecLimits::default(),
        )
        .map_err(|_| Error::Malformed)?;
        if !addresses.contains(&reply.header.source) {
            return Ok(EffectAssessment::waiting(
                "management_address_reconnect_required",
            ));
        }
    }
    let mut facts = Vec::new();
    for row in rows {
        facts.push(EffectFact {
            uri: row.try_get::<Option<String>, _>("uri")?.unwrap_or_default(),
            status: row.try_get("status")?,
            value: result_value(protection, tenant, op, row)?,
            receipt_accepted: row.try_get::<Option<bool>, _>("receipt_accepted")? == Some(true),
            result_accepted: row.try_get::<Option<bool>, _>("result_accepted")? == Some(true),
        });
    }
    Ok(plan.assess(&facts))
}

/// The Windows owner, not SQL, decides which complete observation is authoritative.
fn completed_rows(rows: &[sqlx::postgres::PgRow]) -> Result<Vec<&sqlx::postgres::PgRow>> {
    use rss_mdm_windows_mdm::native::receipt::{ItemEvidence, ReceiptRole};
    let mut attempts = std::collections::BTreeMap::<i64, Vec<_>>::new();
    for row in rows {
        if row.try_get::<String, _>("phase")? == "observe" {
            attempts
                .entry(row.try_get("ordinal")?)
                .or_default()
                .push(row);
        }
    }
    for rows in attempts.into_values().rev() {
        let evidence = rows
            .iter()
            .map(|r| native::item_evidence(r, ReceiptRole::Observe))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !evidence.is_empty() && evidence.iter().all(ItemEvidence::complete) {
            return Ok(rows);
        }
    }
    Ok(Vec::new())
}
async fn read_evidence_rows_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    select: &'static str,
    ids: Vec<Uuid>,
) -> Result<std::collections::BTreeMap<Uuid, Vec<sqlx::postgres::PgRow>>> {
    if ids.len() > 1000 {
        return Err(Error::Malformed);
    }
    let tenant = tenant.to_string();
    let sql = format!(
        "WITH selected AS MATERIALIZED ({select}), budget AS (SELECT count(*)<=8192 AND coalesce(sum(pg_column_size(selected)),0)<=16777216 AS ok FROM selected) SELECT selected.*,budget.ok AS within_budget FROM budget LEFT JOIN selected ON budget.ok"
    );
    let rows = {
        let c = &mut *c;
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(tenant)
            .bind(ids)
            .fetch_all(c)
            .await
    }?;
    rss_mdm_query_postgres::observe_rows("execution.windows", &rows)?;
    let mut result = std::collections::BTreeMap::<_, Vec<_>>::new();
    for row in rows {
        if !row.try_get::<bool, _>("within_budget")? {
            return Err(Error::Conflict);
        }
        if let Some(id) = row.try_get::<Option<Uuid>, _>("operation")? {
            result.entry(id).or_default().push(row);
        }
    }
    Ok(result)
}
const WINDOWS_RECEIPTS: &str = "SELECT a.operation,a.protocol_epoch,a.id AS attempt,a.phase,a.ordinal,a.session,a.message,i.command,i.parent_command,i.item_ordinal,i.kind,i.uri,i.status,i.value,i.value IS NOT NULL AS has_value,i.receipt_accepted,i.received_at,i.result_accepted,i.result_received_at,coalesce((SELECT jsonb_agg(jsonb_build_object('message',f.message,'command',f.command,'startByte',f.start_byte,'endByte',f.end_byte,'totalBytes',f.total_bytes,'status',f.status,'accepted',f.accepted,'receivedAt',f.received_at) ORDER BY f.message,f.command) FROM mdm_windows.attempt_frames f WHERE f.tenant_id=a.tenant_id AND f.attempt=a.id AND f.command=i.command),'[]'::jsonb) AS frames FROM mdm_windows.attempts a JOIN mdm_windows.attempt_items i ON(i.tenant_id,i.attempt)=(a.tenant_id,a.id) WHERE a.tenant_id=$1::uuid AND a.operation=ANY($2) ORDER BY a.operation,a.ordinal,i.command,i.item_ordinal";
const WINDOWS_PLATFORMS: &str = "SELECT DISTINCT ON(operation) operation,platform FROM mdm_windows.attempts WHERE tenant_id=$1::uuid AND operation=ANY($2) AND phase='execute' ORDER BY operation,ordinal DESC";
const WINDOWS_ENDPOINTS: &str = "SELECT DISTINCT ON (a.operation) a.operation, a.protocol_epoch, m.response, a.credential, a.session, a.message FROM mdm_windows.attempts AS a INNER JOIN mdm_access.management_messages AS m ON (m.tenant_id, m.device, m.session_id, m.message_id) = (a.tenant_id, a.device, CAST(a.session AS text), a.message) AND m.protocol_epoch=a.protocol_epoch INNER JOIN mdm_access.management_sessions AS s ON (s.tenant_id, s.device, s.session_id) = (m.tenant_id, m.device, m.session_id) AND s.protocol_epoch = m.protocol_epoch WHERE a.tenant_id = CAST($1 AS uuid) AND a.operation = ANY($2) AND a.phase = 'observe' AND (a.protocol_epoch,a.session) <> (SELECT protocol_epoch,session FROM mdm_windows.attempts WHERE tenant_id = CAST($1 AS uuid) AND operation = a.operation AND phase = 'execute' ORDER BY ordinal DESC LIMIT 1) ORDER BY a.operation, a.ordinal DESC";

// The channel owns receipt precedence and post-dispatch collection correlation.
const INSTALLATIONS: &str = "WITH selected AS MATERIALIZED (SELECT x.operation, (SELECT q.channel_state FROM mdm_windows.collections AS q INNER JOIN mdm_windows.attempts AS a ON a.tenant_id = q.tenant_id AND a.operation = x.operation AND a.phase = 'execute' INNER JOIN mdm_windows.attempt_items AS i ON (i.tenant_id, i.attempt) = (a.tenant_id, a.id) WHERE q.tenant_id = CAST($1 AS uuid) AND q.id = x.snapshot AND q.device = x.device AND q.protocol_epoch=a.protocol_epoch AND a.device = x.device AND q.first_command > i.command ORDER BY q.first_command DESC LIMIT 1) AS channel_state, (SELECT i.status FROM mdm_windows.attempts AS a INNER JOIN mdm_windows.attempt_items AS i ON (i.tenant_id, i.attempt) = (a.tenant_id, a.id) WHERE a.tenant_id = CAST($1 AS uuid) AND a.operation = x.operation AND a.device = x.device AND (a.phase = 'execute' OR (a.phase = 'prepare' AND i.status >= 400)) AND i.receipt_accepted ORDER BY a.ordinal DESC, i.command DESC LIMIT 1) AS delivery_status FROM jsonb_to_recordset(CAST($2 AS jsonb)) AS x(operation uuid, device uuid, snapshot uuid)), budget AS (SELECT COALESCE(sum(pg_column_size(selected)), 0) <= 16777216 AS ok FROM selected) SELECT selected.*, budget.ok AS within_budget FROM budget LEFT JOIN selected ON budget.ok";

impl Results {
    /// Operations with durable execute delivery evidence; a terminal timeout is not a stop acknowledgement.
    pub async fn sent_on(
        &self,
        c: &mut PgConnection,
        tenant: rss_request_context::TenantId,
        ids: Vec<Uuid>,
    ) -> std::result::Result<std::collections::BTreeSet<Uuid>, Error> {
        if ids.len() > 1000 {
            return Err(Error::Malformed);
        }
        let ids:Vec<Uuid>=sqlx::query_scalar("SELECT DISTINCT operation FROM mdm_windows.attempts WHERE tenant_id=$1::uuid AND operation=ANY($2) AND phase='execute'").bind(tenant.to_string()).bind(ids).fetch_all(c).await.map_err(crate::database::db)?;
        Ok(ids.into_iter().collect())
    }
}

impl Results {
    pub async fn control_applicability_on(
        &self,
        c: &mut PgConnection,
        tenant: TenantId,
        checks: Vec<(
            usize,
            rss_mdm_agent_wire::DeviceId,
            rss_mdm_windows_mdm::native::Request,
        )>,
    ) -> Result<BTreeMap<usize, std::result::Result<(), rss_mdm_windows_mdm::native::Error>>> {
        if checks.len() > 1000 {
            return Err(Error::Malformed);
        }
        let registrations = checks.iter().map(|v| v.1.into_uuid()).collect::<Vec<_>>();
        let rows:Vec<(Uuid,String,i32)>=sqlx::query_as("SELECT c.device, c.os_version, c.edition FROM mdm_windows.capabilities c JOIN mdm_access.devices d ON(d.tenant_id,d.id,d.epoch)=(c.tenant_id,c.device,c.protocol_epoch) WHERE c.tenant_id = CAST($1 AS uuid) AND c.device = ANY($2)").bind(tenant.to_string()).bind(registrations).fetch_all(c).await.map_err(crate::database::db)?;
        let capabilities = rows
            .into_iter()
            .map(|(id, v, e)| (id, (v, e)))
            .collect::<BTreeMap<_, _>>();
        Ok(checks
            .into_iter()
            .map(|(id, device, request)| {
                let supported = match capabilities.get(device.as_uuid()) {
                    None => Err(rss_mdm_windows_mdm::native::Error::MissingEvidence),
                    Some((v, e)) => rss_mdm_windows_mdm::native::Context::from_capabilities(
                        v,
                        *e as u32,
                        rss_mdm_windows_mdm::native::Scope::Device,
                        rss_mdm_windows_mdm::native::Enrollment::Primary,
                    )
                    .and_then(|ctx| request.compile(ctx, 1).map(|_| ())),
                };
                (id, supported)
            })
            .collect())
    }
}
