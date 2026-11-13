//! Native applicability evidence is retained in the same immutable exchange attempts as its request.
//! These protocol prerequisite queries are not Inventory definitions or command success evidence.
use crate::{Error, database::db, device::DevicePrincipal, protocol_types::AppleCommand};
use plist::Value;
use rss_mdm_apple_mdm::{
    applicability::{Channel, Context},
    protocol,
};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub(crate) fn rights(mask: i32) -> Vec<&'static str> {
    [
        (1, "AllowInspection"),
        (2, "AllowInstallationRemoval"),
        (4, "AllowPasscodeRemovalAndLock"),
        (4, "DeviceLockAndRemovePasscode"),
        (8, "AllowDeviceErase"),
        (16, "AllowQueryDeviceInformation"),
        (32, "AllowQueryNetworkInformation"),
        (256, "AllowQueryApplications"),
        (256, "QueryInstalledApps"),
        (1024, "AllowQuerySecurity"),
        (2048, "AllowSettings"),
        (4096, "AllowAppInstallation"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (mask & bit == bit).then_some(name))
    .collect()
}

/// Only authenticated evidence from this exact device generation is usable.
pub(crate) async fn control_applicability(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    tenant: &str,
    requests: &[crate::protocol_types::AppleControlCheck],
) -> Result<std::collections::BTreeMap<usize, Result<(), rss_mdm_apple_mdm::native::Error>>, Error>
{
    use std::collections::BTreeMap;
    if requests.len() > 1000 {
        return Err(Error::Malformed);
    }
    let registrations = requests.iter().map(|r| r.device).collect::<Vec<_>>();
    let rows=sqlx::query("WITH targets AS (SELECT DISTINCT * FROM unnest(CAST($2 AS uuid[])) AS t (device)), selected AS (SELECT t.*, o.operation FROM targets AS t LEFT JOIN LATERAL (SELECT d.operation FROM mdm_apple.attempts AS d INNER JOIN mdm_apple.attempts AS s ON (s.tenant_id, s.operation, s.device) = (d.tenant_id, d.operation, d.device) WHERE d.tenant_id = CAST($1 AS uuid) AND d.device = t.device AND d.phase = 'resolve_device' AND s.phase = 'resolve_security' AND d.state = 'acknowledged' AND s.state = 'acknowledged' AND d.accepted AND s.accepted ORDER BY GREATEST(d.received_at, s.received_at) DESC, d.operation LIMIT 1) AS o ON TRUE), evidence AS MATERIALIZED (SELECT t.device, a.id, a.phase, a.response, d.access_rights FROM selected AS t INNER JOIN mdm_apple.devices AS d ON (d.tenant_id, d.device) = (CAST($1 AS uuid), t.device) AND d.state = 'active' INNER JOIN mdm_apple.attempts AS a ON (a.tenant_id, a.device, a.operation) = (CAST($1 AS uuid), t.device, t.operation) WHERE a.phase IN ('resolve_device', 'resolve_security') AND a.state = 'acknowledged' AND a.accepted), budget AS (SELECT CAST(COALESCE(sum(octet_length(response)), 0) AS bigint) AS bytes FROM evidence) SELECT evidence.*, budget.bytes FROM budget LEFT JOIN evidence ON budget.bytes <= 16777216")
        .bind(tenant).bind(registrations.iter().map(|id|id.into_uuid()).collect::<Vec<_>>()).fetch_all(c).await.map_err(db)?;
    let bytes: i64 = rows
        .first()
        .ok_or(Error::Malformed)?
        .try_get("bytes")
        .map_err(db)?;
    if bytes > 16 * 1024 * 1024 {
        return Err(Error::Unavailable(crate::Failure::Capacity));
    }
    struct Reports {
        device: Option<plist::Dictionary>,
        security: Option<plist::Dictionary>,
        rights: i32,
    }
    let mut reports: BTreeMap<rss_mdm_agent_wire::DeviceId, Reports> = BTreeMap::new();
    for row in rows {
        let Some(id) = row.try_get::<Option<Uuid>, _>("id").map_err(db)? else {
            continue;
        };
        let device = row
            .try_get::<uuid::Uuid, _>("device")
            .and_then(|id| {
                rss_mdm_agent_wire::DeviceId::try_from(id)
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))
            })
            .map_err(db)?;

        let sealed: Vec<u8> = row.try_get("response").map_err(db)?;
        let plain = crate::protection::open(
            protection,
            tenant,
            &device,
            id,
            crate::protection::Part::Response,
            &sealed,
        )?;
        let body = protocol::decode(plain.expose())?;
        let entry = reports.entry(device).or_insert(Reports {
            device: None,
            security: None,
            rights: row.try_get("access_rights").map_err(db)?,
        });
        match row.try_get::<String, _>("phase").map_err(db)?.as_str() {
            "resolve_device" => entry.device = Some(body),
            "resolve_security" => entry.security = Some(body),
            _ => return Err(Error::Malformed),
        }
    }
    let mut result = BTreeMap::new();
    for request in requests {
        let supported = if let Some(Reports {
            device: Some(device),
            security: Some(security),
            rights: mask,
        }) = reports.get(&request.device)
        {
            let facts = device
                .get("QueryResponses")
                .and_then(plist::Value::as_dictionary)
                .ok_or(Error::Malformed)?;
            if facts.contains_key("OSVersion") {
                let context = Context::from_reports(device, Some(security), Channel::Device)?;
                request
                    .action
                    .applicability(&context, &request.command, &rights(*mask))
            } else {
                Err(rss_mdm_apple_mdm::native::Error::Applicability(
                    rss_mdm_apple_mdm::applicability::Rejection::MissingEvidence(
                        rss_mdm_apple_mdm::applicability::Condition::Version,
                    ),
                ))
            }
        } else {
            Err(rss_mdm_apple_mdm::native::Error::Applicability(
                rss_mdm_apple_mdm::applicability::Rejection::MissingEvidence(
                    rss_mdm_apple_mdm::applicability::Condition::Version,
                ),
            ))
        };
        result.insert(request.id, supported);
    }
    Ok(result)
}
pub(crate) async fn context(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    command: &AppleCommand,
) -> Result<Option<Context>, Error> {
    let rows=sqlx::query("SELECT id, phase, response FROM mdm_apple.attempts WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND operation = $3 AND phase IN ('resolve_device', 'resolve_security') AND state = 'acknowledged' AND accepted ORDER BY phase").bind(p.tenant().to_string()).bind(p.device().into_uuid()).bind(command.operation).fetch_all(c).await.map_err(db)?;
    let mut device = None;
    let mut security = None;
    for row in rows {
        let sealed: Vec<u8> = row.try_get("response").map_err(db)?;
        let plain = crate::protection::open(
            protection,
            &p.tenant().to_string(),
            p.device(),
            row.try_get("id").map_err(db)?,
            crate::protection::Part::Response,
            &sealed,
        )?;
        let body = protocol::decode(plain.expose())?;
        match row.try_get::<String, _>("phase").map_err(db)?.as_str() {
            "resolve_device" => device = Some(body),
            "resolve_security" => security = Some(body),
            _ => return Err(Error::Malformed),
        }
    }
    let (Some(device), Some(security)) = (device, security) else {
        return Ok(None);
    };
    Ok(Some(Context::from_reports(
        &device,
        Some(&security),
        if command.target.user_key().is_empty() {
            Channel::Device
        } else {
            Channel::User
        },
    )?))
}

pub(crate) async fn resolve(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    command: &AppleCommand,
) -> Result<crate::protocol_types::AppleDispatch, Error> {
    let tenant = p.tenant().to_string();
    let rights:i32=sqlx::query_scalar("SELECT access_rights FROM mdm_apple.devices WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND state = 'active'").bind(&tenant).bind(p.device().into_uuid()).fetch_one(&mut *c).await.map_err(db)?;
    if rights & 1040 != 1040 {
        return Ok(crate::protocol_types::AppleDispatch::Rejected(
            rss_mdm_apple_mdm::native::Error::AccessRight,
        ));
    }
    for (phase, payload) in [
        (
            "resolve_device",
            protocol::dictionary([
                ("RequestType", "DeviceInformation".into()),
                (
                    "Queries",
                    Value::Array(vec![
                        "OSVersion".into(),
                        "IsSupervised".into(),
                        "IsAppleSilicon".into(),
                    ]),
                ),
            ]),
        ),
        (
            "resolve_security",
            protocol::dictionary([("RequestType", "SecurityInfo".into())]),
        ),
    ] {
        let row=sqlx::query("SELECT id, state, request, accepted, next_attempt <= clock_timestamp() AS ready FROM mdm_apple.attempts WHERE tenant_id = CAST($1 AS uuid) AND operation = $2 AND phase = $3 AND device = $4 FOR UPDATE").bind(&tenant).bind(command.operation).bind(phase).bind(p.device().into_uuid()).fetch_optional(&mut *c).await.map_err(db)?;
        if let Some(row) = row {
            let state: String = row.try_get("state").map_err(db)?;
            if state == "acknowledged" {
                if !row.try_get::<bool, _>("accepted").map_err(db)? {
                    return Ok(crate::protocol_types::AppleDispatch::Rejected(
                        rss_mdm_apple_mdm::native::Error::Field,
                    ));
                }
                continue;
            }
            if !matches!(state.as_str(), "sent" | "not_now")
                || !row.try_get::<bool, _>("ready").map_err(db)?
            {
                return Ok(crate::protocol_types::AppleDispatch::Waiting);
            }
            let id: Uuid = row.try_get("id").map_err(db)?;
            sqlx::query("UPDATE mdm_apple.attempts SET state='sent',next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(id).execute(&mut *c).await.map_err(db)?;
            let sealed: Vec<u8> = row.try_get("request").map_err(db)?;
            let plain = crate::protection::open(
                protection,
                &tenant,
                p.device(),
                id,
                crate::protection::Part::Request,
                &sealed,
            )?;
            return Ok(crate::protocol_types::AppleDispatch::Ready(
                plain.expose().to_vec(),
            ));
        }
        // The only unversioned bootstrap commands are these fixed read-only prerequisites.
        // Their responses determine the real context before any authored native input is compiled.
        let id = Uuid::new_v4();
        let bytes = protocol::command(id, payload)?;
        let sealed = crate::protection::seal(
            protection,
            &tenant,
            p.device(),
            id,
            crate::protection::Part::Request,
            &bytes,
        )?;
        sqlx::query("INSERT INTO mdm_apple.attempts (tenant_id, id, device, operation, phase, request, state, deadline, next_attempt) VALUES (CAST($1 AS uuid), $2, $3, $4, $5, $6, 'sent', to_timestamp($7), clock_timestamp() + CAST('30 seconds' AS interval))").bind(&tenant).bind(id).bind(p.device().into_uuid()).bind(command.operation).bind(phase).bind(sealed).bind(command.deadline as f64).execute(&mut *c).await.map_err(db)?;
        return Ok(crate::protocol_types::AppleDispatch::Ready(bytes));
    }
    Ok(crate::protocol_types::AppleDispatch::Waiting)
}
