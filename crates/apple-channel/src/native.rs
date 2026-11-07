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

/// Only authenticated evidence from this exact registration generation is usable.
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
    let registrations = requests.iter().map(|r| r.registration).collect::<Vec<_>>();
    let generations = requests.iter().map(|r| r.generation).collect::<Vec<_>>();
    let rows=sqlx::query("WITH targets AS (SELECT DISTINCT * FROM unnest($2::uuid[],$3::bigint[]) AS t(registration,generation)), selected AS (SELECT t.*,o.operation FROM targets t LEFT JOIN LATERAL (SELECT d.operation FROM mdm_apple.attempts d JOIN mdm_apple.attempts s ON(s.tenant_id,s.operation,s.registration,s.generation)=(d.tenant_id,d.operation,d.registration,d.generation) WHERE d.tenant_id=$1::uuid AND d.registration=t.registration AND d.generation=t.generation AND d.phase='resolve_device' AND s.phase='resolve_security' AND d.state='acknowledged' AND s.state='acknowledged' AND d.accepted AND s.accepted ORDER BY greatest(d.received_at,s.received_at) DESC,d.operation LIMIT 1) o ON true), evidence AS MATERIALIZED (SELECT t.registration,t.generation,a.id,a.phase,a.response,d.access_rights FROM selected t JOIN mdm_apple.devices d ON(d.tenant_id,d.registration)=($1::uuid,t.registration) AND d.state='active' JOIN mdm_apple.attempts a ON(a.tenant_id,a.registration,a.generation,a.operation)=($1::uuid,t.registration,t.generation,t.operation) WHERE a.phase IN('resolve_device','resolve_security') AND a.state='acknowledged' AND a.accepted), budget AS(SELECT coalesce(sum(octet_length(response)),0)::bigint AS bytes FROM evidence) SELECT evidence.*,budget.bytes FROM budget LEFT JOIN evidence ON budget.bytes<=16777216")
        .bind(tenant).bind(registrations).bind(generations).fetch_all(c).await.map_err(db)?;
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
    let mut reports: BTreeMap<(Uuid, i64), Reports> = BTreeMap::new();
    for row in rows {
        let Some(id) = row.try_get::<Option<Uuid>, _>("id").map_err(db)? else {
            continue;
        };
        let registration = row.try_get("registration").map_err(db)?;
        let generation = row.try_get("generation").map_err(db)?;
        let sealed: Vec<u8> = row.try_get("response").map_err(db)?;
        let plain = crate::protection::open(
            protection,
            tenant,
            registration,
            generation,
            id,
            crate::protection::Part::Response,
            &sealed,
        )?;
        let body = protocol::decode(plain.expose())?;
        let entry = reports
            .entry((registration, generation))
            .or_insert(Reports {
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
        }) = reports.get(&(request.registration, request.generation))
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
    let rows=sqlx::query("SELECT id,phase,response FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND operation=$4 AND phase IN('resolve_device','resolve_security') AND state='acknowledged' AND accepted ORDER BY phase").bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(command.operation).fetch_all(c).await.map_err(db)?;
    let mut device = None;
    let mut security = None;
    for row in rows {
        let sealed: Vec<u8> = row.try_get("response").map_err(db)?;
        let plain = crate::protection::open(
            protection,
            &p.tenant().to_string(),
            p.registration(),
            p.generation(),
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
    let rights:i32=sqlx::query_scalar("SELECT access_rights FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'").bind(&tenant).bind(p.registration()).fetch_one(&mut *c).await.map_err(db)?;
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
        let row=sqlx::query("SELECT id,state,request,accepted,next_attempt<=clock_timestamp() AS ready FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase=$3 AND registration=$4 AND generation=$5 FOR UPDATE").bind(&tenant).bind(command.operation).bind(phase).bind(p.registration()).bind(p.generation()).fetch_optional(&mut *c).await.map_err(db)?;
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
                p.registration(),
                p.generation(),
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
            p.registration(),
            p.generation(),
            id,
            crate::protection::Part::Request,
            &bytes,
        )?;
        sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,operation,phase,request,state,deadline,next_attempt) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,'sent',to_timestamp($8),clock_timestamp()+interval '30 seconds')").bind(&tenant).bind(id).bind(p.registration()).bind(p.generation()).bind(command.operation).bind(phase).bind(sealed).bind(command.deadline as f64).execute(&mut *c).await.map_err(db)?;
        return Ok(crate::protocol_types::AppleDispatch::Ready(bytes));
    }
    Ok(crate::protocol_types::AppleDispatch::Waiting)
}
