//! Native applicability evidence is retained in the same immutable exchange attempts as its request.
//! These protocol prerequisite queries are not Inventory definitions or command success evidence.
use crate::{Error, database::db, device::DevicePrincipal, execution::channels::AppleCommand};
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
) -> Result<crate::execution::channels::AppleDispatch, Error> {
    let tenant = p.tenant().to_string();
    let rights:i32=sqlx::query_scalar("SELECT access_rights FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'").bind(&tenant).bind(p.registration()).fetch_one(&mut *c).await.map_err(db)?;
    if rights & 1040 != 1040 {
        return Ok(crate::execution::channels::AppleDispatch::Rejected(
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
                    return Ok(crate::execution::channels::AppleDispatch::Rejected(
                        rss_mdm_apple_mdm::native::Error::Field,
                    ));
                }
                continue;
            }
            if !matches!(state.as_str(), "sent" | "not_now")
                || !row.try_get::<bool, _>("ready").map_err(db)?
            {
                return Ok(crate::execution::channels::AppleDispatch::Waiting);
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
            return Ok(crate::execution::channels::AppleDispatch::Ready(
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
        return Ok(crate::execution::channels::AppleDispatch::Ready(bytes));
    }
    Ok(crate::execution::channels::AppleDispatch::Waiting)
}
