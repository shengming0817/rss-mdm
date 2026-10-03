//! Profile dispatch history and native collision guards; Policy remains the desired-state owner.
//! ref: apple/device-management CommonPayloadKeys.yaml, TopLevel.yaml and profile.list.yaml.
use crate::{
    Error, Failure,
    database::db,
    device::DevicePrincipal,
    execution::channels::{AppleCommand, AppleRegistration},
};
use rss_mdm_apple_mdm::native::{profiles::ProfileObject, request::Request};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use sqlx::{PgConnection, Row, postgres::PgRow};
use uuid::Uuid;

fn aad(row: &PgRow) -> Result<DerivedAad, Error> {
    let tenant: Uuid = row.try_get("tenant_id").map_err(db)?;
    let owner = serde_json::to_string(&(
        row.try_get::<Uuid, _>("operation").map_err(db)?,
        row.try_get::<String, _>("device").map_err(db)?,
        row.try_get::<String, _>("user_key").map_err(db)?,
        row.try_get::<Uuid, _>("registration").map_err(db)?,
        row.try_get::<i64, _>("generation").map_err(db)?,
        row.try_get::<String, _>("identifier").map_err(db)?,
        row.try_get::<Uuid, _>("profile").map_err(db)?,
        row.try_get::<String, _>("version").map_err(db)?,
        row.try_get::<bool, _>("present").map_err(db)?,
    ))
    .map_err(|_| Error::Malformed)?;
    ProtectionContext::new(
        rss_request_context::TenantId::parse(&tenant.to_string()).map_err(|_| Error::Malformed)?,
        &owner,
        "apple.profile.manifest",
        1,
    )
    .map(|c| c.derive())
    .map_err(|_| Error::Unavailable(Failure::AppleStorage))
}
fn open(key: &Protector, row: &PgRow) -> Result<Vec<ProfileObject>, Error> {
    let cipher: Vec<u8> = row.try_get("manifest").map_err(db)?;
    let plain = key
        .open_bytes(&cipher, &aad(row)?)
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    serde_json::from_slice(plain.expose()).map_err(|_| Error::Unavailable(Failure::AppleStorage))
}
/// The caller holds the existing device/registration lock. Scan bounded pages of active evidence.
async fn collides(
    c: &mut PgConnection,
    key: &Protector,
    target: &AppleRegistration,
    user: &str,
    root: &str,
    objects: &[ProfileObject],
    types: bool,
) -> Result<bool, Error> {
    let mut after = Uuid::nil();
    loop {
        let rows=sqlx::query("SELECT * FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND device=$2 AND user_key=$3 AND registration=$4 AND generation=$5 AND retired_at IS NULL AND identifier<>$6 AND manifest IS NOT NULL AND operation>$7 ORDER BY operation LIMIT 32")
            .bind(&target.tenant).bind(&target.device).bind(user).bind(target.registration).bind(target.generation).bind(root).bind(after).fetch_all(&mut *c).await.map_err(db)?;
        if rows.is_empty() {
            return Ok(false);
        }
        for row in rows {
            after = row.try_get("operation").map_err(db)?;
            if rss_mdm_apple_mdm::native::profiles::collides(objects, &open(key, &row)?, types) {
                return Ok(true);
            }
        }
    }
}
pub(crate) async fn reserve(
    c: &mut PgConnection,
    key: &Protector,
    target: &AppleRegistration,
    command: &AppleCommand,
) -> Result<(), Error> {
    let (identifier, uuid, present, objects) = match &command.request {
        Request::InstallProfile { profile } => {
            let mut objects = vec![ProfileObject {
                payload_type: "Configuration".into(),
                identifier: profile.identifier.clone(),
                uuid: profile.uuid,
                multiple: true,
            }];
            objects.extend(profile.payloads.iter().map(|p| ProfileObject {
                payload_type: String::new(),
                identifier: p.identifier.clone(),
                uuid: p.uuid,
                multiple: true,
            }));
            (profile.identifier.as_str(), profile.uuid, true, objects)
        }
        Request::RemoveProfile { identifier, uuid } => (identifier.as_str(), *uuid, false, vec![]),
        _ => return Err(Error::Malformed),
    };
    let user = command.target.user_key();
    let enrollment:Uuid=sqlx::query_scalar("SELECT request_id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 AND generation=$3 AND state='active'").bind(&target.tenant).bind(target.registration).bind(target.generation).fetch_one(&mut *c).await.map_err(db)?;
    if identifier == format!("com.rss-mdm.enrollment.{enrollment}") {
        return Err(Error::Forbidden);
    }

    let rows=sqlx::query("SELECT d.terminal_at IS NOT NULL AS terminal,p.dispatched_at IS NOT NULL AS dispatched,p.observed_at IS NOT NULL AS observed,p.present,p.profile FROM mdm_apple.profiles p JOIN rss_device_command.commands d ON d.tenant_id=p.tenant_id AND d.command_id=p.operation::text WHERE p.tenant_id=$1::uuid AND p.device=$2 AND p.user_key=$3 AND p.registration=$4 AND p.generation=$5 AND p.identifier=$6 AND p.retired_at IS NULL")
        .bind(&target.tenant).bind(&target.device).bind(user).bind(target.registration).bind(target.generation).bind(identifier).fetch_all(&mut *c).await.map_err(db)?;
    let history = rows
        .iter()
        .map(|row| {
            Ok(rss_mdm_apple_mdm::native::profiles::History {
                terminal: row.try_get("terminal").map_err(db)?,
                dispatched: row.try_get("dispatched").map_err(db)?,
                observed: row.try_get("observed").map_err(db)?,
                present: row.try_get("present").map_err(db)?,
                uuid: row.try_get("profile").map_err(db)?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    if !rss_mdm_apple_mdm::native::profiles::can_reserve(&history, uuid, present)
        || collides(c, key, target, user, identifier, &objects, false).await?
    {
        return Err(Error::Conflict);
    }
    sqlx::query("UPDATE mdm_apple.profiles SET retired_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1::uuid AND device=$2 AND user_key=$3 AND registration=$4 AND generation=$5 AND identifier=$6 AND retired_at IS NULL AND dispatched_at IS NULL")
        .bind(&target.tenant).bind(&target.device).bind(user).bind(target.registration).bind(target.generation).bind(identifier).execute(&mut *c).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_apple.profiles(tenant_id,operation,device,user_key,registration,generation,identifier,profile,version,present) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(&target.tenant).bind(command.operation).bind(&target.device).bind(user).bind(target.registration).bind(target.generation).bind(identifier).bind(uuid).bind(&command.input_version).bind(present).execute(c).await.map_err(db)?;
    Ok(())
}
pub(crate) async fn dispatch(
    c: &mut PgConnection,
    key: &Protector,
    p: &DevicePrincipal,
    operation: Uuid,
    objects: Option<&[ProfileObject]>,
) -> Result<bool, Error> {
    let row=sqlx::query("SELECT * FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND operation=$2 AND registration=$3 AND generation=$4 AND retired_at IS NULL FOR UPDATE")
        .bind(p.tenant().to_string()).bind(operation).bind(p.registration()).bind(p.generation()).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Conflict)?;
    let target = AppleRegistration {
        tenant: p.tenant().to_string(),
        device: p.device().into(),
        registration: p.registration(),
        generation: p.generation(),
    };
    let user: String = row.try_get("user_key").map_err(db)?;
    let root: String = row.try_get("identifier").map_err(db)?;
    if let Some(objects) = objects {
        if collides(c, key, &target, &user, &root, objects, true).await? {
            return Ok(false);
        }
    }
    if row
        .try_get::<Option<i64>, _>("dispatched_at")
        .map_err(db)?
        .is_some()
    {
        return Err(Error::Conflict);
    }
    let manifest = objects
        .map(|objects| {
            let plain =
                zeroize::Zeroizing::new(serde_json::to_vec(objects).map_err(|_| Error::Malformed)?);
            key.seal_bytes(&plain, &aad(&row)?)
                .map_err(|_| Error::Unavailable(Failure::AppleStorage))
        })
        .transpose()?;
    sqlx::query("UPDATE mdm_apple.profiles SET manifest=$3,dispatched_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1::uuid AND operation=$2")
        .bind(&target.tenant).bind(operation).bind(manifest).execute(c).await.map_err(db)?;
    Ok(true)
}
pub(crate) async fn confirm(
    c: &mut PgConnection,
    target: &AppleRegistration,
    operation: Uuid,
) -> Result<(), Error> {
    let row=sqlx::query("SELECT identifier,user_key FROM mdm_apple.profiles p WHERE p.tenant_id=$1::uuid AND p.operation=$2 AND p.device=$3 AND p.registration=$4 AND p.generation=$5 AND p.retired_at IS NULL AND p.dispatched_at IS NOT NULL AND EXISTS(SELECT 1 FROM mdm_apple.attempts a WHERE a.tenant_id=p.tenant_id AND a.operation=p.operation AND a.phase='observe' AND a.state='acknowledged' AND a.accepted) FOR UPDATE")
        .bind(&target.tenant).bind(operation).bind(&target.device).bind(target.registration).bind(target.generation).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Conflict)?;
    let identifier: String = row.try_get("identifier").map_err(db)?;
    let user: String = row.try_get("user_key").map_err(db)?;
    sqlx::query("UPDATE mdm_apple.profiles SET retired_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1::uuid AND device=$2 AND user_key=$3 AND registration=$4 AND generation=$5 AND identifier=$6 AND operation<>$7 AND retired_at IS NULL")
        .bind(&target.tenant).bind(&target.device).bind(user).bind(target.registration).bind(target.generation).bind(identifier).bind(operation).execute(&mut *c).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple.profiles SET observed_at=coalesce(observed_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1::uuid AND operation=$2")
        .bind(&target.tenant).bind(operation).execute(c).await.map_err(db)?;
    Ok(())
}
