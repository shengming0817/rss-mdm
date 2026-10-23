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
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row, postgres::PgRow};
use uuid::Uuid;

pub(crate) fn aad(row: &PgRow) -> Result<DerivedAad, Error> {
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
    if row
        .try_get::<Option<Vec<u8>>, _>("manifest_cipher_digest")
        .map_err(db)?
        .as_deref()
        != Some(Sha256::digest(&cipher).as_slice())
    {
        return Err(Error::Unavailable(Failure::AppleStorage));
    }
    let plain = key
        .open_bytes(&cipher, &aad(row)?)
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    if row
        .try_get::<Option<Vec<u8>>, _>("manifest_digest")
        .map_err(db)?
        .as_deref()
        != Some(Sha256::digest(plain.expose()).as_slice())
    {
        return Err(Error::Unavailable(Failure::AppleStorage));
    }
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
    let management_removal = identifier == format!("com.rss-mdm.enrollment.{enrollment}");
    if management_removal {
        if present
            || uuid != enrollment
            || !matches!(command.target, crate::execution::NativeTarget::Device)
        {
            return Err(Error::Forbidden);
        }
        let allowed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_devices.retirement_channels t JOIN mdm_access.devices d ON(d.tenant_id,d.id,d.retirement)=(t.tenant_id,t.device,t.operation) WHERE t.tenant_id=$1::uuid AND t.registration=$2 AND t.generation=$3 AND t.execution=$4 AND t.stage='unenroll' AND ('retirement:'||t.operation::text)=$5)")
            .bind(&target.tenant).bind(target.registration).bind(target.generation).bind(command.operation).bind(&command.owner).fetch_one(&mut *c).await.map_err(db)?;
        if !allowed {
            return Err(Error::Forbidden);
        }
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
    if (!management_removal
        && !rss_mdm_apple_mdm::native::profiles::can_reserve(&history, uuid, present))
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
    if crate::ddm::profile_conflict(c, key, p, &user, &root, objects).await? {
        return Ok(false);
    }
    if let Some(objects) = objects
        && collides(c, key, &target, &user, &root, objects, true).await?
    {
        return Ok(false);
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
    sqlx::query("UPDATE mdm_apple.profiles SET manifest=$3,manifest_cipher_digest=sha256($3),manifest_digest=$4,dispatched_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1::uuid AND operation=$2")
        .bind(&target.tenant).bind(operation).bind(manifest).bind(objects.map(|v| serde_json::to_vec(v).map(|plain| Sha256::digest(plain).to_vec())).transpose().map_err(|_|Error::Malformed)?).execute(c).await.map_err(db)?;
    Ok(true)
}
/// Current qualification is bound to exact latest evidence, independently of observation history.
pub(crate) async fn assessment(
    c: &mut PgConnection,
    tenant: &str,
    operation: Uuid,
) -> Result<rss_mdm_apple_mdm::native::profiles::Verification, Error> {
    use rss_mdm_apple_mdm::native::profiles::Verification as V;
    let state: Option<String> = sqlx::query_scalar(
        "SELECT verification FROM mdm_apple.profile_qualifications WHERE tenant_id=$1::uuid AND operation=$2",
    )
    .bind(tenant).bind(operation).fetch_optional(c).await.map_err(db)?;
    match state.as_deref() {
        None | Some("unknown") => Ok(V::Unknown),
        Some("matched") => Ok(V::Matched),
        Some("mismatched") => Ok(V::Mismatched),
        Some("failed") => Ok(V::Failed),
        _ => Err(Error::Unavailable(Failure::AppleStorage)),
    }
}

/// Called after native settlement, before any rejection/NotNow/phase early return.
/// Maintenance that rewraps profile evidence calls this same owner in its original transaction.
pub(crate) async fn qualify_latest(
    c: &mut PgConnection,
    key: &Protector,
    tenant: &str,
    operation: Uuid,
) -> Result<(), Error> {
    use rss_mdm_apple_mdm::native::profiles::Verification as V;
    let decision = evaluate_latest(c, key, tenant, operation).await?;
    let state = match decision {
        V::Unknown => "unknown",
        V::Matched => "matched",
        V::Mismatched => "mismatched",
        V::Failed => "failed",
    };
    sqlx::query("UPDATE mdm_apple.profiles p SET verification=$3,verification_evidence=q.current_evidence FROM mdm_apple.profile_qualifications q WHERE (p.tenant_id,p.operation)=(q.tenant_id,q.operation) AND p.tenant_id=$1::uuid AND p.operation=$2")
        .bind(tenant).bind(operation).bind(state).execute(c).await.map_err(db)?;
    Ok(())
}

/// Sole interpretation of protected native profile evidence, used only by its writer.
async fn evaluate_latest(
    c: &mut PgConnection,
    key: &Protector,
    tenant: &str,
    operation: Uuid,
) -> Result<rss_mdm_apple_mdm::native::profiles::Verification, Error> {
    use rss_mdm_apple_mdm::native::profiles::{Verification as V, verification};
    let Some(row) = sqlx::query("SELECT * FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND operation=$2 AND dispatched_at IS NOT NULL")
        .bind(tenant).bind(operation).fetch_optional(&mut *c).await.map_err(db)? else { return Ok(V::Unknown); };
    let registration: Uuid = row.try_get("registration").map_err(db)?;
    let generation: i64 = row.try_get("generation").map_err(db)?;
    let user: String = row.try_get("user_key").map_err(db)?;
    let identifier: String = row.try_get("identifier").map_err(db)?;
    let uuid: Uuid = row.try_get("profile").map_err(db)?;
    let present: bool = row.try_get("present").map_err(db)?;
    let Some(observe) = sqlx::query("SELECT id,state,accepted,response FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND registration=$3 AND generation=$4 AND user_key=$5 AND phase='observe' ORDER BY ordinal DESC LIMIT 1")
        .bind(tenant).bind(operation).bind(registration).bind(generation).bind(&user).fetch_optional(&mut *c).await.map_err(db)? else { return Ok(V::Unknown); };
    if !observe.try_get::<bool, _>("accepted").map_err(db)?
        || observe.try_get::<String, _>("state").map_err(db)? != "acknowledged"
    {
        return Ok(V::Unknown);
    }
    let sealed: Vec<u8> = observe.try_get("response").map_err(db)?;
    let plain = crate::protection::open(
        key,
        tenant,
        registration,
        generation,
        observe.try_get("id").map_err(db)?,
        crate::protection::Part::Response,
        &sealed,
    )?;
    let report = crate::protocol::decode(plain.expose())?;
    let failed = sqlx::query_scalar::<_,bool>("SELECT accepted AND state='error' FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND registration=$3 AND generation=$4 AND user_key=$5 AND phase='execute' ORDER BY ordinal DESC LIMIT 1")
        .bind(tenant).bind(operation).bind(registration).bind(generation).bind(&user).fetch_optional(&mut *c).await.map_err(db)?.unwrap_or(false);
    let old = if failed && !present {
        sqlx::query("SELECT * FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND device=$2 AND user_key=$3 AND registration=$4 AND generation=$5 AND identifier=$6 AND profile=$7 AND operation<>$8 AND retired_at IS NULL AND present AND observed_at IS NOT NULL AND dispatched_at IS NOT NULL ORDER BY operation LIMIT 2")
            .bind(tenant).bind(row.try_get::<String,_>("device").map_err(db)?).bind(&user).bind(registration).bind(generation).bind(&identifier).bind(uuid).bind(operation).fetch_all(&mut *c).await.map_err(db)?
    } else {
        Vec::new()
    };
    let previous = if old.len() == 1 {
        Some(open(key, &old[0])?)
    } else {
        None
    };
    let manifest = if present {
        open(key, &row)?
    } else {
        Vec::new()
    };
    Ok(verification(
        &report,
        &identifier,
        uuid,
        present,
        &manifest,
        failed,
        previous.as_deref(),
    ))
}
pub(crate) async fn confirm(
    c: &mut PgConnection,
    key: &Protector,
    target: &AppleRegistration,
    operation: Uuid,
) -> Result<rss_mdm_apple_mdm::native::profiles::Verification, Error> {
    use rss_mdm_apple_mdm::native::profiles::Verification as V;
    let row = sqlx::query("SELECT identifier,user_key FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND operation=$2 AND device=$3 AND registration=$4 AND generation=$5 AND retired_at IS NULL AND dispatched_at IS NOT NULL FOR UPDATE")
        .bind(&target.tenant).bind(operation).bind(&target.device).bind(target.registration).bind(target.generation).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Conflict)?;
    let decision = assessment(c, &target.tenant, operation).await?;
    match decision {
        V::Matched => {
            sqlx::query("UPDATE mdm_apple.profiles SET retired_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1::uuid AND device=$2 AND user_key=$3 AND registration=$4 AND generation=$5 AND identifier=$6 AND operation<>$7 AND retired_at IS NULL")
                .bind(&target.tenant).bind(&target.device).bind(row.try_get::<String,_>("user_key").map_err(db)?).bind(target.registration).bind(target.generation).bind(row.try_get::<String,_>("identifier").map_err(db)?).bind(operation).execute(&mut *c).await.map_err(db)?;
        }
        V::Failed => {
            sqlx::query("UPDATE mdm_apple.profiles SET retired_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1::uuid AND operation=$2")
                .bind(&target.tenant).bind(operation).execute(&mut *c).await.map_err(db)?;
        }
        V::Unknown | V::Mismatched => return Ok(decision),
    }
    sqlx::query("UPDATE mdm_apple.profiles SET observed_at=coalesce(observed_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1::uuid AND operation=$2")
        .bind(&target.tenant).bind(operation).execute(&mut *c).await.map_err(db)?;
    // Retiring previous manifests changes removal evidence; capture the settled owner state.
    qualify_latest(c, key, &target.tenant, operation).await?;
    Ok(decision)
}

/// DDM may adopt only the complete ordered structure of an observed classic MDM profile.
pub(crate) async fn ddm_admission(
    c: &mut PgConnection,
    key: &Protector,
    p: &DevicePrincipal,
    user: &str,
    profiles: &[rss_mdm_apple_mdm::native::ddm::LegacyProfile],
) -> Result<bool, Error> {
    let target = AppleRegistration {
        tenant: p.tenant().to_string(),
        device: p.device().into(),
        registration: p.registration(),
        generation: p.generation(),
    };
    for profile in profiles {
        let root = profile.objects.first().ok_or(Error::Malformed)?;
        let rows=sqlx::query("SELECT * FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key=$4 AND identifier=$5 AND retired_at IS NULL")
            .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(user).bind(&root.identifier).fetch_all(&mut *c).await.map_err(db)?;
        for row in rows {
            if !row.try_get::<bool, _>("present").map_err(db)?
                || row
                    .try_get::<Option<i64>, _>("observed_at")
                    .map_err(db)?
                    .is_none()
                || row
                    .try_get::<Option<Vec<u8>>, _>("manifest")
                    .map_err(db)?
                    .is_none()
                || !rss_mdm_apple_mdm::native::profiles::same_structure(
                    &profile.objects,
                    &open(key, &row)?,
                )
            {
                return Ok(false);
            }
            let old_operation: Uuid = row.try_get("operation").map_err(db)?;
            let evidence=sqlx::query("SELECT id,request,response FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND registration=$3 AND generation=$4 AND user_key=$5 AND phase='observe' AND accepted AND state='acknowledged' AND ordinal=(SELECT max(a.ordinal) FROM mdm_apple.attempts a WHERE a.tenant_id=$1::uuid AND a.operation=$2 AND a.phase='observe')")
                .bind(p.tenant().to_string()).bind(old_operation).bind(p.registration()).bind(p.generation()).bind(user).fetch_optional(&mut *c).await.map_err(db)?;
            let Some(evidence) = evidence else {
                return Ok(false);
            };
            // macOS does not return IsManaged. A correlated ManagedOnly query proves MDM ownership.
            let sealed: Vec<u8> = evidence.try_get("request").map_err(db)?;
            let plain = crate::protection::open(
                key,
                &p.tenant().to_string(),
                p.registration(),
                p.generation(),
                evidence.try_get("id").map_err(db)?,
                crate::protection::Part::Request,
                &sealed,
            )?;
            let request = crate::protocol::decode(plain.expose())?;
            let Some(command) = request.get("Command").and_then(plist::Value::as_dictionary) else {
                return Ok(false);
            };
            if command.get("RequestType").and_then(plist::Value::as_string) != Some("ProfileList")
                || command
                    .get("ManagedOnly")
                    .and_then(plist::Value::as_boolean)
                    != Some(true)
            {
                return Ok(false);
            }
            let sealed: Vec<u8> = evidence.try_get("response").map_err(db)?;
            let plain = crate::protection::open(
                key,
                &p.tenant().to_string(),
                p.registration(),
                p.generation(),
                evidence.try_get("id").map_err(db)?,
                crate::protection::Part::Response,
                &sealed,
            )?;
            let body = crate::protocol::decode(plain.expose())?;
            if !matches!(
                rss_mdm_apple_mdm::native::profiles::observed_structure(&body, &profile.objects),
                Ok(true)
            ) {
                return Ok(false);
            }
        }
        if collides(
            c,
            key,
            &target,
            user,
            &root.identifier,
            &profile.objects,
            true,
        )
        .await?
        {
            return Ok(false);
        }
    }
    Ok(true)
}
