//! Borrowed product transaction operations. The caller retains audit, commit and rollback ownership.
use crate::*;
use rss_mdm_inventory::Channel;
use sqlx::{PgConnection, Row};
use subtle::ConstantTimeEq;
use uuid::Uuid;

macro_rules! select_material { ($suffix:literal) => { concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM mdm_recovery.entries e JOIN mdm_recovery.versions v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id)", $suffix) }; }
pub(crate) use select_material;

/// Registration lock precedes material locks everywhere, including disclosure and retirement.
pub async fn active_in(c: &mut PgConnection, tenant: Uuid, binding: &Binding) -> Result<(), Error> {
    binding.validate()?;
    let channel = match binding.subject {
        Subject::Bitlocker { .. } | Subject::LocalAdministrator { .. } => Channel::Agent,
        _ => Channel::Mdm,
    };
    let tenant = tenant.to_string();
    rss_mdm_registration_service::device::store::lock_channel(c, &tenant, &binding.device, channel)
        .await
        .map_err(|_| Error::Storage)?;
    let rows = rss_mdm_registration_service::device::read::active_channel_in(
        c,
        tenant,
        vec![binding.device.clone()],
        channel,
        rss_mdm_registration_service::Purpose::Primary,
    )
    .await?;
    if rows.iter().any(|(device, id, generation)| {
        device == &binding.device
            && *id == binding.registration
            && *generation == binding.generation
    }) {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}

/// Reserve one immutable version under the existing execution operation's idempotency boundary.
pub async fn reserve_in(
    c: &mut PgConnection,
    tenant: Uuid,
    binding: &Binding,
    operation: Uuid,
    expected_revision: i64,
) -> Result<Coordinates, Error> {
    if operation.is_nil() || expected_revision < 0 {
        return Err(Error::Malformed);
    }
    active_in(c, tenant, binding).await?;
    let subject = serde_json::to_value(&binding.subject).map_err(|_| Error::Malformed)?;
    sqlx::query("INSERT INTO mdm_recovery.entries(tenant_id,id,device,registration,generation,subject) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,device,registration,generation,subject) DO NOTHING")
        .bind(tenant).bind(Uuid::new_v4()).bind(&binding.device).bind(binding.registration).bind(binding.generation).bind(&subject).execute(&mut *c).await?;
    let row = sqlx::query("SELECT id,revision,retired FROM mdm_recovery.entries WHERE tenant_id=$1 AND device=$2 AND registration=$3 AND generation=$4 AND subject=$5 FOR UPDATE")
        .bind(tenant).bind(&binding.device).bind(binding.registration).bind(binding.generation).bind(&subject).fetch_one(&mut *c).await?;
    let id: Uuid = row.try_get("id")?;
    if row.try_get::<bool, _>("retired")? {
        return Err(Error::Conflict);
    }
    if let Some(version) = sqlx::query_scalar("SELECT version FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2 AND operation=$3").bind(tenant).bind(id).bind(operation).fetch_optional(&mut *c).await? {
        return Ok(Coordinates { tenant, material:id, binding:binding.clone(), version });
    }
    let revision: i64 = row.try_get("revision")?;
    if revision != expected_revision {
        return Err(Error::Conflict);
    }
    let pending:bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2 AND pending)").bind(tenant).bind(id).fetch_one(&mut *c).await?;
    if pending {
        return Err(Error::Conflict);
    }
    let version = revision.checked_add(1).ok_or(Error::Conflict)?;
    sqlx::query("INSERT INTO mdm_recovery.versions(tenant_id,entry,version,operation,validity,created_at) VALUES($1,$2,$3,$4,'unverified',floor(extract(epoch FROM clock_timestamp()))::bigint)")
        .bind(tenant).bind(id).bind(version).bind(operation).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.entries SET revision=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(tenant)
        .bind(id)
        .bind(version)
        .execute(c)
        .await?;
    Ok(Coordinates {
        tenant,
        material: id,
        binding: binding.clone(),
        version,
    })
}

/// Called only for a correlated, accepted platform receipt in its original execution transaction.
/// Escrow alone does not claim the credential has been verified on the endpoint.
pub async fn ingest_in(
    c: &mut PgConnection,
    keys: &KeyRing,
    coordinates: &Coordinates,
    operation: Uuid,
    secret: &[u8],
) -> Result<(), Error> {
    active_in(c, coordinates.tenant, &coordinates.binding).await?;
    coordinates.binding.subject.validate_secret(secret)?;
    let row = locked_version(c, coordinates).await?;
    if row.try_get::<Uuid, _>("operation")? != operation {
        return Err(Error::Conflict);
    }
    if let Some(sealed) = row.try_get::<Option<Vec<u8>>, _>("sealed")? {
        let key: String = row.try_get("key_id")?;
        let old = keys.open(&key, coordinates, &sealed)?;
        return if bool::from(old.expose().ct_eq(secret)) {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    }
    if !row.try_get::<bool, _>("pending")? {
        return Err(Error::Conflict);
    }
    let sealed = keys.seal(coordinates, secret)?;
    sqlx::query("UPDATE mdm_recovery.versions SET key_id=$4,sealed=$5 WHERE tenant_id=$1 AND entry=$2 AND version=$3")
        .bind(coordinates.tenant).bind(coordinates.material).bind(coordinates.version).bind(keys.active()).bind(sealed).execute(c).await?;
    Ok(())
}

async fn locked_version(
    c: &mut PgConnection,
    coordinates: &Coordinates,
) -> Result<sqlx::postgres::PgRow, Error> {
    let row = sqlx::query(select_material!(
        " WHERE e.tenant_id=$1 AND e.id=$2 AND v.version=$3 AND NOT e.retired FOR UPDATE OF e,v"
    ))
    .bind(coordinates.tenant)
    .bind(coordinates.material)
    .bind(coordinates.version)
    .fetch_optional(c)
    .await?
    .ok_or(Error::NotFound)?;
    let material = decode(&row)?;
    if material.binding != coordinates.binding || !material.validity.readable() {
        return Err(Error::Conflict);
    }
    Ok(row)
}

/// A type-specific verification may promote only the reserved latest candidate with escrowed bytes.
pub async fn verify_in(
    c: &mut PgConnection,
    coordinates: &Coordinates,
    operation: Uuid,
) -> Result<(), Error> {
    active_in(c, coordinates.tenant, &coordinates.binding).await?;
    let row = locked_version(c, coordinates).await?;
    if row.try_get::<Uuid, _>("operation")? != operation
        || row.try_get::<Option<Vec<u8>>, _>("sealed")?.is_none()
    {
        return Err(Error::Conflict);
    }
    let revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM mdm_recovery.entries WHERE tenant_id=$1 AND id=$2",
    )
    .bind(coordinates.tenant)
    .bind(coordinates.material)
    .fetch_one(&mut *c)
    .await?;
    if revision != coordinates.version {
        return Err(Error::Conflict);
    }
    sqlx::query("UPDATE mdm_recovery.versions SET validity='superseded',pending=false,invalidated_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1 AND entry=$2 AND version<>$3 AND invalidated_at IS NULL")
        .bind(coordinates.tenant).bind(coordinates.material).bind(coordinates.version).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.versions SET validity='verified',pending=false WHERE tenant_id=$1 AND entry=$2 AND version=$3")
        .bind(coordinates.tenant).bind(coordinates.material).bind(coordinates.version).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.entries SET current_version=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(coordinates.tenant)
        .bind(coordinates.material)
        .bind(coordinates.version)
        .execute(c)
        .await?;
    Ok(())
}

/// Uncertain effects preserve all possibly necessary material; they never trigger a fresh rotation.
pub async fn unknown_in(c: &mut PgConnection, tenant: Uuid, operation: Uuid) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_recovery.versions SET validity='unknown' WHERE tenant_id=$1 AND invalidated_at IS NULL AND entry IN(SELECT entry FROM mdm_recovery.versions WHERE tenant_id=$1 AND operation=$2)")
        .bind(tenant).bind(operation).execute(c).await?;
    Ok(())
}

/// Registration retirement is atomic with the existing registration owner.
pub async fn retire_in(
    c: &mut PgConnection,
    tenant: &str,
    registration: Uuid,
) -> Result<(), Error> {
    sqlx::query(
        "UPDATE mdm_recovery.entries SET retired=true WHERE tenant_id=$1::uuid AND registration=$2",
    )
    .bind(tenant)
    .bind(registration)
    .execute(&mut *c)
    .await?;
    sqlx::query("UPDATE mdm_recovery.versions v SET validity='revoked',invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) FROM mdm_recovery.entries e WHERE (v.tenant_id,v.entry)=(e.tenant_id,e.id) AND e.tenant_id=$1::uuid AND e.registration=$2")
        .bind(tenant).bind(registration).execute(c).await?;
    Ok(())
}

pub(crate) fn decode(row: &sqlx::postgres::PgRow) -> Result<Material, Error> {
    let validity: String = row.try_get("validity")?;
    Ok(Material {
        id: row.try_get("id")?,
        binding: Binding {
            device: row.try_get("device")?,
            registration: row.try_get("registration")?,
            generation: row.try_get("generation")?,
            subject: serde_json::from_value(row.try_get("subject")?)
                .map_err(|_| Error::Integrity)?,
        },
        version: row.try_get("version")?,
        current: row.try_get::<Option<i64>, _>("current_version")? == Some(row.try_get("version")?),
        validity: serde_json::from_value(serde_json::Value::String(validity))
            .map_err(|_| Error::Integrity)?,
        escrowed: row.try_get::<Option<Vec<u8>>, _>("sealed")?.is_some(),
        operation: row.try_get("operation")?,
        created_at: row.try_get("created_at")?,
        invalidated_at: row.try_get("invalidated_at")?,
    })
}

/// Metadata linking an existing native command to its single credential owner.
#[derive(Clone)]
pub struct NativeAction {
    pub action: String,
    pub coordinates: Option<Coordinates>,
    pub recipient: String,
}
pub async fn native_action_in(
    c: &mut PgConnection,
    tenant: Uuid,
    operation: Uuid,
    device: &str,
    registration: Uuid,
    generation: i64,
) -> Result<Option<NativeAction>, Error> {
    sqlx::query("SELECT action,coordinates,recipient FROM mdm_recovery.native_actions WHERE tenant_id=$1 AND operation=$2 AND device=$3 AND registration=$4 AND generation=$5")
        .bind(tenant).bind(operation).bind(device).bind(registration).bind(generation).fetch_optional(c).await?.map(|r|{
            Ok(NativeAction { action:r.try_get("action")?,coordinates:r.try_get::<Option<serde_json::Value>,_>("coordinates")?.map(serde_json::from_value).transpose().map_err(|_|Error::Integrity)?,recipient:r.try_get("recipient")? })
        }).transpose()
}
/// Platform compilation supplies the action; it is not a second execution queue.
pub async fn link_native_in(
    c: &mut PgConnection,
    tenant: Uuid,
    operation: Uuid,
    binding: &Binding,
    action: &NativeAction,
) -> Result<(), Error> {
    active_in(c, tenant, binding).await?;
    sqlx::query("INSERT INTO mdm_recovery.native_actions(tenant_id,operation,device,registration,generation,action,coordinates,recipient) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(tenant).bind(operation).bind(&binding.device).bind(binding.registration).bind(binding.generation).bind(&action.action).bind(action.coordinates.as_ref().map(serde_json::to_value).transpose().map_err(|_|Error::Malformed)?).bind(&action.recipient).execute(c).await?;
    Ok(())
}
/// Internal platform use is separately authorized by the original operation owner.
pub async fn secret_in(
    c: &mut PgConnection,
    keys: &KeyRing,
    coordinates: &Coordinates,
) -> Result<rss_mdm_native_protection::Plaintext, Error> {
    active_in(c, coordinates.tenant, &coordinates.binding).await?;
    let r = locked_version(c, coordinates).await?;
    keys.open(
        &r.try_get::<Option<String>, _>("key_id")?
            .ok_or(Error::NotFound)?,
        coordinates,
        &r.try_get::<Option<Vec<u8>>, _>("sealed")?
            .ok_or(Error::NotFound)?,
    )
}
pub async fn coordinates_in(
    c: &mut PgConnection,
    tenant: Uuid,
    device: &str,
    id: Uuid,
    version: i64,
) -> Result<Coordinates, Error> {
    let r = sqlx::query(select_material!(
        " WHERE e.tenant_id=$1 AND e.device=$2 AND e.id=$3 AND v.version=$4 AND NOT e.retired"
    ))
    .bind(tenant)
    .bind(device)
    .bind(id)
    .bind(version)
    .fetch_optional(c)
    .await?
    .ok_or(Error::NotFound)?;
    let m = decode(&r)?;
    if !m.validity.readable() {
        return Err(Error::Conflict);
    }
    Ok(Coordinates {
        tenant,
        material: id,
        binding: m.binding,
        version,
    })
}
/// Known terminal receipt ends recovery retention without asserting material validity.
pub async fn settled_in(
    c: &mut PgConnection,
    coordinates: &Coordinates,
    operation: Uuid,
) -> Result<(), Error> {
    let r = locked_version(c, coordinates).await?;
    if r.try_get::<Uuid, _>("operation")? != operation {
        return Err(Error::Conflict);
    }
    sqlx::query("UPDATE mdm_recovery.versions SET pending=false WHERE tenant_id=$1 AND entry=$2 AND version=$3").bind(coordinates.tenant).bind(coordinates.material).bind(coordinates.version).execute(c).await?;
    Ok(())
}

/// Validate every retained key identity before serving the tenant, including the active key.
pub async fn validate_keys_in(
    c: &mut PgConnection,
    tenant: Uuid,
    keys: &KeyRing,
) -> Result<(), Error> {
    let rows=sqlx::query(select_material!(" WHERE e.tenant_id=$1 AND (v.entry,v.version) IN(SELECT DISTINCT ON(key_id) entry,version FROM mdm_recovery.versions WHERE tenant_id=$1 AND sealed IS NOT NULL ORDER BY key_id,entry,version)"))
        .bind(tenant).fetch_all(c).await?;
    for r in rows {
        let m = decode(&r)?;
        let coordinates = Coordinates {
            tenant,
            material: m.id,
            binding: m.binding,
            version: m.version,
        };
        keys.open(
            &r.try_get::<String, _>("key_id")?,
            &coordinates,
            &r.try_get::<Vec<u8>, _>("sealed")?,
        )?;
    }
    Ok(())
}
/// Re-encryption changes no material identity or validity and is safe to resume after interruption.
pub async fn rewrap_in(c: &mut PgConnection, tenant: Uuid, keys: &KeyRing) -> Result<u64, Error> {
    let rows=sqlx::query(select_material!(" WHERE e.tenant_id=$1 AND v.sealed IS NOT NULL AND v.key_id<>$2 ORDER BY e.id,v.version LIMIT 100 FOR UPDATE OF v SKIP LOCKED"))
        .bind(tenant).bind(keys.active()).fetch_all(&mut *c).await?;
    let count = rows.len() as u64;
    for r in rows {
        let m = decode(&r)?;
        let coordinates = Coordinates {
            tenant,
            material: m.id,
            binding: m.binding,
            version: m.version,
        };
        let plain = keys.open(
            &r.try_get::<String, _>("key_id")?,
            &coordinates,
            &r.try_get::<Vec<u8>, _>("sealed")?,
        )?;
        let sealed = keys.seal(&coordinates, plain.expose())?;
        sqlx::query("UPDATE mdm_recovery.versions SET key_id=$4,sealed=$5 WHERE tenant_id=$1 AND entry=$2 AND version=$3")
            .bind(tenant).bind(coordinates.material).bind(coordinates.version).bind(keys.active()).bind(sealed).execute(&mut *c).await?;
    }
    Ok(count)
}

/// The execution owner must scrub its terminal input copies before clearing these bytes.
pub async fn expired_in(c: &mut PgConnection, tenant: Uuid) -> Result<Vec<Material>, Error> {
    sqlx::query(select_material!(" WHERE e.tenant_id=$1 AND NOT v.pending AND v.sealed IS NOT NULL AND v.invalidated_at<=floor(extract(epoch FROM clock_timestamp()))::bigint-7776000 ORDER BY v.invalidated_at LIMIT 100 FOR UPDATE OF v SKIP LOCKED"))
        .bind(tenant).fetch_all(c).await?.iter().map(decode).collect()
}
pub async fn clear_expired_in(
    c: &mut PgConnection,
    tenant: Uuid,
    id: Uuid,
    version: i64,
) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_recovery.versions SET sealed=NULL,key_id=NULL WHERE tenant_id=$1 AND entry=$2 AND version=$3 AND NOT pending AND invalidated_at<=floor(extract(epoch FROM clock_timestamp()))::bigint-7776000")
        .bind(tenant).bind(id).bind(version).execute(c).await?;
    Ok(())
}

pub async fn verify_existing_secret_in(
    c: &mut PgConnection,
    keys: &KeyRing,
    tenant: Uuid,
    binding: &Binding,
    revision: i64,
    secret: &[u8],
) -> Result<Coordinates, Error> {
    active_in(c, tenant, binding).await?;
    let subject = serde_json::to_value(&binding.subject).map_err(|_| Error::Malformed)?;
    let id=sqlx::query_scalar("SELECT id FROM mdm_recovery.entries WHERE tenant_id=$1 AND device=$2 AND registration=$3 AND generation=$4 AND subject=$5 AND revision=$6 AND NOT retired FOR UPDATE")
        .bind(tenant).bind(&binding.device).bind(binding.registration).bind(binding.generation).bind(subject).bind(revision).fetch_optional(&mut *c).await?.ok_or(Error::Conflict)?;
    let coordinates = Coordinates {
        tenant,
        material: id,
        binding: binding.clone(),
        version: revision,
    };
    let current = secret_in(c, keys, &coordinates).await?;
    if !bool::from(current.expose().ct_eq(secret)) {
        return Err(Error::Conflict);
    }
    Ok(coordinates)
}
pub async fn link_agent_in(
    c: &mut PgConnection,
    task: Uuid,
    attempt: Uuid,
    coordinates: &Coordinates,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO mdm_recovery.agent_materials(tenant_id,task,attempt,entry,version) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
        .bind(coordinates.tenant).bind(task).bind(attempt).bind(coordinates.material).bind(coordinates.version).execute(&mut *c).await?;
    let version:i64=sqlx::query_scalar("SELECT version FROM mdm_recovery.agent_materials WHERE tenant_id=$1 AND task=$2 AND attempt=$3 AND entry=$4")
        .bind(coordinates.tenant).bind(task).bind(attempt).bind(coordinates.material).fetch_one(c).await?;
    if version != coordinates.version {
        return Err(Error::Conflict);
    }
    Ok(())
}
pub async fn agent_materials_in(
    c: &mut PgConnection,
    tenant: Uuid,
    task: Uuid,
    attempt: Uuid,
) -> Result<Vec<Material>, Error> {
    sqlx::query(select_material!(" JOIN mdm_recovery.agent_materials a ON(a.tenant_id,a.entry,a.version)=(v.tenant_id,v.entry,v.version) WHERE e.tenant_id=$1 AND a.task=$2 AND a.attempt=$3 ORDER BY e.id LIMIT 513"))
        .bind(tenant).bind(task).bind(attempt).fetch_all(c).await?.iter().map(decode).collect()
}
/// Only confirmed removal of the exact predecessor can invalidate another protector's material.
pub async fn supersede_in(
    c: &mut PgConnection,
    tenant: Uuid,
    binding: &Binding,
    revision: i64,
) -> Result<(), Error> {
    active_in(c, tenant, binding).await?;
    let subject = serde_json::to_value(&binding.subject).map_err(|_| Error::Malformed)?;
    let row=sqlx::query("SELECT id,revision FROM mdm_recovery.entries WHERE tenant_id=$1 AND device=$2 AND registration=$3 AND generation=$4 AND subject=$5 FOR UPDATE")
        .bind(tenant).bind(&binding.device).bind(binding.registration).bind(binding.generation).bind(subject).fetch_optional(&mut *c).await?;
    let Some(row) = row else {
        return if revision == 0 {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    };
    if row.try_get::<i64, _>("revision")? != revision {
        return Err(Error::Conflict);
    }
    let id: Uuid = row.try_get("id")?;
    sqlx::query("UPDATE mdm_recovery.versions SET validity='superseded',pending=false,invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1 AND entry=$2 AND invalidated_at IS NULL")
        .bind(tenant).bind(id).execute(&mut *c).await?;
    sqlx::query(
        "UPDATE mdm_recovery.entries SET current_version=NULL WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant)
    .bind(id)
    .execute(c)
    .await?;
    Ok(())
}

/// Serialize mutations across credential policies; an unknown outcome never expires this fence.
pub async fn start_agent_in(
    c: &mut PgConnection,
    tenant: Uuid,
    registration: Uuid,
    generation: i64,
    task: Uuid,
    attempt: Uuid,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO mdm_recovery.agent_guards(tenant_id,registration,task,attempt,generation) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
        .bind(tenant).bind(registration).bind(task).bind(attempt).bind(generation).execute(&mut *c).await?;
    let matches:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_recovery.agent_guards WHERE tenant_id=$1 AND registration=$2 AND task=$3 AND attempt=$4 AND generation=$5)")
        .bind(tenant).bind(registration).bind(task).bind(attempt).bind(generation).fetch_one(c).await?;
    if matches {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}
/// A successful independent verification can settle the original uncertain operation's fence.
pub async fn finish_agent_in(
    c: &mut PgConnection,
    tenant: Uuid,
    task: Uuid,
) -> Result<Option<Uuid>, Error> {
    sqlx::query_scalar(
        "DELETE FROM mdm_recovery.agent_guards WHERE tenant_id=$1 AND task=$2 RETURNING attempt",
    )
    .bind(tenant)
    .bind(task)
    .fetch_optional(c)
    .await
    .map_err(Into::into)
}

/// Resolve the original immutable operation when an independent query confirms a candidate.
pub async fn source_operation_in(
    c: &mut PgConnection,
    coordinates: &Coordinates,
) -> Result<Uuid, Error> {
    Ok(locked_version(c, coordinates).await?.try_get("operation")?)
}

/// A correlated native clear receipt removes the current pointer as well as disclosure eligibility.
pub async fn cleared_in(c: &mut PgConnection, coordinates: &Coordinates) -> Result<(), Error> {
    active_in(c, coordinates.tenant, &coordinates.binding).await?;
    sqlx::query("UPDATE mdm_recovery.versions SET validity='revoked',pending=false,invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1 AND entry=$2 AND version=$3")
        .bind(coordinates.tenant).bind(coordinates.material).bind(coordinates.version).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.entries SET current_version=NULL WHERE tenant_id=$1 AND id=$2 AND current_version=$3")
        .bind(coordinates.tenant).bind(coordinates.material).bind(coordinates.version).execute(c).await?;
    Ok(())
}
