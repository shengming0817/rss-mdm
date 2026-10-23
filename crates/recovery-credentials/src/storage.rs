//! Borrowed product transaction operations. The caller retains audit, commit and rollback ownership.
use crate::*;
use rss_mdm_inventory::Channel;
use sqlx::{PgConnection, Row};
use subtle::ConstantTimeEq;
use uuid::Uuid;

macro_rules! select_material { ($suffix:literal) => { concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM mdm_recovery.entries e JOIN mdm_recovery.versions v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id)", $suffix) }; }
pub(crate) use select_material;

/// Report historical use by the same registered device, without consuming/revalidating a key.
pub async fn rss_use_in(
    c: &mut PgConnection,
    device: &rss_mdm_registration_service::DevicePrincipal,
    input: &rss_mdm_agent_wire::runtime::AccessRecoveryUse,
) -> Result<bool, Error> {
    input.validate().map_err(|_| Error::Malformed)?;
    rss_mdm_registration_service::device::store::revalidate_management(c, device).await?;
    let tenant = Uuid::parse_str(&device.tenant().to_string()).map_err(|_| Error::Malformed)?;
    let row = sqlx::query(select_material!(
        " WHERE e.tenant_id=$1 AND e.id=$2 AND v.version=$3 FOR UPDATE OF e"
    ))
    .bind(tenant)
    .bind(input.material)
    .bind(input.version)
    .fetch_optional(&mut *c)
    .await?
    .ok_or(Error::NotFound)?;
    let material = decode(&row)?;
    if material.binding.device != device.device()
        || material.binding.registration != device.registration()
        || material.binding.generation != device.generation()
        || !matches!(material.binding.subject, Subject::RssLogin { .. })
    {
        return Err(Error::Forbidden);
    }
    if let Some(old)=sqlx::query_as::<_,(Uuid,i64,i64)>("SELECT entry,version,used_at FROM mdm_recovery.rss_login_uses WHERE tenant_id=$1 AND operation=$2")
        .bind(tenant).bind(input.operation_id).fetch_optional(&mut *c).await? {
        return if old==(input.material,input.version,input.used_at){Ok(true)}else{Err(Error::Conflict)};
    }
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await?;
    if input.used_at > now.saturating_add(300) {
        return Err(Error::Malformed);
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_recovery.rss_login_uses WHERE tenant_id=$1 AND entry=$2",
    )
    .bind(tenant)
    .bind(input.material)
    .fetch_one(&mut *c)
    .await?;
    if count >= 4096 {
        return Err(Error::Conflict);
    }
    sqlx::query("INSERT INTO mdm_recovery.rss_login_uses(tenant_id,operation,entry,version,used_at,received_at) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(tenant).bind(input.operation_id).bind(input.material).bind(input.version).bind(input.used_at).bind(now).execute(c).await?;
    Ok(false)
}

/// Registration lock precedes material locks everywhere, including disclosure and retirement.
pub async fn active_in(c: &mut PgConnection, tenant: Uuid, binding: &Binding) -> Result<(), Error> {
    binding.validate()?;
    let channel = match binding.subject {
        Subject::RssLogin { .. }
        | Subject::Bitlocker { .. }
        | Subject::LocalAdministrator { .. } => Channel::Agent,
        _ => Channel::Mdm,
    };
    if let Subject::RssLogin {
        binding: id,
        binding_generation,
        sid,
    } = &binding.subject
    {
        let b =
            rss_mdm_registration_service::device_access::storage::locked_in(c, tenant, *id).await?;
        if b.generation != *binding_generation
            || b.state == rss_mdm_registration_service::device_access::State::Revoked
            || b.device != binding.device
            || b.registration != binding.registration
            || b.registration_generation != binding.generation
            || !matches!(&b.account,Some(rss_mdm_agent_wire::runtime::AccessAccount::Windows{sid:current}) if current==sid)
        {
            return Err(Error::Conflict);
        }
    }
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
    pub reconciles: Option<Uuid>,
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
    sqlx::query("SELECT action,coordinates,recipient,reconciles FROM mdm_recovery.native_actions WHERE tenant_id=$1 AND operation=$2 AND device=$3 AND registration=$4 AND generation=$5")
        .bind(tenant).bind(operation).bind(device).bind(registration).bind(generation).fetch_optional(c).await?.map(|r|{
            Ok(NativeAction { reconciles:r.try_get("reconciles")?,action:r.try_get("action")?,coordinates:r.try_get::<Option<serde_json::Value>,_>("coordinates")?.map(serde_json::from_value).transpose().map_err(|_|Error::Integrity)?,recipient:r.try_get("recipient")? })
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
    sqlx::query("INSERT INTO mdm_recovery.native_actions(tenant_id,operation,device,registration,generation,action,coordinates,recipient,reconciles) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(tenant).bind(operation).bind(&binding.device).bind(binding.registration).bind(binding.generation).bind(&action.action).bind(action.coordinates.as_ref().map(serde_json::to_value).transpose().map_err(|_|Error::Malformed)?).bind(&action.recipient).bind(action.reconciles).execute(c).await?;
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
/// The maintenance owner retains this bounded locked page until it declares its source partition.
pub struct RewrapPage {
    tenant: Uuid,
    rows: Vec<sqlx::postgres::PgRow>,
}
pub async fn prepare_rewrap_in(
    c: &mut PgConnection,
    tenant: Uuid,
    keys: &KeyRing,
) -> Result<RewrapPage, Error> {
    let rows=sqlx::query(select_material!(" WHERE e.tenant_id=$1 AND v.sealed IS NOT NULL AND v.key_id<>$2 ORDER BY e.id,v.version LIMIT 100 FOR UPDATE OF v"))
        .bind(tenant).bind(keys.active()).fetch_all(&mut *c).await?;
    Ok(RewrapPage { tenant, rows })
}
/// Re-encryption changes no material identity or validity; consume the page once.
pub async fn rewrap_in(
    c: &mut PgConnection,
    page: RewrapPage,
    keys: &KeyRing,
) -> Result<u64, Error> {
    let RewrapPage { tenant, rows } = page;
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
    sqlx::query(select_material!(" WHERE e.tenant_id=$1 AND NOT v.pending AND (e.subject->>'kind'<>'rss_login' OR (e.current_version IS NOT NULL AND e.current_version<>v.version) OR EXISTS(SELECT 1 FROM mdm_access.device_access_bindings b WHERE b.tenant_id=e.tenant_id AND b.id=(e.subject->>'binding')::uuid AND b.document->>'appliedRevision'=b.revision::text AND b.document->'effect'->>'state'='unbound')) AND NOT EXISTS(SELECT 1 FROM mdm_recovery.agent_guards g WHERE g.tenant_id=e.tenant_id AND g.registration=e.registration AND g.generation=e.generation) AND NOT EXISTS(SELECT 1 FROM mdm_recovery.entries held JOIN mdm_recovery.versions unresolved ON(unresolved.tenant_id,unresolved.entry)=(held.tenant_id,held.id) WHERE held.tenant_id=e.tenant_id AND held.registration=e.registration AND unresolved.pending) AND v.sealed IS NOT NULL AND v.invalidated_at<=floor(extract(epoch FROM clock_timestamp()))::bigint-7776000 ORDER BY v.cleanup_checked_at,v.invalidated_at,e.id,v.version LIMIT 100 FOR UPDATE OF v SKIP LOCKED"))
        .bind(tenant).fetch_all(c).await?.iter().map(decode).collect()
}
pub async fn clear_expired_in(
    c: &mut PgConnection,
    tenant: Uuid,
    id: Uuid,
    version: i64,
) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_recovery.versions v SET sealed=NULL,key_id=NULL FROM mdm_recovery.entries e WHERE (e.tenant_id,e.id)=(v.tenant_id,v.entry) AND v.tenant_id=$1 AND v.entry=$2 AND v.version=$3 AND NOT v.pending AND (e.subject->>'kind'<>'rss_login' OR (e.current_version IS NOT NULL AND e.current_version<>v.version) OR EXISTS(SELECT 1 FROM mdm_access.device_access_bindings b WHERE b.tenant_id=e.tenant_id AND b.id=(e.subject->>'binding')::uuid AND b.document->>'appliedRevision'=b.revision::text AND b.document->'effect'->>'state'='unbound')) AND v.invalidated_at<=floor(extract(epoch FROM clock_timestamp()))::bigint-7776000 AND NOT EXISTS(SELECT 1 FROM mdm_recovery.agent_guards g WHERE g.tenant_id=e.tenant_id AND g.registration=e.registration AND g.generation=e.generation) AND NOT EXISTS(SELECT 1 FROM mdm_recovery.entries held JOIN mdm_recovery.versions unresolved ON(unresolved.tenant_id,unresolved.entry)=(held.tenant_id,held.id) WHERE held.tenant_id=e.tenant_id AND held.registration=e.registration AND unresolved.pending)")
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
    locked_version(c, coordinates).await?;
    sqlx::query("UPDATE mdm_recovery.versions SET validity='revoked',pending=false,invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1 AND entry=$2 AND (invalidated_at IS NULL OR pending)")
        .bind(coordinates.tenant).bind(coordinates.material).execute(&mut *c).await?;
    sqlx::query(
        "UPDATE mdm_recovery.entries SET current_version=NULL WHERE tenant_id=$1 AND id=$2",
    )
    .bind(coordinates.tenant)
    .bind(coordinates.material)
    .execute(c)
    .await?;
    Ok(())
}

/// Frozen object revisions for the current registration; consumers do not own this schema.
pub async fn revisions_in(
    c: &mut PgConnection,
    tenant: Uuid,
    device: &str,
    registration: Uuid,
    generation: i64,
) -> Result<Vec<(Subject, i64)>, Error> {
    let rows=sqlx::query("SELECT subject,revision FROM mdm_recovery.entries WHERE tenant_id=$1 AND device=$2 AND registration=$3 AND generation=$4 AND NOT retired ORDER BY id LIMIT 513").bind(tenant).bind(device).bind(registration).bind(generation).fetch_all(c).await?;
    rows.into_iter()
        .map(|r| {
            Ok((
                serde_json::from_value(r.try_get("subject")?).map_err(|_| Error::Integrity)?,
                r.try_get("revision")?,
            ))
        })
        .collect()
}
/// Correlated negative verification preserves uncertainty without touching other versions.
pub async fn uncertain_version_in(
    c: &mut PgConnection,
    coordinates: &Coordinates,
) -> Result<(), Error> {
    active_in(c, coordinates.tenant, &coordinates.binding).await?;
    locked_version(c, coordinates).await?;
    sqlx::query("UPDATE mdm_recovery.versions SET validity='unknown' WHERE tenant_id=$1 AND entry=$2 AND version=$3 AND invalidated_at IS NULL").bind(coordinates.tenant).bind(coordinates.material).bind(coordinates.version).execute(c).await?;
    Ok(())
}
/// Native input copies must be purged before any expired ciphertext for this registration.
pub async fn input_copies_in(
    c: &mut PgConnection,
    tenant: Uuid,
    registration: Uuid,
) -> Result<Vec<Uuid>, Error> {
    Ok(sqlx::query_scalar("SELECT operation FROM mdm_recovery.native_actions WHERE tenant_id=$1 AND registration=$2 AND NOT inputs_purged ORDER BY operation LIMIT 100").bind(tenant).bind(registration).fetch_all(c).await?)
}
pub async fn input_purged_in(
    c: &mut PgConnection,
    tenant: Uuid,
    operation: Uuid,
) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_recovery.native_actions SET inputs_purged=true WHERE tenant_id=$1 AND operation=$2").bind(tenant).bind(operation).execute(c).await?;
    Ok(())
}
pub async fn inputs_remain_in(
    c: &mut PgConnection,
    tenant: Uuid,
    registration: Uuid,
) -> Result<bool, Error> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_recovery.native_actions WHERE tenant_id=$1 AND registration=$2 AND NOT inputs_purged)").bind(tenant).bind(registration).fetch_one(c).await?)
}

/// Read the exact unresolved execution identity, including operations with no escrow yet.
pub async fn agent_guard_in(
    c: &mut PgConnection,
    tenant: Uuid,
    registration: Uuid,
    generation: i64,
) -> Result<Option<(Uuid, Uuid)>, Error> {
    sqlx::query("SELECT task,attempt FROM mdm_recovery.agent_guards WHERE tenant_id=$1 AND registration=$2 AND generation=$3").bind(tenant).bind(registration).bind(generation).fetch_optional(c).await?.map(|r|Ok((r.try_get("task")?,r.try_get("attempt")?))).transpose()
}
/// After independent platform verification and original execution fencing, resolve a candidate
/// or restore the verified predecessor. Invalidated versions can never be resurrected.
pub async fn reconcile_in(
    c: &mut PgConnection,
    coordinates: &Coordinates,
    original: Uuid,
) -> Result<(), Error> {
    active_in(c, coordinates.tenant, &coordinates.binding).await?;
    let row = locked_version(c, coordinates).await?;
    if row.try_get::<Option<Vec<u8>>, _>("sealed")?.is_none() {
        return Err(Error::Conflict);
    }
    let candidate:Option<Uuid>=sqlx::query_scalar("SELECT v.operation FROM mdm_recovery.versions v JOIN mdm_recovery.entries e ON(e.tenant_id,e.id,e.revision)=(v.tenant_id,v.entry,v.version) WHERE e.tenant_id=$1 AND e.id=$2 AND v.pending").bind(coordinates.tenant).bind(coordinates.material).fetch_optional(&mut *c).await?;
    if candidate.is_some_and(|id| id != original) {
        return Err(Error::Conflict);
    }
    sqlx::query("UPDATE mdm_recovery.versions SET validity='superseded',pending=false,invalidated_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1 AND entry=$2 AND version<>$3 AND invalidated_at IS NULL").bind(coordinates.tenant).bind(coordinates.material).bind(coordinates.version).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.versions SET validity='verified',pending=false WHERE tenant_id=$1 AND entry=$2 AND version=$3").bind(coordinates.tenant).bind(coordinates.material).bind(coordinates.version).execute(&mut *c).await?;
    sqlx::query("UPDATE mdm_recovery.entries SET current_version=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(coordinates.tenant)
        .bind(coordinates.material)
        .bind(coordinates.version)
        .execute(c)
        .await?;
    Ok(())
}
/// An independent recovery query can receive a previously unreported candidate, or match a
/// retained predecessor. It cannot replace unrelated pending operations or overwrite ciphertext.
pub async fn recovery_secret_in(
    c: &mut PgConnection,
    keys: &KeyRing,
    tenant: Uuid,
    binding: &Binding,
    revision: i64,
    original: Uuid,
    secret: &[u8],
) -> Result<Coordinates, Error> {
    active_in(c, tenant, binding).await?;
    let revisions = revisions_in(
        c,
        tenant,
        &binding.device,
        binding.registration,
        binding.generation,
    )
    .await?;
    if revisions
        .iter()
        .find(|(s, _)| s == &binding.subject)
        .map(|(_, r)| *r)
        .unwrap_or(0)
        != revision
    {
        return Err(Error::Conflict);
    }
    let subject = serde_json::to_value(&binding.subject).map_err(|_| Error::Malformed)?;
    let rows=sqlx::query(select_material!(" WHERE e.tenant_id=$1 AND e.device=$2 AND e.registration=$3 AND e.generation=$4 AND e.subject=$5 AND NOT e.retired AND v.invalidated_at IS NULL ORDER BY v.version DESC FOR UPDATE OF e,v"))
        .bind(tenant).bind(&binding.device).bind(binding.registration).bind(binding.generation).bind(subject).fetch_all(&mut *c).await?;
    for r in rows {
        let m = decode(&r)?;
        let coordinates = Coordinates {
            tenant,
            material: m.id,
            binding: m.binding,
            version: m.version,
        };
        if let (Some(key), Some(sealed)) = (
            r.try_get::<Option<String>, _>("key_id")?,
            r.try_get::<Option<Vec<u8>>, _>("sealed")?,
        ) && bool::from(
            keys.open(&key, &coordinates, &sealed)?
                .expose()
                .ct_eq(secret),
        ) {
            return Ok(coordinates);
        }
    }
    let coordinates = reserve_in(c, tenant, binding, original, revision).await?;
    ingest_in(c, keys, &coordinates, original, secret).await?;
    Ok(coordinates)
}

/// Fair bounded sweeps advance even when a live native command prevents destruction.
pub async fn cleanup_visited_in(
    c: &mut PgConnection,
    tenant: Uuid,
    id: Uuid,
    version: i64,
) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_recovery.versions SET cleanup_checked_at=(extract(epoch FROM clock_timestamp())*1000000)::bigint WHERE tenant_id=$1 AND entry=$2 AND version=$3").bind(tenant).bind(id).bind(version).execute(c).await?;
    Ok(())
}
