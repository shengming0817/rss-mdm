//! Borrowed product transaction operations. The caller retains audit, commit and rollback ownership.
use crate::*;
use rss_mdm_inventory::Channel;
use sqlx::{PgConnection, Row};
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Report historical use by the same registered device, without consuming/revalidating a key.
pub async fn rss_use_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    device: &rss_mdm_registration_service::device::endpoints::DaRegistration,
    input: &rss_mdm_agent_wire::runtime::AccessRecoveryUse,
) -> Result<bool, Error> {
    let profile = custody.profile();

    input.validate().map_err(|_| Error::Malformed)?;
    if profile != rss_mdm_install_support::StorageProfile::Da {
        return Err(Error::Unsupported);
    }
    rss_mdm_registration_service::device::endpoints::lock_da_in(
        c,
        &tenant.to_string(),
        &device.device,
    )
    .await?;
    if rss_mdm_registration_service::device::endpoints::current_da_in(
        c,
        &tenant.to_string(),
        &device.device,
    )
    .await?
    .as_ref()
        != Some(device)
    {
        return Err(Error::Forbidden);
    }
    let row = sqlx::query(crate::storage_profile::sql(profile).storage_rss_use_in_1)
        .bind(tenant)
        .bind(input.material)
        .bind(input.version)
        .fetch_optional(&mut *c)
        .await?
        .ok_or(Error::NotFound)?;
    let material = decode(&row)?;
    if material.binding.device != device.device
        || !matches!(material.binding.subject, Subject::RssLogin { .. })
    {
        return Err(Error::Forbidden);
    }
    if let Some(old) = sqlx::query_as::<_, (Uuid, i64, i64)>(
        crate::storage_profile::sql(profile).storage_rss_use_in_2,
    )
    .bind(tenant)
    .bind(input.operation_id)
    .fetch_optional(&mut *c)
    .await?
    {
        return if old == (input.material, input.version, input.used_at) {
            Ok(true)
        } else {
            Err(Error::Conflict)
        };
    }
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await?;
    if input.used_at > now.saturating_add(300) {
        return Err(Error::Malformed);
    }
    let count: i64 = sqlx::query_scalar(crate::storage_profile::sql(profile).storage_rss_use_in_3)
        .bind(tenant)
        .bind(input.material)
        .fetch_one(&mut *c)
        .await?;
    if count >= 4096 {
        return Err(Error::Conflict);
    }
    sqlx::query(crate::storage_profile::sql(profile).storage_rss_use_in_4)
        .bind(tenant)
        .bind(input.operation_id)
        .bind(input.material)
        .bind(input.version)
        .bind(input.used_at)
        .bind(now)
        .execute(c)
        .await?;
    Ok(false)
}

/// Registration lock precedes material locks everywhere, including disclosure and retirement.
pub async fn active_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    binding: &Binding,
) -> Result<(), Error> {
    let profile = custody.profile();

    binding.validate()?;
    if matches!(binding.subject, Subject::RssLogin { .. })
        != (profile == rss_mdm_install_support::StorageProfile::Da)
    {
        return Err(Error::Unsupported);
    }
    if profile == rss_mdm_install_support::StorageProfile::Da {
        custody.active(c, tenant, binding).await?;
        rss_mdm_registration_service::device::endpoints::lock_da_in(
            c,
            &tenant.to_string(),
            &binding.device,
        )
        .await?;
        let expected = rss_mdm_registration_service::device::endpoints::DaRegistration {
            device: binding.device,
        };
        return if rss_mdm_registration_service::device::endpoints::current_da_in(
            c,
            &tenant.to_string(),
            &binding.device,
        )
        .await?
        .as_ref()
            == Some(&expected)
        {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    }
    if matches!(binding.subject, Subject::Filevault { .. }) {
        if profile != rss_mdm_install_support::StorageProfile::Mdm {
            return Err(Error::Unsupported);
        }
        return crate::filevault::active(c, tenant, binding).await;
    }
    let channel = match binding.subject {
        Subject::RssLogin { .. }
        | Subject::Bitlocker { .. }
        | Subject::LocalAdministrator { .. } => Channel::Agent,
        _ => Channel::Mdm,
    };
    custody.active(c, tenant, binding).await?;
    let tenant = tenant.to_string();
    rss_mdm_registration_service::device::store::lock_channel(
        profile,
        c,
        &tenant,
        &binding.device,
        channel,
    )
    .await
    .map_err(|_| Error::Storage)?;
    let rows = rss_mdm_registration_service::device::read::active_channel_in(
        profile,
        c,
        tenant,
        vec![binding.device],
        channel,
        rss_mdm_registration_service::Purpose::Primary,
    )
    .await?;
    if rows.contains(&binding.device) {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}

/// Reserve one immutable version under the existing execution operation's idempotency boundary.
pub async fn reserve_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    binding: &Binding,
    operation: Uuid,
    expected_revision: i64,
) -> Result<Coordinates, Error> {
    let profile = custody.profile();

    if operation.is_nil() || expected_revision < 0 {
        return Err(Error::Malformed);
    }
    active_in(custody, c, tenant, binding).await?;
    let subject = serde_json::to_value(&binding.subject).map_err(|_| Error::Malformed)?;
    sqlx::query(crate::storage_profile::sql(profile).storage_reserve_in_1)
        .bind(tenant)
        .bind(Uuid::new_v4())
        .bind(binding.device.into_uuid())
        .bind(&subject)
        .execute(&mut *c)
        .await?;
    let row = sqlx::query(crate::storage_profile::sql(profile).storage_reserve_in_2)
        .bind(tenant)
        .bind(binding.device.into_uuid())
        .bind(&subject)
        .fetch_one(&mut *c)
        .await?;
    let id: Uuid = row.try_get("id")?;
    if row.try_get::<bool, _>("retired")? {
        return Err(Error::Conflict);
    }
    if let Some(version) =
        sqlx::query_scalar(crate::storage_profile::sql(profile).storage_reserve_in_3)
            .bind(tenant)
            .bind(id)
            .bind(operation)
            .fetch_optional(&mut *c)
            .await?
    {
        return Ok(Coordinates {
            profile,
            tenant,
            material: id,
            binding: binding.clone(),
            version,
        });
    }
    if matches!(binding.subject, Subject::Filevault { .. }) {
        if profile != rss_mdm_install_support::StorageProfile::Mdm {
            return Err(Error::Unsupported);
        }
        let versions: i64 =
            sqlx::query_scalar(crate::storage_profile::sql(profile).storage_reserve_in_4)
                .bind(tenant)
                .bind(id)
                .fetch_one(&mut *c)
                .await?;
        if versions >= 4096 {
            return Err(Error::Conflict);
        }
    }
    let revision: i64 = row.try_get("revision")?;
    if revision != expected_revision {
        return Err(Error::Conflict);
    }
    let pending: bool =
        sqlx::query_scalar(crate::storage_profile::sql(profile).storage_reserve_in_5)
            .bind(tenant)
            .bind(id)
            .fetch_one(&mut *c)
            .await?;
    if pending {
        return Err(Error::Conflict);
    }
    let version = revision.checked_add(1).ok_or(Error::Conflict)?;
    sqlx::query(crate::storage_profile::sql(profile).storage_reserve_in_6)
        .bind(tenant)
        .bind(id)
        .bind(version)
        .bind(operation)
        .execute(&mut *c)
        .await?;
    sqlx::query(crate::storage_profile::sql(profile).storage_reserve_in_7)
        .bind(tenant)
        .bind(id)
        .bind(version)
        .execute(c)
        .await?;
    Ok(Coordinates {
        profile,
        tenant,
        material: id,
        binding: binding.clone(),
        version,
    })
}

/// Called only for a correlated, accepted platform receipt in its original execution transaction.
/// Escrow alone does not claim the credential has been verified on the endpoint.
pub async fn ingest_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    keys: &KeyRing,
    coordinates: &Coordinates,
    operation: Uuid,
    secret: &[u8],
) -> Result<(), Error> {
    let profile = custody.profile();
    if coordinates.profile != profile {
        return Err(Error::Forbidden);
    }

    active_in(custody, c, coordinates.tenant, &coordinates.binding).await?;
    coordinates.binding.subject.validate_secret(secret)?;
    let row = locked_version(custody, c, coordinates).await?;
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
    sqlx::query(crate::storage_profile::sql(profile).storage_ingest_in_1)
        .bind(coordinates.tenant)
        .bind(coordinates.material)
        .bind(coordinates.version)
        .bind(keys.active())
        .bind(sealed)
        .execute(c)
        .await?;
    Ok(())
}

async fn locked_version(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    coordinates: &Coordinates,
) -> Result<sqlx::postgres::PgRow, Error> {
    let profile = custody.profile();
    if coordinates.profile != profile {
        return Err(Error::Forbidden);
    }

    let row = sqlx::query(crate::storage_profile::sql(profile).storage_locked_version_1)
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
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    coordinates: &Coordinates,
    operation: Uuid,
) -> Result<(), Error> {
    let profile = custody.profile();
    if coordinates.profile != profile {
        return Err(Error::Forbidden);
    }

    active_in(custody, c, coordinates.tenant, &coordinates.binding).await?;
    let row = locked_version(custody, c, coordinates).await?;
    if row.try_get::<Uuid, _>("operation")? != operation
        || row.try_get::<Option<Vec<u8>>, _>("sealed")?.is_none()
    {
        return Err(Error::Conflict);
    }
    let revision: i64 =
        sqlx::query_scalar(crate::storage_profile::sql(profile).storage_verify_in_1)
            .bind(coordinates.tenant)
            .bind(coordinates.material)
            .fetch_one(&mut *c)
            .await?;
    if revision != coordinates.version {
        return Err(Error::Conflict);
    }
    sqlx::query(crate::storage_profile::sql(profile).storage_verify_in_2)
        .bind(coordinates.tenant)
        .bind(coordinates.material)
        .bind(coordinates.version)
        .execute(&mut *c)
        .await?;
    sqlx::query(crate::storage_profile::sql(profile).storage_verify_in_3)
        .bind(coordinates.tenant)
        .bind(coordinates.material)
        .bind(coordinates.version)
        .execute(&mut *c)
        .await?;
    sqlx::query(crate::storage_profile::sql(profile).storage_verify_in_4)
        .bind(coordinates.tenant)
        .bind(coordinates.material)
        .bind(coordinates.version)
        .execute(c)
        .await?;
    Ok(())
}

/// Uncertain effects preserve all possibly necessary material; they never trigger a fresh rotation.
pub async fn unknown_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    operation: Uuid,
) -> Result<(), Error> {
    let profile = custody.profile();

    sqlx::query(crate::storage_profile::sql(profile).storage_unknown_in_1)
        .bind(tenant)
        .bind(operation)
        .execute(c)
        .await?;
    Ok(())
}

/// Registration retirement is atomic with the existing registration owner.
pub async fn retire_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: &str,
    registration: rss_mdm_agent_wire::DeviceId,
) -> Result<(), Error> {
    let profile = custody.profile();

    sqlx::query(crate::storage_profile::sql(profile).storage_retire_in_1)
        .bind(tenant)
        .bind(registration.into_uuid())
        .execute(&mut *c)
        .await?;
    sqlx::query(crate::storage_profile::sql(profile).storage_retire_in_2)
        .bind(tenant)
        .bind(registration.into_uuid())
        .execute(&mut *c)
        .await?;
    crate::filevault::retire_source(c, tenant, registration).await?;
    Ok(())
}

pub(crate) fn decode(row: &sqlx::postgres::PgRow) -> Result<Material, Error> {
    let validity: String = row.try_get("validity")?;
    Ok(Material {
        id: row.try_get("id")?,
        binding: Binding {
            device: row.try_get::<uuid::Uuid, _>("device").and_then(|id| {
                rss_mdm_agent_wire::DeviceId::try_from(id)
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))
            })?,

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
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    operation: Uuid,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<Option<NativeAction>, Error> {
    let profile = custody.profile();
    if profile != rss_mdm_install_support::StorageProfile::Mdm {
        return Err(Error::Unsupported);
    }

    sqlx::query(crate::storage_profile::sql(profile).storage_native_action_in_1)
        .bind(tenant)
        .bind(operation)
        .bind(device.into_uuid())
        .fetch_optional(c)
        .await?
        .map(|r| {
            Ok(NativeAction {
                reconciles: r.try_get("reconciles")?,
                action: r.try_get("action")?,
                coordinates: r
                    .try_get::<Option<serde_json::Value>, _>("coordinates")?
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|_| Error::Integrity)?,
                recipient: r.try_get("recipient")?,
            })
        })
        .transpose()
}
/// Platform compilation supplies the action; it is not a second execution queue.
pub async fn link_native_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    operation: Uuid,
    binding: &Binding,
    action: &NativeAction,
) -> Result<(), Error> {
    let profile = custody.profile();
    if profile != rss_mdm_install_support::StorageProfile::Mdm {
        return Err(Error::Unsupported);
    }

    active_in(custody, c, tenant, binding).await?;
    sqlx::query(crate::storage_profile::sql(profile).storage_link_native_in_1)
        .bind(tenant)
        .bind(operation)
        .bind(binding.device.into_uuid())
        .bind(&action.action)
        .bind(
            action
                .coordinates
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| Error::Malformed)?,
        )
        .bind(&action.recipient)
        .bind(action.reconciles)
        .execute(c)
        .await?;
    Ok(())
}
/// Internal platform use is separately authorized by the original operation owner.
pub async fn secret_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    keys: &KeyRing,
    coordinates: &Coordinates,
) -> Result<rss_mdm_native_protection::Plaintext, Error> {
    let profile = custody.profile();
    if coordinates.profile != profile {
        return Err(Error::Forbidden);
    }

    active_in(custody, c, coordinates.tenant, &coordinates.binding).await?;
    let r = locked_version(custody, c, coordinates).await?;
    keys.open(
        &r.try_get::<Option<String>, _>("key_id")?
            .ok_or(Error::NotFound)?,
        coordinates,
        &r.try_get::<Option<Vec<u8>>, _>("sealed")?
            .ok_or(Error::NotFound)?,
    )
}
pub async fn coordinates_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    device: &rss_mdm_agent_wire::DeviceId,
    id: Uuid,
    version: i64,
) -> Result<Coordinates, Error> {
    let profile = custody.profile();

    let r = sqlx::query(crate::storage_profile::sql(profile).storage_coordinates_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
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
        profile,
        tenant,
        material: id,
        binding: m.binding,
        version,
    })
}
/// Known terminal receipt ends recovery retention without asserting material validity.
pub async fn settled_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    coordinates: &Coordinates,
    operation: Uuid,
) -> Result<(), Error> {
    let profile = custody.profile();
    if coordinates.profile != profile {
        return Err(Error::Forbidden);
    }

    let r = locked_version(custody, c, coordinates).await?;
    if r.try_get::<Uuid, _>("operation")? != operation {
        return Err(Error::Conflict);
    }
    sqlx::query(crate::storage_profile::sql(profile).storage_settled_in_1)
        .bind(coordinates.tenant)
        .bind(coordinates.material)
        .bind(coordinates.version)
        .execute(c)
        .await?;
    Ok(())
}

/// Validate every retained key identity before serving the tenant, including the active key.
pub async fn validate_keys_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    keys: &KeyRing,
) -> Result<(), Error> {
    let profile = custody.profile();

    let rows = sqlx::query(crate::storage_profile::sql(profile).storage_validate_keys_in_1)
        .bind(tenant)
        .fetch_all(c)
        .await?;
    for r in rows {
        let m = decode(&r)?;
        let coordinates = Coordinates {
            profile,
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
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    keys: &KeyRing,
) -> Result<RewrapPage, Error> {
    let profile = custody.profile();

    let rows = sqlx::query(crate::storage_profile::sql(profile).storage_prepare_rewrap_in_1)
        .bind(tenant)
        .bind(keys.active())
        .fetch_all(&mut *c)
        .await?;
    Ok(RewrapPage { tenant, rows })
}
/// Re-encryption changes no material identity or validity; consume the page once.
pub async fn rewrap_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    page: RewrapPage,
    keys: &KeyRing,
) -> Result<u64, Error> {
    let profile = custody.profile();

    let RewrapPage { tenant, rows } = page;
    let count = rows.len() as u64;
    for r in rows {
        let m = decode(&r)?;
        let coordinates = Coordinates {
            profile,
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
        sqlx::query(crate::storage_profile::sql(profile).storage_rewrap_in_1)
            .bind(tenant)
            .bind(coordinates.material)
            .bind(coordinates.version)
            .bind(keys.active())
            .bind(sealed)
            .execute(&mut *c)
            .await?;
    }
    Ok(count)
}

/// The execution owner must scrub its terminal input copies before clearing these bytes.
pub async fn expired_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
) -> Result<Vec<Material>, Error> {
    let profile = custody.profile();

    sqlx::query(crate::storage_profile::sql(profile).storage_expired_in_1)
        .bind(tenant)
        .fetch_all(c)
        .await?
        .iter()
        .map(decode)
        .collect()
}
/// Created and consumed only by the bounded maintenance transaction.
pub(crate) struct RetentionPermit {
    profile: rss_mdm_install_support::StorageProfile,
    tenant: Uuid,
    id: Uuid,
    version: i64,
}
pub(crate) async fn retention_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    material: &Material,
    retention: Option<&dyn crate::eligibility::Retention>,
) -> Result<Option<RetentionPermit>, Error> {
    let profile = custody.profile();
    let row = sqlx::query(crate::storage_profile::sql(profile).retention_material)
        .bind(tenant)
        .bind(material.id)
        .bind(material.version)
        .fetch_optional(&mut *c)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let current: Option<i64> = row.try_get("current_version")?;
    let material = decode(&row)?;
    if matches!(material.binding.subject, Subject::RssLogin { .. })
        && current.is_none_or(|v| v == material.version)
    {
        let Some(retention) = retention else {
            return Ok(None);
        };
        if retention.storage_profile() != profile {
            return Err(Error::Forbidden);
        }
        if !retention.releasable(c, tenant, &material).await? {
            return Ok(None);
        }
    }
    Ok(Some(RetentionPermit {
        profile,
        tenant,
        id: material.id,
        version: material.version,
    }))
}
pub(crate) async fn clear_expired_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    permit: RetentionPermit,
) -> Result<(), Error> {
    let profile = custody.profile();
    if permit.profile != profile {
        return Err(Error::Forbidden);
    }
    sqlx::query(crate::storage_profile::sql(profile).storage_clear_expired_in_1)
        .bind(permit.tenant)
        .bind(permit.id)
        .bind(permit.version)
        .execute(c)
        .await?;
    Ok(())
}

pub async fn verify_existing_secret_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    keys: &KeyRing,
    tenant: Uuid,
    binding: &Binding,
    revision: i64,
    secret: &[u8],
) -> Result<Coordinates, Error> {
    let profile = custody.profile();

    active_in(custody, c, tenant, binding).await?;
    let subject = serde_json::to_value(&binding.subject).map_err(|_| Error::Malformed)?;
    let id = sqlx::query_scalar(
        crate::storage_profile::sql(profile).storage_verify_existing_secret_in_1,
    )
    .bind(tenant)
    .bind(binding.device.into_uuid())
    .bind(subject)
    .bind(revision)
    .fetch_optional(&mut *c)
    .await?
    .ok_or(Error::Conflict)?;
    let coordinates = Coordinates {
        profile,
        tenant,
        material: id,
        binding: binding.clone(),
        version: revision,
    };
    let current = secret_in(custody, c, keys, &coordinates).await?;
    if !bool::from(current.expose().ct_eq(secret)) {
        return Err(Error::Conflict);
    }
    Ok(coordinates)
}
pub async fn link_agent_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    task: Uuid,
    attempt: Uuid,
    coordinates: &Coordinates,
) -> Result<(), Error> {
    let profile = custody.profile();
    if coordinates.profile != profile {
        return Err(Error::Forbidden);
    }

    sqlx::query(crate::storage_profile::sql(profile).storage_link_agent_in_1)
        .bind(coordinates.tenant)
        .bind(task)
        .bind(attempt)
        .bind(coordinates.material)
        .bind(coordinates.version)
        .execute(&mut *c)
        .await?;
    let version: i64 =
        sqlx::query_scalar(crate::storage_profile::sql(profile).storage_link_agent_in_2)
            .bind(coordinates.tenant)
            .bind(task)
            .bind(attempt)
            .bind(coordinates.material)
            .fetch_one(c)
            .await?;
    if version != coordinates.version {
        return Err(Error::Conflict);
    }
    Ok(())
}
pub async fn agent_materials_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    task: Uuid,
    attempt: Uuid,
) -> Result<Vec<Material>, Error> {
    let profile = custody.profile();

    sqlx::query(crate::storage_profile::sql(profile).storage_agent_materials_in_1)
        .bind(tenant)
        .bind(task)
        .bind(attempt)
        .fetch_all(c)
        .await?
        .iter()
        .map(decode)
        .collect()
}
/// Only confirmed removal of the exact predecessor can invalidate another protector's material.
pub async fn supersede_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    binding: &Binding,
    revision: i64,
) -> Result<(), Error> {
    let profile = custody.profile();

    active_in(custody, c, tenant, binding).await?;
    let subject = serde_json::to_value(&binding.subject).map_err(|_| Error::Malformed)?;
    let row = sqlx::query(crate::storage_profile::sql(profile).storage_supersede_in_1)
        .bind(tenant)
        .bind(binding.device.into_uuid())
        .bind(subject)
        .fetch_optional(&mut *c)
        .await?;
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
    sqlx::query(crate::storage_profile::sql(profile).storage_supersede_in_2)
        .bind(tenant)
        .bind(id)
        .execute(&mut *c)
        .await?;
    sqlx::query(crate::storage_profile::sql(profile).storage_supersede_in_3)
        .bind(tenant)
        .bind(id)
        .execute(c)
        .await?;
    Ok(())
}

/// Serialize mutations across credential policies; an unknown outcome never expires this fence.
pub async fn start_agent_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    registration: rss_mdm_agent_wire::DeviceId,
    task: Uuid,
    attempt: Uuid,
) -> Result<(), Error> {
    let profile = custody.profile();

    sqlx::query(crate::storage_profile::sql(profile).storage_start_agent_in_1)
        .bind(tenant)
        .bind(registration.into_uuid())
        .bind(task)
        .bind(attempt)
        .execute(&mut *c)
        .await?;
    let matches: bool =
        sqlx::query_scalar(crate::storage_profile::sql(profile).storage_start_agent_in_2)
            .bind(tenant)
            .bind(registration.into_uuid())
            .bind(task)
            .bind(attempt)
            .fetch_one(c)
            .await?;
    if matches {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}
/// A successful independent verification can settle the original uncertain operation's fence.
pub async fn finish_agent_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    task: Uuid,
) -> Result<Option<Uuid>, Error> {
    let profile = custody.profile();

    sqlx::query_scalar(crate::storage_profile::sql(profile).storage_finish_agent_in_1)
        .bind(tenant)
        .bind(task)
        .fetch_optional(c)
        .await
        .map_err(Into::into)
}

/// Resolve the original immutable operation when an independent query confirms a candidate.
pub async fn source_operation_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    coordinates: &Coordinates,
) -> Result<Uuid, Error> {
    let profile = custody.profile();
    if coordinates.profile != profile {
        return Err(Error::Forbidden);
    }

    Ok(locked_version(custody, c, coordinates)
        .await?
        .try_get("operation")?)
}

/// A correlated native clear receipt removes the current pointer as well as disclosure eligibility.
pub async fn cleared_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    coordinates: &Coordinates,
) -> Result<(), Error> {
    let profile = custody.profile();
    if coordinates.profile != profile {
        return Err(Error::Forbidden);
    }

    active_in(custody, c, coordinates.tenant, &coordinates.binding).await?;
    locked_version(custody, c, coordinates).await?;
    let revision: i64 =
        sqlx::query_scalar(crate::storage_profile::sql(profile).storage_cleared_in_1)
            .bind(coordinates.tenant)
            .bind(coordinates.material)
            .fetch_one(&mut *c)
            .await?;
    if revision != coordinates.version {
        return Err(Error::Conflict);
    }
    sqlx::query(crate::storage_profile::sql(profile).storage_cleared_in_2)
        .bind(coordinates.tenant)
        .bind(coordinates.material)
        .execute(&mut *c)
        .await?;
    sqlx::query(crate::storage_profile::sql(profile).storage_cleared_in_3)
        .bind(coordinates.tenant)
        .bind(coordinates.material)
        .execute(c)
        .await?;
    Ok(())
}

/// Frozen object revisions for the current registration; consumers do not own this schema.
pub async fn revisions_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<Vec<(Subject, i64)>, Error> {
    let profile = custody.profile();

    let rows = sqlx::query(crate::storage_profile::sql(profile).storage_revisions_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .fetch_all(c)
        .await?;
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
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    coordinates: &Coordinates,
) -> Result<(), Error> {
    let profile = custody.profile();
    if coordinates.profile != profile {
        return Err(Error::Forbidden);
    }

    active_in(custody, c, coordinates.tenant, &coordinates.binding).await?;
    locked_version(custody, c, coordinates).await?;
    sqlx::query(crate::storage_profile::sql(profile).storage_uncertain_version_in_1)
        .bind(coordinates.tenant)
        .bind(coordinates.material)
        .bind(coordinates.version)
        .execute(c)
        .await?;
    Ok(())
}
/// Native input copies must be purged before any expired ciphertext for this registration.
pub async fn input_copies_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    registration: rss_mdm_agent_wire::DeviceId,
) -> Result<Vec<Uuid>, Error> {
    let profile = custody.profile();
    if profile != rss_mdm_install_support::StorageProfile::Mdm {
        return Err(Error::Unsupported);
    }

    Ok(
        sqlx::query_scalar(crate::storage_profile::sql(profile).storage_input_copies_in_1)
            .bind(tenant)
            .bind(registration.into_uuid())
            .fetch_all(c)
            .await?,
    )
}
pub async fn input_purged_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    operation: Uuid,
) -> Result<(), Error> {
    let profile = custody.profile();
    if profile != rss_mdm_install_support::StorageProfile::Mdm {
        return Err(Error::Unsupported);
    }

    sqlx::query(crate::storage_profile::sql(profile).storage_input_purged_in_1)
        .bind(tenant)
        .bind(operation)
        .execute(c)
        .await?;
    Ok(())
}
pub async fn inputs_remain_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    registration: rss_mdm_agent_wire::DeviceId,
) -> Result<bool, Error> {
    let profile = custody.profile();
    if profile != rss_mdm_install_support::StorageProfile::Mdm {
        return Err(Error::Unsupported);
    }

    Ok(
        sqlx::query_scalar(crate::storage_profile::sql(profile).storage_inputs_remain_in_1)
            .bind(tenant)
            .bind(registration.into_uuid())
            .fetch_one(c)
            .await?,
    )
}

/// Read the exact unresolved execution identity, including operations with no escrow yet.
pub async fn agent_guard_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    registration: rss_mdm_agent_wire::DeviceId,
) -> Result<Option<(Uuid, Uuid)>, Error> {
    let profile = custody.profile();

    sqlx::query(crate::storage_profile::sql(profile).storage_agent_guard_in_1)
        .bind(tenant)
        .bind(registration.into_uuid())
        .fetch_optional(c)
        .await?
        .map(|r| Ok((r.try_get("task")?, r.try_get("attempt")?)))
        .transpose()
}
/// After independent platform verification and original execution fencing, resolve a candidate
/// or restore the verified predecessor. Invalidated versions can never be resurrected.
pub async fn reconcile_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    coordinates: &Coordinates,
    original: Uuid,
) -> Result<(), Error> {
    let profile = custody.profile();
    if coordinates.profile != profile {
        return Err(Error::Forbidden);
    }

    active_in(custody, c, coordinates.tenant, &coordinates.binding).await?;
    let row = locked_version(custody, c, coordinates).await?;
    if row.try_get::<Option<Vec<u8>>, _>("sealed")?.is_none() {
        return Err(Error::Conflict);
    }
    let candidate: Option<Uuid> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).storage_reconcile_in_1)
            .bind(coordinates.tenant)
            .bind(coordinates.material)
            .fetch_optional(&mut *c)
            .await?;
    if candidate.is_some_and(|id| id != original) {
        return Err(Error::Conflict);
    }
    sqlx::query(crate::storage_profile::sql(profile).storage_reconcile_in_2)
        .bind(coordinates.tenant)
        .bind(coordinates.material)
        .bind(coordinates.version)
        .execute(&mut *c)
        .await?;
    sqlx::query(crate::storage_profile::sql(profile).storage_reconcile_in_3)
        .bind(coordinates.tenant)
        .bind(coordinates.material)
        .bind(coordinates.version)
        .execute(&mut *c)
        .await?;
    sqlx::query(crate::storage_profile::sql(profile).storage_reconcile_in_4)
        .bind(coordinates.tenant)
        .bind(coordinates.material)
        .bind(coordinates.version)
        .execute(c)
        .await?;
    Ok(())
}
/// An independent recovery query can receive a previously unreported candidate, or match a
/// retained predecessor. It cannot replace unrelated pending operations or overwrite ciphertext.
#[allow(
    clippy::too_many_arguments,
    reason = "credential authorization and persisted recovery identity remain explicit in the borrowed transaction"
)]
pub async fn recovery_secret_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    keys: &KeyRing,
    tenant: Uuid,
    binding: &Binding,
    revision: i64,
    original: Uuid,
    secret: &[u8],
) -> Result<Coordinates, Error> {
    let profile = custody.profile();

    active_in(custody, c, tenant, binding).await?;
    let revisions = revisions_in(custody, c, tenant, &binding.device).await?;
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
    let rows = sqlx::query(crate::storage_profile::sql(profile).storage_recovery_secret_in_1)
        .bind(tenant)
        .bind(binding.device.into_uuid())
        .bind(subject)
        .fetch_all(&mut *c)
        .await?;
    for r in rows {
        let m = decode(&r)?;
        let coordinates = Coordinates {
            profile,
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
    let coordinates = reserve_in(custody, c, tenant, binding, original, revision).await?;
    ingest_in(custody, c, keys, &coordinates, original, secret).await?;
    Ok(coordinates)
}

/// Fair bounded sweeps advance even when a live native command prevents destruction.
pub async fn cleanup_visited_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    id: Uuid,
    version: i64,
) -> Result<(), Error> {
    let profile = custody.profile();

    sqlx::query(crate::storage_profile::sql(profile).storage_cleanup_visited_in_1)
        .bind(tenant)
        .bind(id)
        .bind(version)
        .execute(c)
        .await?;
    Ok(())
}

/// Current verified/pending state for one exact subject; callers cannot select another device.
pub async fn current_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    binding: &Binding,
) -> Result<Option<Material>, Error> {
    let profile = custody.profile();

    active_in(custody, c, tenant, binding).await?;
    sqlx::query(crate::storage_profile::sql(profile).storage_current_in_1)
        .bind(tenant)
        .bind(binding.device.into_uuid())
        .bind(serde_json::to_value(&binding.subject).map_err(|_| Error::Malformed)?)
        .fetch_optional(c)
        .await?
        .as_ref()
        .map(decode)
        .transpose()
}

/// Start retention only after the current binding has a correlated native Unbound fact.
/// Unknown candidates retain their pending barrier; this does not alter generic settlement.
/// ref: vault-plugin-secrets-kv path_delete.go (persist invalidation before physical cleanup).
pub async fn access_unbound_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    unbound: &crate::eligibility::Unbound,
) -> Result<(), Error> {
    let profile = custody.profile();

    let crate::eligibility::Unbound {
        tenant,
        device,
        binding: id,
        generation,
    } = unbound;
    if tenant.is_nil() || id.is_nil() || *generation < 1 {
        return Err(Error::Malformed);
    }
    let entries: Vec<Uuid> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).storage_access_unbound_in_1)
            .bind(tenant)
            .bind(device.into_uuid())
            .bind(id.to_string())
            .bind(generation)
            .fetch_all(&mut *c)
            .await?;
    for entry in entries {
        sqlx::query(crate::storage_profile::sql(profile).storage_access_unbound_in_2)
            .bind(tenant)
            .bind(entry)
            .execute(&mut *c)
            .await?;
        sqlx::query(crate::storage_profile::sql(profile).storage_access_unbound_in_3)
            .bind(tenant)
            .bind(entry)
            .execute(&mut *c)
            .await?;
    }
    Ok(())
}

/// A correlated native response can deduplicate to an already escrowed version of the same PRK.
pub async fn replace_native_coordinates_in(
    custody: crate::Custody<'_>,
    c: &mut PgConnection,
    tenant: Uuid,
    operation: Uuid,
    value: &Coordinates,
) -> Result<(), Error> {
    let profile = custody.profile();
    if profile != rss_mdm_install_support::StorageProfile::Mdm {
        return Err(Error::Unsupported);
    }

    sqlx::query(crate::storage_profile::sql(profile).storage_replace_native_coordinates_in_1)
        .bind(tenant)
        .bind(operation)
        .bind(serde_json::to_value(value).map_err(|_| Error::Malformed)?)
        .execute(c)
        .await?;
    Ok(())
}

/// Validate product registration identities read from native PostgreSQL UUID columns.
pub(crate) fn device_id(
    id: uuid::Uuid,
) -> std::result::Result<rss_mdm_agent_wire::DeviceId, sqlx::Error> {
    rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}
pub(crate) fn device_ids(
    ids: Vec<uuid::Uuid>,
) -> std::result::Result<Vec<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    ids.into_iter().map(device_id).collect()
}
