//! Durable task-signing trust. Caller owns authorization, audit and the surrounding transaction.
use crate::Error;
use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rss_mdm_agent_wire::task_trust::{Acknowledgement, KeyState, PublicKey, Trust};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub const fn install_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    crate::storage_profile::sql(profile).install
}
fn db(_: sqlx::Error) -> Error {
    Error::Unavailable(crate::Failure::Database)
}
fn aad(
    profile: rss_mdm_install_support::StorageProfile,
    tenant: TenantId,
    key: &str,
) -> Result<DerivedAad, Error> {
    ProtectionContext::new(
        tenant,
        &match profile {
            rss_mdm_install_support::StorageProfile::Mdm => key.to_owned(),
            rss_mdm_install_support::StorageProfile::Da => format!("da:{key}"),
        },
        "task-signing.private-key",
        1,
    )
    .map(|c| c.derive())
    .map_err(|_| Error::Malformed)
}
fn request_aad(
    profile: rss_mdm_install_support::StorageProfile,
    tenant: TenantId,
    operation: Uuid,
) -> Result<DerivedAad, Error> {
    ProtectionContext::new(
        tenant,
        &match profile {
            rss_mdm_install_support::StorageProfile::Mdm => operation.to_string(),
            rss_mdm_install_support::StorageProfile::Da => format!("da:{operation}"),
        },
        "task-signing.operation",
        1,
    )
    .map(|c| c.derive())
    .map_err(|_| Error::Malformed)
}
async fn lock(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
) -> Result<i64, Error> {
    sqlx::query(crate::storage_profile::sql(profile).trust_lock_1)
        .bind(tenant.to_string())
        .execute(&mut *c)
        .await
        .map_err(db)?;
    sqlx::query_scalar(crate::storage_profile::sql(profile).trust_lock_2)
        .bind(tenant.to_string())
        .fetch_one(c)
        .await
        .map_err(db)
}
fn stored_trust(
    body: serde_json::Value,
    revision: i64,
    digest: &str,
    tenant: TenantId,
    service: Uuid,
) -> Result<Trust, Error> {
    let invalid = || Error::Unavailable(crate::Failure::CommandInvariant);
    let trust: Trust = serde_json::from_value(body).map_err(|_| invalid())?;
    trust.validate().map_err(|_| invalid())?;
    if trust.service_id != service
        || trust.tenant.to_string() != tenant.to_string()
        || trust.revision != u64::try_from(revision).map_err(|_| invalid())?
        || trust.installation_digest().map_err(|_| invalid())? != digest
    {
        return Err(invalid());
    }
    Ok(trust)
}
pub async fn current(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
) -> Result<Trust, Error> {
    let (body, revision, digest): (serde_json::Value, i64, String) =
        sqlx::query_as(crate::storage_profile::sql(profile).trust_current_1)
            .bind(tenant.to_string())
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?
            .ok_or(Error::NotFound)?;
    let service = installation_service(profile, c).await?;
    stored_trust(body, revision, &digest, tenant, service)
}
async fn installation_service(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
) -> Result<Uuid, Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).trust_installation_service_1)
        .fetch_one(c)
        .await
        .map_err(db)
}
async fn replay(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    protection: &Protector,
    request: &[u8],
) -> Result<Option<Trust>, Error> {
    let row = sqlx::query(crate::storage_profile::sql(profile).trust_replay_1)
        .bind(tenant.to_string())
        .bind(operation)
        .fetch_optional(&mut *c)
        .await
        .map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    protection
        .verify_mac_with_key(
            &row.try_get::<String, _>("fingerprint_key").map_err(db)?,
            request,
            &request_aad(profile, tenant, operation)?,
            &row.try_get::<Vec<u8>, _>("fingerprint").map_err(db)?,
        )
        .map_err(|_| Error::Conflict)?;
    let value: Trust =
        serde_json::from_value(row.try_get("body").map_err(db)?).map_err(|_| Error::Conflict)?;
    value.validate().map_err(|_| Error::Conflict)?;
    if value.service_id != installation_service(profile, c).await?
        || value.tenant.to_string() != tenant.to_string()
    {
        return Err(Error::Conflict);
    }
    Ok(Some(value))
}
async fn save(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    protection: &Protector,
    request: &[u8],
    trust: &Trust,
) -> Result<(), Error> {
    let digest = trust.installation_digest().map_err(|_| Error::Malformed)?;
    let tag = protection
        .mac(request, &request_aad(profile, tenant, operation)?)
        .map_err(|_| Error::Conflict)?;
    sqlx::query(crate::storage_profile::sql(profile).trust_save_1)
        .bind(tenant.to_string())
        .bind(trust.revision as i64)
        .bind(operation)
        .bind(protection.fingerprint_id())
        .bind(tag.as_slice())
        .bind(serde_json::to_value(trust).map_err(|_| Error::Malformed)?)
        .bind(digest)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    sqlx::query(crate::storage_profile::sql(profile).trust_save_2)
        .bind(tenant.to_string())
        .bind(trust.revision as i64)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
/// First key requires no enrolled Agents; successors are distributed as Prepared, never active.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    expected: i64,
    protection: &Protector,
    actor: &str,
) -> Result<Trust, Error> {
    if expected < 0 || expected == i64::MAX || operation.is_nil() {
        return Err(Error::Malformed);
    }
    let request =
        serde_json::to_vec(&("prepare", expected, actor)).map_err(|_| Error::Malformed)?;
    let revision = lock(profile, c, tenant).await?;
    if let Some(previous) = replay(profile, c, tenant, operation, protection, &request).await? {
        return Ok(previous);
    }
    if revision != expected {
        return Err(Error::Conflict);
    }
    let mut trust = if revision == 0 {
        let count: i64 = sqlx::query_scalar(crate::storage_profile::sql(profile).trust_prepare_1)
            .bind(tenant.to_string())
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
        if count != 0 {
            return Err(Error::Conflict);
        }
        Trust {
            version: 1,
            tenant: Uuid::parse_str(&tenant.to_string()).map_err(|_| Error::Malformed)?,
            service_id: sqlx::query_scalar::<_, Uuid>(
                crate::storage_profile::sql(profile).trust_prepare_2,
            )
            .fetch_one(&mut *c)
            .await
            .map_err(db)?,
            revision: 1,
            keys: vec![],
        }
    } else {
        let mut previous = current(profile, c, tenant).await?;
        if previous.keys.len() >= 16 {
            return Err(Error::Conflict);
        }
        previous.revision += 1;
        previous
    };
    let private = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| Error::Conflict)?;
    let key = Ed25519KeyPair::from_pkcs8(private.as_ref()).map_err(|_| Error::Conflict)?;
    let id = Uuid::new_v4().to_string();
    trust.keys.push(PublicKey {
        id: id.clone(),
        public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(key.public_key().as_ref()),
        state: if revision == 0 {
            KeyState::Active
        } else {
            KeyState::Prepared
        },
    });
    trust.keys.sort_by(|a, b| a.id.cmp(&b.id));
    trust.validate().map_err(|_| Error::Malformed)?;
    let sealed = protection
        .seal_bytes(private.as_ref(), &aad(profile, tenant, &id)?)
        .map_err(|_| Error::Conflict)?;
    sqlx::query(crate::storage_profile::sql(profile).trust_prepare_3)
        .bind(tenant.to_string())
        .bind(id)
        .bind(sealed)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    save(profile, c, tenant, operation, protection, &request, &trust).await?;
    Ok(trust)
}
/// Activation proves every currently enrolled Agent has durably acknowledged the prepared key set.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn activate(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    expected: i64,
    key_id: &str,
    protection: &Protector,
    actor: &str,
) -> Result<Trust, Error> {
    if expected < 1 || expected == i64::MAX || operation.is_nil() {
        return Err(Error::Malformed);
    }
    let request =
        serde_json::to_vec(&("activate", expected, key_id, actor)).map_err(|_| Error::Malformed)?;
    let revision = lock(profile, c, tenant).await?;
    if let Some(previous) = replay(profile, c, tenant, operation, protection, &request).await? {
        return Ok(previous);
    }
    if revision != expected {
        return Err(Error::Conflict);
    }
    let mut trust = current(profile, c, tenant).await?;
    if !trust
        .keys
        .iter()
        .any(|k| k.id == key_id && k.state == KeyState::Prepared)
    {
        return Err(Error::Conflict);
    }
    let missing: bool = sqlx::query_scalar(crate::storage_profile::sql(profile).trust_activate_1)
        .bind(tenant.to_string())
        .bind(key_id)
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;
    if missing {
        return Err(Error::Conflict);
    }
    for key in &mut trust.keys {
        if key.id == key_id {
            key.state = KeyState::Active
        } else if key.state == KeyState::Active {
            key.state = KeyState::VerifyOnly
        }
    }
    trust.revision += 1;
    save(profile, c, tenant, operation, protection, &request, &trust).await?;
    Ok(trust)
}

/// The caller authenticates mTLS and settles this acknowledgement in its audited transaction.
pub(crate) async fn acknowledge(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    p: &rss_mdm_registration_service::device::DevicePrincipal,
    input: &Acknowledgement,
) -> Result<(), Error> {
    input.validate().map_err(|_| Error::Malformed)?;
    if input.registration != p.registration() || input.generation != p.generation() as u64 {
        return Err(Error::Forbidden);
    }
    lock(profile, c, p.tenant()).await?;
    let active: bool = sqlx::query_scalar(crate::storage_profile::sql(profile).trust_acknowledge_1)
        .bind(p.tenant().to_string())
        .bind(p.registration())
        .bind(p.generation())
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;
    if !active {
        return Err(Error::Forbidden);
    }
    let digest: Option<String> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).trust_acknowledge_2)
            .bind(p.tenant().to_string())
            .bind(input.revision as i64)
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?;
    if digest.as_deref() != Some(input.digest.as_str()) {
        return Err(Error::Conflict);
    }
    sqlx::query(crate::storage_profile::sql(profile).trust_acknowledge_3)
        .bind(p.tenant().to_string())
        .bind(input.operation)
        .bind(p.registration())
        .bind(p.generation())
        .bind(input.revision as i64)
        .bind(&input.digest)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    let same: bool = sqlx::query_scalar(crate::storage_profile::sql(profile).trust_acknowledge_4)
        .bind(p.tenant().to_string())
        .bind(input.operation)
        .bind(p.registration())
        .bind(p.generation())
        .bind(input.revision as i64)
        .bind(&input.digest)
        .fetch_one(c)
        .await
        .map_err(db)?;
    if !same {
        return Err(Error::Conflict);
    }
    Ok(())
}
/// An Agent that enrolled during rotation also needs the exact key in a durable acknowledgement.
pub(crate) async fn require_issue(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    p: &rss_mdm_registration_service::device::DevicePrincipal,
    key_id: &str,
) -> Result<(), Error> {
    let trust = current(profile, c, p.tenant()).await?;
    if !trust
        .keys
        .iter()
        .any(|k| k.id == key_id && k.state == KeyState::Active)
    {
        return Err(Error::Conflict);
    }
    let installed: bool =
        sqlx::query_scalar(crate::storage_profile::sql(profile).trust_require_issue_1)
            .bind(p.tenant().to_string())
            .bind(p.registration())
            .bind(p.generation())
            .bind(key_id)
            .fetch_one(c)
            .await
            .map_err(db)?;
    if !installed {
        return Err(Error::Forbidden);
    }
    Ok(())
}
pub struct Loaded {
    pub(crate) profile: rss_mdm_install_support::StorageProfile,
    pub(crate) tenant: TenantId,
    pub(crate) task: crate::signing::Signer,
}
/// Load an exact published revision only while its signer remains active in the current authority.
/// Preparing a successor does not invalidate a still-active signer on restart.
pub async fn load(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    revision: u64,
    protection: &Protector,
) -> Result<Loaded, Error> {
    let trust = selected_trust(profile, c, tenant, revision).await?;
    let active = trust
        .keys
        .iter()
        .find(|k| k.state == KeyState::Active)
        .ok_or(Error::Conflict)?;
    let sealed: Vec<u8> = sqlx::query_scalar(crate::storage_profile::sql(profile).trust_load_1)
        .bind(tenant.to_string())
        .bind(&active.id)
        .fetch_one(c)
        .await
        .map_err(db)?;
    let private = protection
        .open_bytes(&sealed, &aad(profile, tenant, &active.id)?)
        .map_err(|_| Error::Unavailable(crate::Failure::CommandInvariant))?;
    let keys = trust
        .keys
        .iter()
        .map(|key| (key.id.clone(), key.public_key.clone()))
        .collect();
    Ok(Loaded {
        profile,
        tenant,
        task: crate::signing::Signer::from_bytes(private.expose(), &active.id, &keys)
            .map_err(|_| Error::Unavailable(crate::Failure::CommandInvariant))?,
    })
}

async fn selected_trust(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    revision: u64,
) -> Result<Trust, Error> {
    let current = current(profile, c, tenant).await?;
    let (body, stored_revision, digest): (serde_json::Value, i64, String) =
        sqlx::query_as(crate::storage_profile::sql(profile).trust_selected_trust_1)
            .bind(tenant.to_string())
            .bind(i64::try_from(revision).map_err(|_| Error::Malformed)?)
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?
            .ok_or(Error::Conflict)?;
    let trust = stored_trust(body, stored_revision, &digest, tenant, current.service_id)?;
    let active = trust
        .keys
        .iter()
        .find(|k| k.state == KeyState::Active)
        .ok_or(Error::Conflict)?;
    if !current.keys.iter().any(|k| {
        k.id == active.id && k.public_key == active.public_key && k.state == KeyState::Active
    }) {
        return Err(Error::Conflict);
    }
    Ok(trust)
}
/// Check the loaded revision against the current authority without decrypting private material.
pub async fn check_revision(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    revision: u64,
) -> Result<(), Error> {
    selected_trust(profile, c, tenant, revision)
        .await
        .map(|_| ())
}

pub async fn operation(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<Trust, Error> {
    let body: serde_json::Value =
        sqlx::query_scalar(crate::storage_profile::sql(profile).trust_operation_1)
            .bind(tenant.to_string())
            .bind(id)
            .fetch_optional(c)
            .await
            .map_err(db)?
            .ok_or(Error::NotFound)?;
    let trust: Trust = serde_json::from_value(body).map_err(|_| Error::Conflict)?;
    trust.validate().map_err(|_| Error::Conflict)?;
    Ok(trust)
}

pub async fn require_active_key(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    key_id: &str,
) -> Result<(), Error> {
    let trust = current(profile, c, tenant).await?;
    if trust
        .keys
        .iter()
        .any(|k| k.id == key_id && k.state == KeyState::Active)
    {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}
/// Retain immutable public history and protected private material for backup recovery.
/// Exit the current set only after pending signatures expire and peers know the key is verify-only.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn retire(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    expected: i64,
    key_id: &str,
    protection: &Protector,
    actor: &str,
    guard: &dyn crate::RetirementGuard,
) -> Result<Trust, Error> {
    if expected < 1 || expected == i64::MAX || operation.is_nil() {
        return Err(Error::Malformed);
    }
    let request =
        serde_json::to_vec(&("retire", expected, key_id, actor)).map_err(|_| Error::Malformed)?;
    let revision = lock(profile, c, tenant).await?;
    if let Some(previous) = replay(profile, c, tenant, operation, protection, &request).await? {
        return Ok(previous);
    }
    if revision != expected {
        return Err(Error::Conflict);
    }
    let mut trust = current(profile, c, tenant).await?;
    let key = trust
        .keys
        .iter()
        .find(|k| k.id == key_id)
        .ok_or(Error::Conflict)?;
    if key.state == KeyState::Active {
        return Err(Error::Conflict);
    }
    if key.state == KeyState::VerifyOnly {
        let pending = guard.pending(c, tenant, key_id).await?;
        if pending {
            return Err(Error::Conflict);
        }
        let missing: bool = sqlx::query_scalar(crate::storage_profile::sql(profile).trust_retire_1)
            .bind(tenant.to_string())
            .bind(key_id)
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
        if missing {
            return Err(Error::Conflict);
        }
    }
    trust.keys.retain(|key| key.id != key_id);
    trust.revision += 1;
    save(profile, c, tenant, operation, protection, &request, &trust).await?;
    Ok(trust)
}

/// 重加密保留任务签名身份、信任历史和 ACK，不创建新的签名钥。
pub async fn rewrap(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: TenantId,
    protection: &Protector,
) -> Result<u64, Error> {
    let prefix = protection.ciphertext_prefix();
    let rows = sqlx::query(crate::storage_profile::sql(profile).trust_rewrap_1)
        .bind(tenant.to_string())
        .bind(prefix.len() as i32)
        .bind(prefix)
        .fetch_all(&mut *c)
        .await
        .map_err(db)?;
    for row in &rows {
        let id: String = row.try_get("key_id").map_err(db)?;
        let sealed: Vec<u8> = row.try_get("private_key").map_err(db)?;
        let next = protection
            .rewrap_bytes(&sealed, &aad(profile, tenant, &id)?)
            .map_err(|_| Error::Conflict)?;
        sqlx::query(crate::storage_profile::sql(profile).trust_rewrap_2)
            .bind(tenant.to_string())
            .bind(id)
            .bind(next)
            .execute(&mut *c)
            .await
            .map_err(db)?;
    }
    Ok(rows.len() as u64)
}
