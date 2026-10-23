//! Durable task-signing trust. Caller owns authorization, audit and the surrounding transaction.
use crate::Error;
use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rss_mdm_agent_wire::task_trust::{Acknowledgement, KeyState, PublicKey, Trust};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub const INSTALL_SQL: &str = include_str!("trust.sql");
fn db(_: sqlx::Error) -> Error {
    Error::Unavailable(crate::Failure::Database)
}
fn aad(tenant: TenantId, key: &str) -> Result<DerivedAad, Error> {
    ProtectionContext::new(tenant, key, "task-signing.private-key", 1)
        .map(|c| c.derive())
        .map_err(|_| Error::Malformed)
}
fn request_aad(tenant: TenantId, operation: Uuid) -> Result<DerivedAad, Error> {
    ProtectionContext::new(tenant, &operation.to_string(), "task-signing.operation", 1)
        .map(|c| c.derive())
        .map_err(|_| Error::Malformed)
}
async fn lock(c: &mut PgConnection, tenant: TenantId) -> Result<i64, Error> {
    sqlx::query("INSERT INTO mdm_task_signing.heads(tenant_id,revision) VALUES($1::uuid,0) ON CONFLICT DO NOTHING").bind(tenant.to_string()).execute(&mut *c).await.map_err(db)?;
    sqlx::query_scalar(
        "SELECT revision FROM mdm_task_signing.heads WHERE tenant_id=$1::uuid FOR UPDATE",
    )
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
pub async fn current(c: &mut PgConnection, tenant: TenantId) -> Result<Trust, Error> {
    let (body, revision, digest): (serde_json::Value,i64,String) = sqlx::query_as("SELECT v.body,v.revision,v.digest FROM mdm_task_signing.versions v JOIN mdm_task_signing.heads h USING(tenant_id,revision) WHERE tenant_id=$1::uuid")
        .bind(tenant.to_string()).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::NotFound)?;
    let service = installation_service(c).await?;
    stored_trust(body, revision, &digest, tenant, service)
}
async fn installation_service(c: &mut PgConnection) -> Result<Uuid, Error> {
    sqlx::query_scalar("SELECT instance_id FROM public.mdm_installation")
        .fetch_one(c)
        .await
        .map_err(db)
}
async fn replay(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    protection: &Protector,
    request: &[u8],
) -> Result<Option<Trust>, Error> {
    let row=sqlx::query("SELECT body,fingerprint_key,fingerprint FROM mdm_task_signing.versions WHERE tenant_id=$1::uuid AND operation_id=$2").bind(tenant.to_string()).bind(operation).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    protection
        .verify_mac_with_key(
            &row.try_get::<String, _>("fingerprint_key").map_err(db)?,
            request,
            &request_aad(tenant, operation)?,
            &row.try_get::<Vec<u8>, _>("fingerprint").map_err(db)?,
        )
        .map_err(|_| Error::Conflict)?;
    let value: Trust =
        serde_json::from_value(row.try_get("body").map_err(db)?).map_err(|_| Error::Conflict)?;
    value.validate().map_err(|_| Error::Conflict)?;
    if value.service_id != installation_service(c).await?
        || value.tenant.to_string() != tenant.to_string()
    {
        return Err(Error::Conflict);
    }
    Ok(Some(value))
}
async fn save(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    protection: &Protector,
    request: &[u8],
    trust: &Trust,
) -> Result<(), Error> {
    let digest = trust.installation_digest().map_err(|_| Error::Malformed)?;
    let tag = protection
        .mac(request, &request_aad(tenant, operation)?)
        .map_err(|_| Error::Conflict)?;
    sqlx::query("INSERT INTO mdm_task_signing.versions(tenant_id,revision,operation_id,fingerprint_key,fingerprint,body,digest) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)")
        .bind(tenant.to_string()).bind(trust.revision as i64).bind(operation).bind(protection.fingerprint_id()).bind(tag.as_slice()).bind(serde_json::to_value(trust).map_err(|_|Error::Malformed)?).bind(digest).execute(&mut *c).await.map_err(db)?;
    sqlx::query("UPDATE mdm_task_signing.heads SET revision=$2 WHERE tenant_id=$1::uuid")
        .bind(tenant.to_string())
        .bind(trust.revision as i64)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
/// First key requires no enrolled Agents; successors are distributed as Prepared, never active.
#[allow(clippy::too_many_arguments)]
pub async fn prepare(
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
    let revision = lock(c, tenant).await?;
    if let Some(previous) = replay(c, tenant, operation, protection, &request).await? {
        return Ok(previous);
    }
    if revision != expected {
        return Err(Error::Conflict);
    }
    let mut trust = if revision == 0 {
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND channel='agent' AND state='active'").bind(tenant.to_string()).fetch_one(&mut *c).await.map_err(db)?;
        if count != 0 {
            return Err(Error::Conflict);
        }
        Trust {
            version: 1,
            tenant: Uuid::parse_str(&tenant.to_string()).map_err(|_| Error::Malformed)?,
            service_id: sqlx::query_scalar::<_, Uuid>(
                "SELECT instance_id FROM public.mdm_installation",
            )
            .fetch_one(&mut *c)
            .await
            .map_err(db)?,
            revision: 1,
            keys: vec![],
        }
    } else {
        let mut previous = current(c, tenant).await?;
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
        .seal_bytes(private.as_ref(), &aad(tenant, &id)?)
        .map_err(|_| Error::Conflict)?;
    sqlx::query(
        "INSERT INTO mdm_task_signing.keys(tenant_id,key_id,private_key) VALUES($1::uuid,$2,$3)",
    )
    .bind(tenant.to_string())
    .bind(id)
    .bind(sealed)
    .execute(&mut *c)
    .await
    .map_err(db)?;
    save(c, tenant, operation, protection, &request, &trust).await?;
    Ok(trust)
}
/// Activation proves every currently enrolled Agent has durably acknowledged the prepared key set.
#[allow(clippy::too_many_arguments)]
pub async fn activate(
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
    let revision = lock(c, tenant).await?;
    if let Some(previous) = replay(c, tenant, operation, protection, &request).await? {
        return Ok(previous);
    }
    if revision != expected {
        return Err(Error::Conflict);
    }
    let mut trust = current(c, tenant).await?;
    if !trust
        .keys
        .iter()
        .any(|k| k.id == key_id && k.state == KeyState::Prepared)
    {
        return Err(Error::Conflict);
    }
    let missing:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.channel='agent' AND r.state='active' AND NOT EXISTS(SELECT 1 FROM mdm_task_signing.acknowledgements a JOIN mdm_task_signing.versions v USING(tenant_id,revision) WHERE a.tenant_id=r.tenant_id AND a.registration=r.id AND a.generation=r.generation AND a.digest=v.digest AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.body->'keys') k WHERE k->>'id'=$2 AND k->>'state'='prepared')))")
        .bind(tenant.to_string()).bind(key_id).fetch_one(&mut *c).await.map_err(db)?;
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
    save(c, tenant, operation, protection, &request, &trust).await?;
    Ok(trust)
}

/// The caller authenticates mTLS and settles this acknowledgement in its audited transaction.
pub async fn acknowledge(
    c: &mut PgConnection,
    p: &crate::device::DevicePrincipal,
    input: &Acknowledgement,
) -> Result<(), Error> {
    input.validate().map_err(|_| Error::Malformed)?;
    if input.registration != p.registration() || input.generation != p.generation() as u64 {
        return Err(Error::Forbidden);
    }
    lock(c, p.tenant()).await?;
    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 AND generation=$3 AND channel='agent' AND state='active')")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).fetch_one(&mut *c).await.map_err(db)?;
    if !active {
        return Err(Error::Forbidden);
    }
    let digest: Option<String> = sqlx::query_scalar(
        "SELECT digest FROM mdm_task_signing.versions WHERE tenant_id=$1::uuid AND revision=$2",
    )
    .bind(p.tenant().to_string())
    .bind(input.revision as i64)
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?;
    if digest.as_deref() != Some(input.digest.as_str()) {
        return Err(Error::Conflict);
    }
    sqlx::query("INSERT INTO mdm_task_signing.acknowledgements(tenant_id,operation_id,registration,generation,revision,digest) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
        .bind(p.tenant().to_string()).bind(input.operation).bind(p.registration()).bind(p.generation()).bind(input.revision as i64).bind(&input.digest).execute(&mut *c).await.map_err(db)?;
    let same:bool=sqlx::query_scalar("SELECT registration=$3 AND generation=$4 AND revision=$5 AND digest=$6 FROM mdm_task_signing.acknowledgements WHERE tenant_id=$1::uuid AND operation_id=$2")
        .bind(p.tenant().to_string()).bind(input.operation).bind(p.registration()).bind(p.generation()).bind(input.revision as i64).bind(&input.digest).fetch_one(c).await.map_err(db)?;
    if !same {
        return Err(Error::Conflict);
    }
    Ok(())
}
/// An Agent that enrolled during rotation also needs the exact key in a durable acknowledgement.
pub async fn require_issue(
    c: &mut PgConnection,
    p: &crate::device::DevicePrincipal,
    key_id: &str,
) -> Result<(), Error> {
    let trust = current(c, p.tenant()).await?;
    if !trust
        .keys
        .iter()
        .any(|k| k.id == key_id && k.state == KeyState::Active)
    {
        return Err(Error::Conflict);
    }
    let installed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_task_signing.acknowledgements a JOIN mdm_task_signing.versions v USING(tenant_id,revision) WHERE a.tenant_id=$1::uuid AND a.registration=$2 AND a.generation=$3 AND a.digest=v.digest AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.body->'keys') k WHERE k->>'id'=$4 AND k->>'state' IN('prepared','active')))")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(key_id).fetch_one(c).await.map_err(db)?;
    if !installed {
        return Err(Error::Forbidden);
    }
    Ok(())
}
pub struct Loaded {
    pub task: super::Signer,
}
/// Load an exact published revision only while its signer remains active in the current authority.
/// Preparing a successor does not invalidate a still-active signer on restart.
pub async fn load(
    c: &mut PgConnection,
    tenant: TenantId,
    revision: u64,
    protection: &Protector,
) -> Result<Loaded, Error> {
    let trust = selected_trust(c, tenant, revision).await?;
    let active = trust
        .keys
        .iter()
        .find(|k| k.state == KeyState::Active)
        .ok_or(Error::Conflict)?;
    let sealed: Vec<u8> = sqlx::query_scalar(
        "SELECT private_key FROM mdm_task_signing.keys WHERE tenant_id=$1::uuid AND key_id=$2",
    )
    .bind(tenant.to_string())
    .bind(&active.id)
    .fetch_one(c)
    .await
    .map_err(db)?;
    let private = protection
        .open_bytes(&sealed, &aad(tenant, &active.id)?)
        .map_err(|_| Error::Unavailable(crate::Failure::CommandInvariant))?;
    let keys = trust
        .keys
        .iter()
        .map(|key| (key.id.clone(), key.public_key.clone()))
        .collect();
    Ok(Loaded {
        task: super::Signer::from_bytes(private.expose(), &active.id, &keys)
            .map_err(|_| Error::Unavailable(crate::Failure::CommandInvariant))?,
    })
}

async fn selected_trust(
    c: &mut PgConnection,
    tenant: TenantId,
    revision: u64,
) -> Result<Trust, Error> {
    let current = current(c, tenant).await?;
    let (body, stored_revision, digest): (serde_json::Value,i64,String) = sqlx::query_as(
        "SELECT body,revision,digest FROM mdm_task_signing.versions WHERE tenant_id=$1::uuid AND revision=$2",
    )
    .bind(tenant.to_string())
    .bind(i64::try_from(revision).map_err(|_| Error::Malformed)?)
    .fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Conflict)?;
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
    c: &mut PgConnection,
    tenant: TenantId,
    revision: u64,
) -> Result<(), Error> {
    selected_trust(c, tenant, revision).await.map(|_| ())
}

pub async fn operation(c: &mut PgConnection, tenant: TenantId, id: Uuid) -> Result<Trust, Error> {
    let body: serde_json::Value = sqlx::query_scalar(
        "SELECT body FROM mdm_task_signing.versions WHERE tenant_id=$1::uuid AND operation_id=$2",
    )
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
    c: &mut PgConnection,
    tenant: TenantId,
    key_id: &str,
) -> Result<(), Error> {
    let trust = current(c, tenant).await?;
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
pub async fn retire(
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
        serde_json::to_vec(&("retire", expected, key_id, actor)).map_err(|_| Error::Malformed)?;
    let revision = lock(c, tenant).await?;
    if let Some(previous) = replay(c, tenant, operation, protection, &request).await? {
        return Ok(previous);
    }
    if revision != expected {
        return Err(Error::Conflict);
    }
    let mut trust = current(c, tenant).await?;
    let key = trust
        .keys
        .iter()
        .find(|k| k.id == key_id)
        .ok_or(Error::Conflict)?;
    if key.state == KeyState::Active {
        return Err(Error::Conflict);
    }
    if key.state == KeyState::VerifyOnly {
        let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_attempts a JOIN mdm_commands.action_runs r ON (r.tenant_id,r.id)=(a.tenant_id,a.run) WHERE a.tenant_id=$1::uuid AND r.deadline>extract(epoch FROM clock_timestamp()) AND (a.offer->>'keyId'=$2 OR a.permit->>'keyId'=$2))")
            .bind(tenant.to_string()).bind(key_id).fetch_one(&mut *c).await.map_err(db)?;
        if pending {
            return Err(Error::Conflict);
        }
        let missing:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.channel='agent' AND r.state='active' AND NOT EXISTS(SELECT 1 FROM mdm_task_signing.acknowledgements a JOIN mdm_task_signing.versions v USING(tenant_id,revision) WHERE a.tenant_id=r.tenant_id AND a.registration=r.id AND a.generation=r.generation AND a.digest=v.digest AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.body->'keys') k WHERE k->>'id'=$2 AND k->>'state'='verify_only')))")
            .bind(tenant.to_string()).bind(key_id).fetch_one(&mut *c).await.map_err(db)?;
        if missing {
            return Err(Error::Conflict);
        }
    }
    trust.keys.retain(|key| key.id != key_id);
    trust.revision += 1;
    save(c, tenant, operation, protection, &request, &trust).await?;
    Ok(trust)
}

/// 重加密保留任务签名身份、信任历史和 ACK，不创建新的签名钥。
pub async fn rewrap(
    c: &mut PgConnection,
    tenant: TenantId,
    protection: &Protector,
) -> Result<u64, Error> {
    let prefix = protection.ciphertext_prefix();
    let rows=sqlx::query("SELECT key_id,private_key FROM mdm_task_signing.keys WHERE tenant_id=$1::uuid AND substring(private_key FROM 1 FOR $2)<>$3 ORDER BY key_id LIMIT 64 FOR UPDATE").bind(tenant.to_string()).bind(prefix.len() as i32).bind(prefix).fetch_all(&mut *c).await.map_err(db)?;
    for row in &rows {
        let id: String = row.try_get("key_id").map_err(db)?;
        let sealed: Vec<u8> = row.try_get("private_key").map_err(db)?;
        let next = protection
            .rewrap_bytes(&sealed, &aad(tenant, &id)?)
            .map_err(|_| Error::Conflict)?;
        sqlx::query("UPDATE mdm_task_signing.keys SET private_key=$3 WHERE tenant_id=$1::uuid AND key_id=$2").bind(tenant.to_string()).bind(id).bind(next).execute(&mut *c).await.map_err(db)?;
    }
    Ok(rows.len() as u64)
}
