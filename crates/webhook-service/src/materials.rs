//! Typed outgoing signing material; subscriptions and delivery recovery retain their owners.
use crate::Error;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
use zeroize::Zeroizing;
pub const INSTALL_SQL: &str = include_str!("../schema/materials.sql");
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Generate,
    Import {
        #[schemars(with = "String")]
        secret: Zeroizing<String>,
    },
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepare {
    pub reference: String,
    pub expected_revision: i64,
    pub configuration_sha256: String,
    pub endpoint: String,
    pub network_reference: String,
    pub source: Source,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Action {
    Activate { material_revision: i64 },
    Revoke { material_revision: i64 },
    RetirePrevious,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Transition {
    pub reference: String,
    pub expected_revision: i64,
    pub action: Action,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Material {
    pub operation_id: Uuid,
    pub reference: String,
    pub revision: i64,
    pub configuration_sha256: String,
    pub key_digest: String,
    pub challenge: String,
    pub confirmed: bool,
    pub revoked: bool,
    pub endpoint: Option<String>,
    pub network_reference: Option<String>,
    pub attempted_at: Option<i64>,
    pub confirmed_at: Option<i64>,
    pub failure_reason: Option<String>,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub reference: String,
    pub revision: i64,
    pub active_revision: Option<i64>,
    pub retiring_revision: Option<i64>,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub heads: Vec<Head>,
    pub materials: Vec<Material>,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Head {
    pub reference: String,
    pub revision: i64,
    pub active_revision: Option<i64>,
    pub retiring_revision: Option<i64>,
}
fn context(tenant: Uuid, reference: &str, revision: i64) -> Result<DerivedAad, Error> {
    ProtectionContext::new(
        rss_request_context::TenantId::parse(&tenant.to_string()).map_err(|_| Error::Invalid)?,
        &format!("{reference}:{revision}"),
        "webhook.signing-key",
        1,
    )
    .map(|c| c.derive())
    .map_err(|_| Error::Invalid)
}
fn reference(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn decode(secret: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    crate::transport::SigningKey::from_encoded(secret).map_err(|_| Error::Invalid)?;
    STANDARD
        .decode(secret.strip_prefix("whsec_").ok_or(Error::Invalid)?)
        .map(Zeroizing::new)
        .map_err(|_| Error::Invalid)
}
fn random() -> Result<[u8; 32], Error> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Storage)?;
    Ok(bytes)
}
fn material(row: &sqlx::postgres::PgRow) -> Result<Material, Error> {
    Ok(Material {
        operation_id: row.try_get("operation_id")?,
        reference: row.try_get("reference")?,
        revision: row.try_get("revision")?,
        configuration_sha256: row.try_get("configuration")?,
        key_digest: row
            .try_get::<Vec<u8>, _>("key_digest")?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        challenge: STANDARD.encode(row.try_get::<Vec<u8>, _>("nonce")?),
        confirmed: row.try_get("confirmed")?,
        revoked: row.try_get("revoked")?,
        endpoint: row.try_get("confirmation_endpoint")?,
        network_reference: row.try_get("network_reference")?,
        attempted_at: row.try_get("attempted_at")?,
        confirmed_at: row.try_get("confirmed_at")?,
        failure_reason: row.try_get("failure_reason")?,
    })
}
async fn head(
    c: &mut PgConnection,
    tenant: Uuid,
    reference: &str,
    id: Uuid,
) -> Result<Receipt, Error> {
    let row=sqlx::query("SELECT revision,active_revision,retiring_revision FROM mdm_webhook.key_heads WHERE tenant_id=$1 AND reference=$2 FOR UPDATE").bind(tenant).bind(reference).fetch_optional(c).await?.ok_or(Error::NotFound)?;
    Ok(Receipt {
        operation_id: id,
        reference: reference.into(),
        revision: row.try_get("revision")?,
        active_revision: row.try_get("active_revision")?,
        retiring_revision: row.try_get("retiring_revision")?,
    })
}
/// Call within the existing webhook Audit transaction and operation replay boundary.
pub async fn prepare(
    c: &mut PgConnection,
    tenant: Uuid,
    id: Uuid,
    input: &Prepare,
    protection: &Protector,
) -> Result<Material, Error> {
    reference(&input.reference)?;
    reference(&input.network_reference)?;
    let endpoint = url::Url::parse(&input.endpoint).map_err(|_| Error::Invalid)?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
        || endpoint.query().is_some()
        || input.endpoint.len() > 2048
    {
        return Err(Error::Invalid);
    }
    if id.is_nil()
        || input.expected_revision < 0
        || input.configuration_sha256.len() != 64
        || !input
            .configuration_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,28232))")
        .bind(tenant.to_string())
        .execute(&mut *c)
        .await?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mdm_webhook.key_materials WHERE tenant_id=$1")
            .bind(tenant)
            .fetch_one(&mut *c)
            .await?;
    let slots: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_webhook.key_heads WHERE tenant_id=$1 AND reference<>$2",
    )
    .bind(tenant)
    .bind(&input.reference)
    .fetch_one(&mut *c)
    .await?;
    if count >= 4096 || slots >= 128 {
        return Err(Error::Conflict);
    }
    sqlx::query(
        "INSERT INTO mdm_webhook.key_heads VALUES($1,$2,0,NULL,NULL) ON CONFLICT DO NOTHING",
    )
    .bind(tenant)
    .bind(&input.reference)
    .execute(&mut *c)
    .await?;
    let head = head(c, tenant, &input.reference, id).await?;
    if head.revision != input.expected_revision {
        return Err(Error::Conflict);
    }
    let revision = head.revision.checked_add(1).ok_or(Error::Conflict)?;
    let secret = match &input.source {
        Source::Generate => Zeroizing::new(format!(
            "whsec_{}",
            STANDARD.encode(Zeroizing::new(random()?).as_slice())
        )),
        Source::Import { secret } => secret.clone(),
    };
    let key = decode(&secret)?;
    let digest = Sha256::digest(key.as_slice()).to_vec();
    let duplicate:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_webhook.key_materials WHERE tenant_id=$1 AND key_digest=$2)").bind(tenant).bind(&digest).fetch_one(&mut *c).await?;
    if duplicate {
        return Err(Error::Conflict);
    }
    let encrypted = protection
        .seal_bytes(
            secret.as_bytes(),
            &context(tenant, &input.reference, revision)?,
        )
        .map_err(|_| Error::Storage)?;
    let row=sqlx::query("INSERT INTO mdm_webhook.key_materials(tenant_id,reference,revision,operation_id,configuration,key_digest,material,nonce,confirmation_endpoint,network_reference) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *")
        .bind(tenant).bind(&input.reference).bind(revision).bind(id).bind(&input.configuration_sha256).bind(digest).bind(encrypted).bind(random()?.as_slice()).bind(&input.endpoint).bind(&input.network_reference).fetch_one(&mut *c).await?;
    sqlx::query("UPDATE mdm_webhook.key_heads SET revision=$3 WHERE tenant_id=$1 AND reference=$2")
        .bind(tenant)
        .bind(&input.reference)
        .bind(revision)
        .execute(c)
        .await?;
    material(&row)
}
pub fn confirmation_message(tenant: Uuid, value: &Material) -> Vec<u8> {
    format!(
        "rss-mdm.webhook-key/v1\n{tenant}\n{}\n{}\n{}\n{}",
        value.reference, value.revision, value.configuration_sha256, value.challenge
    )
    .into_bytes()
}
async fn secret(
    c: &mut PgConnection,
    tenant: Uuid,
    reference: &str,
    revision: i64,
    key: &Protector,
) -> Result<(Material, Zeroizing<String>), Error> {
    let row=sqlx::query("SELECT * FROM mdm_webhook.key_materials WHERE tenant_id=$1 AND reference=$2 AND revision=$3").bind(tenant).bind(reference).bind(revision).fetch_optional(c).await?.ok_or(Error::NotFound)?;
    let value = material(&row)?;
    let bytes = key
        .open_bytes(
            &row.try_get::<Vec<u8>, _>("material")?,
            &context(tenant, reference, revision)?,
        )
        .map_err(|_| Error::Storage)?;
    let secret = Zeroizing::new(
        std::str::from_utf8(bytes.expose())
            .map_err(|_| Error::Storage)?
            .to_owned(),
    );
    decode(&secret)?;
    Ok((value, secret))
}
pub async fn transition(
    c: &mut PgConnection,
    tenant: Uuid,
    id: Uuid,
    input: &Transition,
    configuration: &str,
    key: &Protector,
) -> Result<Receipt, Error> {
    reference(&input.reference)?;
    let mut result = head(c, tenant, &input.reference, id).await?;
    if id.is_nil() || result.revision != input.expected_revision {
        return Err(Error::Conflict);
    }
    match &input.action {
        Action::Activate { material_revision } => {
            let (value, _) = secret(c, tenant, &input.reference, *material_revision, key).await?;
            if !value.confirmed
                || value.confirmed_at.is_none()
                || value.revoked
                || value.configuration_sha256 != configuration
                || result.retiring_revision.is_some()
                || result.active_revision == Some(*material_revision)
            {
                return Err(Error::Conflict);
            }
            result.retiring_revision = result.active_revision;
            result.active_revision = Some(*material_revision);
        }
        Action::Revoke { material_revision } => {
            let affected=sqlx::query("UPDATE mdm_webhook.key_materials SET revoked=true WHERE tenant_id=$1 AND reference=$2 AND revision=$3").bind(tenant).bind(&input.reference).bind(material_revision).execute(&mut *c).await?;
            if affected.rows_affected() != 1 {
                return Err(Error::NotFound);
            }
            // Revoking current material fails delivery closed. Never silently select an old secret.
            if result.retiring_revision == Some(*material_revision) {
                result.retiring_revision = None;
            }
        }
        Action::RetirePrevious => {
            if result.retiring_revision.is_none() {
                return Err(Error::Conflict);
            }
            let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_webhook.deliveries d JOIN mdm_webhook.versions v ON(v.tenant_id,v.subscription,v.version)=(d.tenant_id,d.subscription,d.target_version) LEFT JOIN rss_transactional_messaging.outbox o ON o.tenant_id=d.tenant_id AND o.message_id=d.id::text AND o.domain='mdm-webhook-delivery' WHERE d.tenant_id=$1 AND v.settings->>'keyReference'=$2 AND ((o.status IS NOT NULL AND o.status<>'published') OR (o.status IS NULL AND d.last_outcome IS DISTINCT FROM 'received')))").bind(tenant).bind(&input.reference).fetch_one(&mut *c).await?;
            if pending {
                return Err(Error::Conflict);
            }
            result.retiring_revision = None;
        }
    }
    result.revision = result.revision.checked_add(1).ok_or(Error::Conflict)?;
    sqlx::query("UPDATE mdm_webhook.key_heads SET revision=$3,active_revision=$4,retiring_revision=$5 WHERE tenant_id=$1 AND reference=$2").bind(tenant).bind(&input.reference).bind(result.revision).bind(result.active_revision).bind(result.retiring_revision).execute(c).await?;
    Ok(result)
}
pub async fn directory(c: &mut PgConnection, tenant: Uuid) -> Result<Directory, Error> {
    let heads = sqlx::query(
        "SELECT * FROM mdm_webhook.key_heads WHERE tenant_id=$1 ORDER BY reference LIMIT 129",
    )
    .bind(tenant)
    .fetch_all(&mut *c)
    .await?;
    if heads.len() > 128 {
        return Err(Error::Storage);
    }
    let mut output = Vec::new();
    for row in heads {
        output.push(Head {
            reference: row.try_get("reference")?,
            revision: row.try_get("revision")?,
            active_revision: row.try_get("active_revision")?,
            retiring_revision: row.try_get("retiring_revision")?,
        });
    }
    let rows=sqlx::query("SELECT * FROM mdm_webhook.key_materials WHERE tenant_id=$1 ORDER BY reference,revision LIMIT 4097").bind(tenant).fetch_all(c).await?;
    if rows.len() > 4096 {
        return Err(Error::Storage);
    }
    Ok(Directory {
        heads: output,
        materials: rows.iter().map(material).collect::<Result<_, _>>()?,
    })
}
pub struct Loaded {
    pub current: Zeroizing<String>,
    pub retiring: Option<Zeroizing<String>>,
    pub revision: i64,
}
pub async fn load(
    c: &mut PgConnection,
    tenant: Uuid,
    reference: &str,
    configuration: &str,
    key: &Protector,
) -> Result<Loaded, Error> {
    let row=sqlx::query("SELECT revision,active_revision,retiring_revision FROM mdm_webhook.key_heads WHERE tenant_id=$1 AND reference=$2").bind(tenant).bind(reference).fetch_optional(&mut *c).await?.ok_or(Error::NotFound)?;
    let head = Receipt {
        operation_id: Uuid::nil(),
        reference: reference.into(),
        revision: row.try_get("revision")?,
        active_revision: row.try_get("active_revision")?,
        retiring_revision: row.try_get("retiring_revision")?,
    };
    let (current, secret) = secret(
        c,
        tenant,
        reference,
        head.active_revision.ok_or(Error::NotFound)?,
        key,
    )
    .await?;
    if current.revoked || !current.confirmed || current.configuration_sha256 != configuration {
        return Err(Error::Denied);
    }
    let retiring = if let Some(revision) = head.retiring_revision {
        let (old, secret) = self::secret(c, tenant, reference, revision, key).await?;
        if old.revoked || old.configuration_sha256 != configuration {
            return Err(Error::Denied);
        }
        Some(secret)
    } else {
        None
    };
    Ok(Loaded {
        current: secret,
        retiring,
        revision: head.revision,
    })
}
/// Root-only secure delivery; the HTTP read model never returns key bytes.
async fn require_operator(c: &mut PgConnection) -> Result<(), Error> {
    let owner: bool = sqlx::query_scalar("SELECT current_user='mdm_owner'")
        .fetch_one(&mut *c)
        .await?;
    if !owner {
        return Err(Error::Denied);
    }
    Ok(())
}
pub async fn export(
    c: &mut PgConnection,
    tenant: Uuid,
    reference: &str,
    revision: i64,
    key: &Protector,
) -> Result<(Material, Zeroizing<String>), Error> {
    require_operator(c).await?;
    let (material, secret) = secret(c, tenant, reference, revision, key).await?;
    if material.revoked {
        return Err(Error::Conflict);
    }
    Ok((material, secret))
}
pub async fn rewrap(c: &mut PgConnection, tenant: Uuid, key: &Protector) -> Result<u64, Error> {
    let prefix = key.ciphertext_prefix();
    let rows=sqlx::query("SELECT reference,revision,material FROM mdm_webhook.key_materials WHERE tenant_id=$1 AND substring(material FROM 1 FOR $2)<>$3 ORDER BY reference,revision LIMIT 64 FOR UPDATE").bind(tenant).bind(prefix.len() as i32).bind(prefix).fetch_all(&mut *c).await?;
    for row in &rows {
        let reference: String = row.try_get("reference")?;
        let revision: i64 = row.try_get("revision")?;
        let bytes = key
            .rewrap_bytes(
                &row.try_get::<Vec<u8>, _>("material")?,
                &context(tenant, &reference, revision)?,
            )
            .map_err(|_| Error::Storage)?;
        sqlx::query("UPDATE mdm_webhook.key_materials SET material=$4 WHERE tenant_id=$1 AND reference=$2 AND revision=$3").bind(tenant).bind(reference).bind(revision).bind(bytes).execute(&mut *c).await?;
    }
    Ok(rows.len() as u64)
}

/// Only the deployment-side real TLS exchange may establish receiver possession.
pub async fn confirm(
    c: &mut PgConnection,
    tenant: Uuid,
    reference: &str,
    revision: i64,
    proof: &str,
    key: &Protector,
) -> Result<(), Error> {
    require_operator(c).await?;
    let (value, secret) = secret(c, tenant, reference, revision, key).await?;
    if value.revoked {
        return Err(Error::Conflict);
    }
    let supplied = STANDARD.decode(proof).map_err(|_| Error::Invalid)?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &decode(&secret)?);
    ring::hmac::verify(&key, &confirmation_message(tenant, &value), &supplied)
        .map_err(|_| Error::Denied)?;
    sqlx::query("UPDATE mdm_webhook.key_materials SET confirmed=true,confirmed_at=floor(extract(epoch FROM clock_timestamp()))::bigint,failure_reason=NULL WHERE tenant_id=$1 AND reference=$2 AND revision=$3 AND NOT revoked").bind(tenant).bind(reference).bind(revision).execute(c).await?;
    Ok(())
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
pub enum ConfirmationKind {
    #[serde(rename = "rss-mdm.webhook-key-confirmation/v1")]
    V1,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationRequest {
    #[serde(rename = "type")]
    pub kind: ConfirmationKind,
    pub tenant_id: Uuid,
    pub operation_id: Uuid,
    pub reference: String,
    pub revision: i64,
    pub configuration_sha256: String,
    pub challenge: String,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationResponse {
    pub confirmation_proof: String,
}

/// A receiver confirmation prepared by the material owner in the caller's transaction.
/// The host sends these exact bytes and settles the result in a later transaction.
pub struct ConfirmationAttempt {
    tenant: Uuid,
    material: Material,
    body: Vec<u8>,
    timestamp: i64,
    signature: String,
}
impl ConfirmationAttempt {
    pub fn endpoint(&self) -> &str {
        self.material
            .endpoint
            .as_deref()
            .expect("qualified endpoint")
    }
    pub fn network_reference(&self) -> &str {
        self.material
            .network_reference
            .as_deref()
            .expect("qualified network")
    }
    pub fn operation_id(&self) -> Uuid {
        self.material.operation_id
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }
    pub fn signature(&self) -> &str {
        &self.signature
    }
}

/// Preserve the current material identity, qualification interval and configuration binding.
/// The caller commits the attempt before performing network I/O.
pub async fn begin_confirmation(
    c: &mut PgConnection,
    tenant: Uuid,
    reference: &str,
    revision: i64,
    policies: &crate::network::Policies,
    now: i64,
    protection: &Protector,
) -> Result<Option<ConfirmationAttempt>, Error> {
    require_operator(c).await?;
    let (material, secret) = secret(c, tenant, reference, revision, protection).await?;
    if material.confirmed
        || material.revoked
        || material.configuration_sha256 != policies.digest()
        || material
            .attempted_at
            .is_some_and(|at| now.saturating_sub(at) < 60)
    {
        return Ok(None);
    }
    let Some(network) = material.network_reference.as_deref() else {
        return Ok(None);
    };
    let Some(endpoint) = material.endpoint.as_deref() else {
        return Ok(None);
    };
    match policies.check_material(tenant, network, endpoint) {
        Ok(()) => (),
        Err(Error::Denied) => return Ok(None),
        Err(error) => return Err(error),
    }
    let body = serde_json::to_vec(&ConfirmationRequest {
        kind: ConfirmationKind::V1,
        tenant_id: tenant,
        operation_id: material.operation_id,
        reference: material.reference.clone(),
        revision: material.revision,
        configuration_sha256: material.configuration_sha256.clone(),
        challenge: material.challenge.clone(),
    })?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &decode(&secret)?);
    let mut signing = ring::hmac::Context::with_key(&key);
    signing.update(format!("{}.{now}.", material.operation_id).as_bytes());
    signing.update(&body);
    let signature = format!("v1,{}", STANDARD.encode(signing.sign().as_ref()));
    sqlx::query("UPDATE mdm_webhook.key_materials SET attempted_at=$4,failure_reason='confirmation_pending' WHERE tenant_id=$1 AND reference=$2 AND revision=$3 AND NOT confirmed AND NOT revoked")
        .bind(tenant).bind(reference).bind(revision).bind(now).execute(c).await?;
    Ok(Some(ConfirmationAttempt {
        tenant,
        material,
        body,
        timestamp: now,
        signature,
    }))
}

/// Verify possession and retain a failed candidate after an unavailable or invalid receiver response.
/// Returns whether possession was confirmed; storage and authority failures remain errors.
pub async fn finish_confirmation(
    c: &mut PgConnection,
    attempt: &ConfirmationAttempt,
    response: Option<&[u8]>,
    protection: &Protector,
) -> Result<bool, Error> {
    require_operator(c).await?;
    if let Some(bytes) = response {
        if bytes.len() <= 4096
            && let Ok(response) = serde_json::from_slice::<ConfirmationResponse>(bytes)
        {
            match confirm(
                c,
                attempt.tenant,
                &attempt.material.reference,
                attempt.material.revision,
                &response.confirmation_proof,
                protection,
            )
            .await
            {
                Ok(()) => return Ok(true),
                Err(Error::Denied | Error::Invalid) => (),
                Err(error) => return Err(error),
            }
        }
    }
    sqlx::query("UPDATE mdm_webhook.key_materials SET failure_reason='receiver_confirmation_unavailable' WHERE tenant_id=$1 AND reference=$2 AND revision=$3 AND NOT confirmed")
        .bind(attempt.tenant).bind(&attempt.material.reference).bind(attempt.material.revision)
        .execute(c).await?;
    Ok(false)
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublicDirectory {
    pub configuration_sha256: String,
    pub keys: Directory,
}
#[derive(schemars::JsonSchema)]
#[allow(dead_code, reason = "published material contract alternatives")]
pub enum Contract {
    Prepare(Prepare),
    Transition(Transition),
    Material(Material),
    Receipt(Receipt),
    Directory(PublicDirectory),
    ConfirmationRequest(ConfirmationRequest),
    ConfirmationResponse(ConfirmationResponse),
}
#[cfg(test)]
mod tests {
    #[test]
    fn published_schema_matches_material_owner() {
        let actual = serde_json::to_value(schemars::schema_for!(super::Contract)).unwrap();
        let published: serde_json::Value =
            serde_json::from_str(include_str!("../schema/Materials.json")).unwrap();
        assert_eq!(actual, published);
    }
}
