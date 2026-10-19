//! Typed S3 connection lifecycle. Deployment qualifies providers; the domain owns encrypted material.
use crate::{Error, storage};
use base64::Engine;
use ring::rand::SecureRandom;
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
use zeroize::Zeroizing;
pub mod authority;
pub const INSTALL_SQL: &str = include_str!("../schema/connections.sql");
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Generate,
    Import {
        access_key: Zeroizing<String>,
        secret_key: Zeroizing<String>,
        session_token: Option<Zeroizing<String>>,
        expires_at: Option<i64>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub expected_revision: i64,
    pub profile: String,
    pub source: Source,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub access_key: Zeroizing<String>,
    pub secret_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
    pub expires_at: Option<i64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub revision: i64,
    pub profile: String,
    pub state: String,
    pub failure_reason: Option<String>,
    pub selected: bool,
    pub revoked: bool,
    pub qualified_at: Option<i64>,
    pub expires_at: Option<i64>,
}
fn db(_: sqlx::Error) -> Error {
    storage()
}
fn aad(tenant: TenantId, revision: i64) -> Result<DerivedAad, Error> {
    ProtectionContext::new(tenant, &revision.to_string(), "content.s3.credentials", 1)
        .map(|c| c.derive())
        .map_err(|_| Error::Metadata)
}
fn operation_aad(tenant: TenantId, operation: Uuid) -> Result<DerivedAad, Error> {
    ProtectionContext::new(tenant, &operation.to_string(), "content.s3.operation", 1)
        .map(|c| c.derive())
        .map_err(|_| Error::Metadata)
}
fn receipt(row: &sqlx::postgres::PgRow) -> Result<Receipt, Error> {
    Ok(Receipt {
        operation_id: row.try_get("operation_id").map_err(db)?,
        revision: row.try_get("revision").map_err(db)?,
        profile: row.try_get("profile").map_err(db)?,
        state: row.try_get("state").map_err(db)?,
        failure_reason: row.try_get("failure_reason").map_err(db)?,
        selected: row.try_get("selected").map_err(db)?,
        revoked: row.try_get("revoked").map_err(db)?,
        qualified_at: row.try_get("qualified_at").map_err(db)?,
        expires_at: row.try_get("expires_at").map_err(db)?,
    })
}
/// Call inside an authorized, audited transaction; credentials are persisted before provider calls.
pub async fn prepare(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    input: &Request,
    actor: &str,
    protection: &Protector,
) -> Result<Receipt, Error> {
    if operation.is_nil()
        || input.expected_revision < 0
        || input.expected_revision == i64::MAX
        || input.profile.is_empty()
        || input.profile.len() > 64
        || !input
            .profile
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err(Error::Configuration);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2824))")
        .bind(tenant.to_string())
        .execute(&mut *c)
        .await
        .map_err(db)?;
    let request = Zeroizing::new(serde_json::to_vec(&(input, actor)).map_err(|_| Error::Metadata)?);
    if let Some(row)=sqlx::query("SELECT * FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid AND operation_id=$2").bind(tenant.to_string()).bind(operation).fetch_optional(&mut *c).await.map_err(db)? {
        protection.verify_mac_with_key(&row.try_get::<String,_>("fingerprint_key").map_err(db)?,&request,&operation_aad(tenant,operation)?,&row.try_get::<Vec<u8>,_>("fingerprint").map_err(db)?).map_err(|_|Error::Conflict)?;
        return receipt(&row);
    }
    let credentials = match &input.source {
        Source::Generate => {
            let mut secret = Zeroizing::new(vec![0u8; 32]);
            ring::rand::SystemRandom::new()
                .fill(&mut secret)
                .map_err(|_| Error::Configuration)?;
            Credentials {
                access_key: Zeroizing::new(format!(
                    "rss{}",
                    &Uuid::new_v4().simple().to_string()[..16]
                )),
                secret_key: Zeroizing::new(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*secret),
                ),
                session_token: None,
                expires_at: None,
            }
        }
        Source::Import {
            access_key,
            secret_key,
            session_token,
            expires_at,
        } => {
            if access_key.is_empty()
                || access_key.len() > 128
                || secret_key.is_empty()
                || secret_key.len() > 16384
                || access_key.chars().any(char::is_control)
                || secret_key.chars().any(char::is_control)
                || session_token
                    .as_ref()
                    .is_some_and(|t| t.len() > 16384 || t.is_empty())
                || (session_token.is_some() && expires_at.is_none())
            {
                return Err(Error::Configuration);
            }
            Credentials {
                access_key: access_key.clone(),
                secret_key: secret_key.clone(),
                session_token: session_token.clone(),
                expires_at: *expires_at,
            }
        }
    };
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    if credentials.expires_at.is_some_and(|t| t <= now) {
        return Err(Error::Configuration);
    }
    let revision = input.expected_revision + 1;
    let bytes = Zeroizing::new(serde_json::to_vec(&credentials).map_err(|_| Error::Metadata)?);
    let sealed = protection
        .seal_bytes(&bytes, &aad(tenant, revision)?)
        .map_err(|_| Error::Metadata)?;
    let fingerprint = protection
        .mac(&request, &operation_aad(tenant, operation)?)
        .map_err(|_| Error::Metadata)?;
    sqlx::query("SELECT mdm_content_connections.reserve($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(input.expected_revision)
        .bind(operation)
        .bind(&input.profile)
        .bind(matches!(input.source, Source::Generate))
        .bind(sealed)
        .bind(protection.fingerprint_id())
        .bind(fingerprint.as_slice())
        .bind(credentials.expires_at)
        .execute(&mut *c)
        .await
        .map_err(|_| Error::Conflict)?;
    operation_receipt(c, tenant, operation).await
}
pub async fn operation_receipt(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
) -> Result<Receipt, Error> {
    let row=sqlx::query("SELECT * FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid AND operation_id=$2").bind(tenant.to_string()).bind(operation).fetch_optional(c).await.map_err(db)?.ok_or(Error::Conflict)?;
    receipt(&row)
}
pub struct Pending {
    pub receipt: Receipt,
    pub generated: bool,
    pub credentials: Credentials,
}
pub async fn pending(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    protection: &Protector,
) -> Result<Pending, Error> {
    let row=sqlx::query("SELECT * FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid AND operation_id=$2").bind(tenant.to_string()).bind(operation).fetch_optional(c).await.map_err(db)?.ok_or(Error::Conflict)?;
    let revision: i64 = row.try_get("revision").map_err(db)?;
    let sealed: Vec<u8> = row.try_get("credentials").map_err(db)?;
    let bytes = protection
        .open_bytes(&sealed, &aad(tenant, revision)?)
        .map_err(|_| Error::Metadata)?;
    Ok(Pending {
        receipt: receipt(&row)?,
        generated: row.try_get("generated").map_err(db)?,
        credentials: serde_json::from_slice(bytes.expose()).map_err(|_| Error::Metadata)?,
    })
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub namespace: String,
    pub private_ca: Vec<u8>,
}
/// 在外部副作用前固定目标；重试必须使用同一端点、命名空间和信任材料。
pub async fn bind_metadata(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    metadata: &Metadata,
) -> Result<(), Error> {
    let operator: bool =
        sqlx::query_scalar("SELECT current_user='mdm_owner' AND session_user='mdm_owner'")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    if !operator {
        return Err(Error::Configuration);
    }
    sqlx::query(
        "SELECT revision FROM mdm_content_connections.heads WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(tenant.to_string())
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    let existing:Option<(String,String,String,String)>=sqlx::query_as("SELECT endpoint,region,bucket,namespace FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid AND state='qualified' LIMIT 1").bind(tenant.to_string()).fetch_optional(&mut *c).await.map_err(db)?;
    if existing.is_some_and(|old| {
        old != (
            metadata.endpoint.clone(),
            metadata.region.clone(),
            metadata.bucket.clone(),
            metadata.namespace.clone(),
        )
    }) {
        return Err(Error::Conflict);
    }
    let row=sqlx::query("SELECT endpoint,region,bucket,namespace,private_ca FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid AND operation_id=$2 FOR UPDATE").bind(tenant.to_string()).bind(operation).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Conflict)?;
    if let Some(endpoint) = row.try_get::<Option<String>, _>("endpoint").map_err(db)? {
        let original = Metadata {
            endpoint,
            region: row.try_get("region").map_err(db)?,
            bucket: row.try_get("bucket").map_err(db)?,
            namespace: row.try_get("namespace").map_err(db)?,
            private_ca: row.try_get("private_ca").map_err(db)?,
        };
        return if original == *metadata {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    }
    sqlx::query("UPDATE mdm_content_connections.versions SET endpoint=$3,region=$4,bucket=$5,namespace=$6,private_ca=$7 WHERE tenant_id=$1::uuid AND operation_id=$2")
        .bind(tenant.to_string()).bind(operation).bind(&metadata.endpoint).bind(&metadata.region).bind(&metadata.bucket).bind(&metadata.namespace).bind(&metadata.private_ca).execute(c).await.map_err(db)?;
    Ok(())
}
/// Deployment-only completion; API roles cannot write qualification, selection or revocation columns.
pub async fn qualify(
    c: &mut PgConnection,
    tenant: TenantId,
    operation: Uuid,
    metadata: &Metadata,
    observed_at: i64,
) -> Result<Receipt, Error> {
    let operator: bool =
        sqlx::query_scalar("SELECT current_user='mdm_owner' AND session_user='mdm_owner'")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    if !operator || observed_at <= 0 || observed_at > now {
        return Err(Error::Configuration);
    }
    bind_metadata(c, tenant, operation, metadata).await?;
    let current = operation_receipt(c, tenant, operation).await?;
    if current.state == "qualified" {
        return Ok(current);
    }
    if current.state != "pending" || current.revoked || current.expires_at.is_some_and(|t| t <= now)
    {
        return Err(Error::Conflict);
    }
    sqlx::query("UPDATE mdm_content_connections.versions SET endpoint=$3,region=$4,bucket=$5,namespace=$6,private_ca=$7,qualified_at=$8,state='qualified',failure_reason=NULL,selected=true WHERE tenant_id=$1::uuid AND operation_id=$2 AND state='pending'")
        .bind(tenant.to_string()).bind(operation).bind(&metadata.endpoint).bind(&metadata.region).bind(&metadata.bucket).bind(&metadata.namespace).bind(&metadata.private_ca).bind(observed_at).execute(&mut *c).await.map_err(db)?;
    sqlx::query(
        "UPDATE mdm_content_connections.heads SET desired_revision=$2 WHERE tenant_id=$1::uuid",
    )
    .bind(tenant.to_string())
    .bind(current.revision)
    .execute(&mut *c)
    .await
    .map_err(db)?;
    operation_receipt(c, tenant, operation).await
}
pub async fn require_live(
    c: &mut PgConnection,
    tenant: TenantId,
    revision: u64,
) -> Result<(), Error> {
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid AND revision=$2 AND state='qualified' AND selected AND NOT revoked AND (expires_at IS NULL OR expires_at>extract(epoch FROM clock_timestamp())))").bind(tenant.to_string()).bind(i64::try_from(revision).map_err(|_|Error::Configuration)?).fetch_one(c).await.map_err(db)?;
    if valid {
        Ok(())
    } else {
        Err(Error::Configuration)
    }
}
pub struct Loaded {
    pub metadata: Metadata,
    pub credentials: Credentials,
}
impl rss_mdm_content_s3::Secrets for Loaded {
    fn resolve(
        &self,
        reference: &str,
    ) -> rss_mdm_content_s3::Result<rss_mdm_content_s3::Credentials> {
        if reference != "content-connection" {
            return Err(rss_mdm_content_s3::Error::Configuration);
        }
        let c = &self.credentials;
        let expires = c
            .expires_at
            .map(|t| {
                std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_secs(t.max(0) as u64))
                    .ok_or(rss_mdm_content_s3::Error::Configuration)
            })
            .transpose()?;
        rss_mdm_content_s3::Credentials::new(
            c.access_key.to_string(),
            c.secret_key.to_string(),
            c.session_token.as_ref().map(|s| s.to_string()),
            expires,
        )
    }
}
pub async fn load(
    c: &mut PgConnection,
    tenant: TenantId,
    revision: u64,
    protection: &Protector,
) -> Result<Loaded, Error> {
    require_live(c, tenant, revision).await?;
    let row=sqlx::query("SELECT endpoint,region,bucket,namespace,private_ca,credentials FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid AND revision=$2").bind(tenant.to_string()).bind(revision as i64).fetch_one(c).await.map_err(db)?;
    let sealed: Vec<u8> = row.try_get("credentials").map_err(db)?;
    let bytes = protection
        .open_bytes(&sealed, &aad(tenant, revision as i64)?)
        .map_err(|_| Error::Metadata)?;
    Ok(Loaded {
        metadata: Metadata {
            endpoint: row.try_get("endpoint").map_err(db)?,
            region: row.try_get("region").map_err(db)?,
            bucket: row.try_get("bucket").map_err(db)?,
            namespace: row.try_get("namespace").map_err(db)?,
            private_ca: row.try_get("private_ca").map_err(db)?,
        },
        credentials: serde_json::from_slice(bytes.expose()).map_err(|_| Error::Metadata)?,
    })
}

pub const ACCESS_CONTRACT: &str = include_str!("connections-contract.json");
pub async fn verify_reservation(c: &mut PgConnection) -> Result<bool, Error> {
    let body = INSTALL_SQL
        .split("$reserve$")
        .nth(1)
        .expect("fixed reserve body");
    sqlx::query_scalar("SELECT count(*)=1 AND coalesce(bool_and(p.prosrc=$1 AND p.proowner='mdm_owner'::regrole AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp'] AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 OR a.is_grantable OR pg_get_userbyid(a.grantee) NOT IN('mdm_owner','mdm_access'))),false) FROM pg_proc p WHERE p.oid='mdm_content_connections.reserve(bigint,uuid,text,boolean,bytea,text,bytea,bigint)'::regprocedure")
        .bind(body).fetch_one(c).await.map_err(db)
}

/// 部署维护事务中的有界重加密；材料版本和请求指纹保持不变。
pub async fn rewrap(
    c: &mut PgConnection,
    tenant: TenantId,
    protection: &Protector,
) -> Result<u64, Error> {
    let prefix = protection.ciphertext_prefix();
    let rows=sqlx::query("SELECT revision,credentials FROM mdm_content_connections.versions WHERE tenant_id=$1::uuid AND substring(credentials FROM 1 FOR $2)<>$3 ORDER BY revision LIMIT 64 FOR UPDATE").bind(tenant.to_string()).bind(prefix.len() as i32).bind(prefix).fetch_all(&mut *c).await.map_err(db)?;
    for row in &rows {
        let revision: i64 = row.try_get("revision").map_err(db)?;
        let sealed: Vec<u8> = row.try_get("credentials").map_err(db)?;
        let next = protection
            .rewrap_bytes(&sealed, &aad(tenant, revision)?)
            .map_err(|_| Error::Metadata)?;
        sqlx::query("UPDATE mdm_content_connections.versions SET credentials=$3 WHERE tenant_id=$1::uuid AND revision=$2").bind(tenant.to_string()).bind(revision).bind(next).execute(&mut *c).await.map_err(db)?;
    }
    Ok(rows.len() as u64)
}
