//! 租户邮件材料和一次测试投递回执；网络副作用由部署进程消费。
use crate::{
    Error, Result,
    transport::{Credentials, Endpoint, Tls},
};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
use zeroize::Zeroizing;
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub expected_revision: i64,
    pub profile: String,
    pub sender: String,
    pub recipient: String,
    #[schemars(with = "String")]
    pub username: Zeroizing<String>,
    #[schemars(with = "String")]
    pub password: Zeroizing<String>,
}
#[derive(Serialize, Deserialize)]
struct Secret {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pending,
    Submitting,
    Accepted,
    Failed,
    Unknown,
}
fn state(value: &str) -> Result<State> {
    match value {
        "pending" => Ok(State::Pending),
        "submitting" => Ok(State::Submitting),
        "accepted" => Ok(State::Accepted),
        "failed" => Ok(State::Failed),
        "unknown" => Ok(State::Unknown),
        _ => Err(Error::Storage),
    }
}
#[derive(Clone, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub operation_id: Uuid,
    pub revision: i64,
    pub profile: String,
    pub state: State,
    pub attempted_at: Option<i64>,
    pub accepted_at: Option<i64>,
    pub failure_reason: Option<String>,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub revision: i64,
    pub selected_revision: Option<i64>,
    pub version_count: i64,
    pub current: Option<Receipt>,
    pub latest: Option<Receipt>,
}
fn db(_: sqlx::Error) -> Error {
    Error::Storage
}
fn aad(tenant: &str, owner: &str, purpose: &str) -> Result<DerivedAad> {
    ProtectionContext::new(
        rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Input)?,
        owner,
        purpose,
        1,
    )
    .map(|v| v.derive())
    .map_err(|_| Error::Input)
}
pub(crate) fn receipt(row: &sqlx::postgres::PgRow) -> Result<Receipt> {
    Ok(Receipt {
        operation_id: row.try_get("operation_id").map_err(db)?,
        revision: row.try_get("revision").map_err(db)?,
        profile: row.try_get("profile").map_err(db)?,
        state: state(&row.try_get::<String, _>("state").map_err(db)?)?,
        attempted_at: row.try_get("attempted_at").map_err(db)?,
        accepted_at: row.try_get("accepted_at").map_err(db)?,
        failure_reason: row.try_get("failure_reason").map_err(db)?,
    })
}
pub async fn prepare(
    c: &mut PgConnection,
    tenant: &str,
    operation: Uuid,
    actor: &str,
    input: &Request,
    key: &Protector,
) -> Result<Receipt> {
    if operation.is_nil()
        || actor.is_empty()
        || input.expected_revision < 0
        || input.profile.is_empty()
        || input.profile.len() > 128
        || !input
            .profile
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(Error::Input);
    }
    crate::transport::mailbox(&input.sender)?;
    crate::transport::mailbox(&input.recipient)?;
    if input.username.is_empty()
        || input.username.len() > 1024
        || input.password.is_empty()
        || input.password.len() > 4096
        || input.username.contains('\0')
        || input.password.contains('\0')
    {
        return Err(Error::Input);
    }
    let request = Zeroizing::new(serde_json::to_vec(&(actor, input)).map_err(|_| Error::Input)?);
    let request_aad = aad(tenant, &operation.to_string(), "smtp.operation")?;
    if let Some(row) =
        sqlx::query("SELECT * FROM mdm_mail.versions WHERE tenant_id=$1::uuid AND operation_id=$2")
            .bind(tenant)
            .bind(operation)
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?
    {
        key.verify_mac_with_key(
            &row.try_get::<String, _>("fingerprint_key").map_err(db)?,
            &request,
            &request_aad,
            &row.try_get::<Vec<u8>, _>("fingerprint").map_err(db)?,
        )
        .map_err(|_| Error::Conflict)?;
        return receipt(&row);
    }
    sqlx::query("INSERT INTO mdm_mail.heads VALUES($1::uuid,0,NULL) ON CONFLICT DO NOTHING")
        .bind(tenant)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    let head: i64 = sqlx::query_scalar(
        "SELECT revision FROM mdm_mail.heads WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(tenant)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if head != input.expected_revision {
        return Err(Error::Conflict);
    }
    let revision = head.checked_add(1).ok_or(Error::Conflict)?;
    let bytes = Zeroizing::new(
        serde_json::to_vec(&Secret {
            username: input.username.clone(),
            password: input.password.clone(),
        })
        .map_err(|_| Error::Input)?,
    );
    let encrypted = key
        .seal_bytes(
            &bytes,
            &aad(tenant, &revision.to_string(), "smtp.credentials")?,
        )
        .map_err(|_| Error::Storage)?;
    let fingerprint = key
        .mac(&request, &request_aad)
        .map_err(|_| Error::Storage)?;
    let row=sqlx::query("INSERT INTO mdm_mail.versions(tenant_id,revision,operation_id,fingerprint_key,fingerprint,profile,sender,recipient,credentials) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *").bind(tenant).bind(revision).bind(operation).bind(key.fingerprint_id()).bind(fingerprint.as_slice()).bind(&input.profile).bind(&input.sender).bind(&input.recipient).bind(encrypted).fetch_one(&mut *c).await.map_err(db)?;
    sqlx::query("UPDATE mdm_mail.heads SET revision=$2 WHERE tenant_id=$1::uuid")
        .bind(tenant)
        .bind(revision)
        .execute(c)
        .await
        .map_err(db)?;
    receipt(&row)
}
pub async fn directory(c: &mut PgConnection, tenant: &str) -> Result<Directory> {
    let (revision, selected_revision) = sqlx::query_as(
        "SELECT revision,selected_revision FROM mdm_mail.heads WHERE tenant_id=$1::uuid",
    )
    .bind(tenant)
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?
    .unwrap_or((0, None));
    let version_count =
        sqlx::query_scalar("SELECT count(*) FROM mdm_mail.versions WHERE tenant_id=$1::uuid")
            .bind(tenant)
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    let rows=sqlx::query("SELECT operation_id,revision,profile,state,attempted_at,accepted_at,failure_reason FROM mdm_mail.versions WHERE tenant_id=$1::uuid AND (revision=$2 OR revision=$3)").bind(tenant).bind(revision).bind(selected_revision).fetch_all(c).await.map_err(db)?;
    let values = rows.iter().map(receipt).collect::<Result<Vec<_>>>()?;
    Ok(Directory {
        revision,
        selected_revision,
        version_count,
        current: values
            .iter()
            .find(|v| Some(v.revision) == selected_revision)
            .cloned(),
        latest: values.iter().find(|v| v.revision == revision).cloned(),
    })
}
pub async fn operation(c: &mut PgConnection, tenant: &str, operation: Uuid) -> Result<Receipt> {
    let row =
        sqlx::query("SELECT * FROM mdm_mail.versions WHERE tenant_id=$1::uuid AND operation_id=$2")
            .bind(tenant)
            .bind(operation)
            .fetch_one(c)
            .await
            .map_err(db)?;
    receipt(&row)
}
async fn owner(c: &mut PgConnection) -> Result<()> {
    let allowed: bool =
        sqlx::query_scalar("SELECT session_user='mdm_owner' AND current_user='mdm_owner'")
            .fetch_one(c)
            .await
            .map_err(db)?;
    if !allowed {
        return Err(Error::Conflict);
    }
    Ok(())
}
pub struct Pending {
    pub receipt: Receipt,
    pub credentials: Credentials,
    pub sender: String,
    pub recipient: String,
}
pub async fn pending(
    c: &mut PgConnection,
    tenant: &str,
    operation: Uuid,
    key: &Protector,
    endpoint: &Endpoint,
) -> Result<Pending> {
    owner(c).await?;
    endpoint.validate()?;
    let row = sqlx::query(
        "SELECT * FROM mdm_mail.versions WHERE tenant_id=$1::uuid AND operation_id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(operation)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    let value = receipt(&row)?;
    let digest = Sha256::digest(serde_json::to_vec(endpoint).map_err(|_| Error::Input)?).to_vec();
    let previous: Option<Vec<u8>> = row.try_get("endpoint_digest").map_err(db)?;
    if previous.as_ref().is_some_and(|old| old != &digest) {
        return Err(Error::Conflict);
    }
    if previous.is_none() {
        sqlx::query("UPDATE mdm_mail.versions SET endpoint_digest=$3,hostname=$4,address=$5,tls_mode=$6,tls_roots=$7 WHERE tenant_id=$1::uuid AND operation_id=$2").bind(tenant).bind(operation).bind(digest).bind(&endpoint.hostname).bind(endpoint.address.to_string()).bind(match endpoint.tls{Tls::Implicit=>"implicit",Tls::Starttls=>"starttls"}).bind(&endpoint.ca_pem).execute(&mut *c).await.map_err(db)?;
    }
    let encrypted: Vec<u8> = row.try_get("credentials").map_err(db)?;
    let bytes = key
        .open_bytes(
            &encrypted,
            &aad(tenant, &value.revision.to_string(), "smtp.credentials")?,
        )
        .map_err(|_| Error::Storage)?;
    let secret: Secret = serde_json::from_slice(bytes.expose()).map_err(|_| Error::Storage)?;
    Ok(Pending {
        receipt: value,
        credentials: Credentials {
            username: secret.username,
            password: secret.password,
        },
        sender: row.try_get("sender").map_err(db)?,
        recipient: row.try_get("recipient").map_err(db)?,
    })
}
/// DATA 前提交；调用者必须在此事务真正提交后才继续网络发送。
pub async fn submitting(c: &mut PgConnection, tenant: &str, operation: Uuid) -> Result<()> {
    owner(c).await?;
    let result=sqlx::query("UPDATE mdm_mail.versions SET state='submitting',attempted_at=floor(extract(epoch FROM clock_timestamp()))::bigint,failure_reason=NULL WHERE tenant_id=$1::uuid AND operation_id=$2 AND state IN('pending','failed') AND endpoint_digest IS NOT NULL").bind(tenant).bind(operation).execute(c).await.map_err(db)?;
    if result.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
#[derive(Clone, Copy)]
pub enum Outcome {
    Accepted,
    Rejected,
    Unavailable,
}
pub async fn finish(
    c: &mut PgConnection,
    tenant: &str,
    operation: Uuid,
    outcome: Outcome,
) -> Result<()> {
    owner(c).await?;
    let accepted = matches!(outcome, Outcome::Accepted);
    let state:String=sqlx::query_scalar("SELECT state FROM mdm_mail.versions WHERE tenant_id=$1::uuid AND operation_id=$2 FOR UPDATE").bind(tenant).bind(operation).fetch_one(&mut *c).await.map_err(db)?;
    if state == "accepted" {
        return if accepted {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    }
    if accepted && state != "submitting" {
        return Err(Error::Conflict);
    }
    let (next, reason) = if accepted && state == "submitting" {
        ("accepted", None)
    } else if matches!(outcome, Outcome::Rejected) && state == "submitting" {
        ("failed", Some("rejected_by_server"))
    } else if state == "submitting" || state == "unknown" {
        ("unknown", Some("submission_unknown"))
    } else if !accepted {
        ("failed", Some("tls_or_authentication_failed"))
    } else {
        return Err(Error::Conflict);
    };
    sqlx::query("UPDATE mdm_mail.versions SET state=$3,failure_reason=$4,attempted_at=floor(extract(epoch FROM clock_timestamp()))::bigint,accepted_at=CASE WHEN $3='accepted' THEN floor(extract(epoch FROM clock_timestamp()))::bigint ELSE accepted_at END WHERE tenant_id=$1::uuid AND operation_id=$2").bind(tenant).bind(operation).bind(next).bind(reason).execute(&mut *c).await.map_err(db)?;
    if next == "accepted" {
        sqlx::query("UPDATE mdm_mail.heads h SET selected_revision=v.revision FROM mdm_mail.versions v WHERE h.tenant_id=$1::uuid AND v.tenant_id=h.tenant_id AND v.operation_id=$2 AND h.revision=v.revision").bind(tenant).bind(operation).execute(c).await.map_err(db)?;
    }
    Ok(())
}
pub async fn rewrap(c: &mut PgConnection, tenant: &str, key: &Protector) -> Result<u64> {
    owner(c).await?;
    let prefix = key.ciphertext_prefix();
    let rows:Vec<(i64,Vec<u8>)>=sqlx::query_as("SELECT revision,credentials FROM mdm_mail.versions WHERE tenant_id=$1::uuid AND substring(credentials FROM 1 FOR $2)<>$3 ORDER BY revision LIMIT 64 FOR UPDATE").bind(tenant).bind(prefix.len() as i32).bind(prefix).fetch_all(&mut *c).await.map_err(db)?;
    for (revision, bytes) in &rows {
        let bytes = key
            .rewrap_bytes(
                bytes,
                &aad(tenant, &revision.to_string(), "smtp.credentials")?,
            )
            .map_err(|_| Error::Storage)?;
        sqlx::query(
            "UPDATE mdm_mail.versions SET credentials=$3 WHERE tenant_id=$1::uuid AND revision=$2",
        )
        .bind(tenant)
        .bind(revision)
        .bind(bytes)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    }
    Ok(rows.len() as u64)
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    #[test]
    fn published_mail_schema_matches_the_runtime_contract() {
        let actual = serde_json::json!({"Qualification":schemars::schema_for!(Request),"Operation":schemars::schema_for!(Receipt),"Directory":schemars::schema_for!(Directory)});
        let published: serde_json::Value =
            serde_json::from_str(include_str!("../schema/Mail.json")).unwrap();
        assert_eq!(actual, published);
    }
}
