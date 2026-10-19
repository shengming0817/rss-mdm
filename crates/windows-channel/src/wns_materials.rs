//! WNS 运行凭据由 Windows 领域保管，部署侧验证真实 OAuth 后申请宿主应用。
use crate::{Error, Failure, database::db};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
use zeroize::Zeroizing;
pub const INSTALL_SQL: &str = include_str!("../schema/wns-materials.sql");
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub expected_revision: i64,
    pub package_family_name: String,
    #[schemars(with = "String")]
    pub sid: Zeroizing<String>,
    #[schemars(with = "String")]
    pub client_secret: Zeroizing<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Material {
    sid: Zeroizing<String>,
    secret: Zeroizing<String>,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub revision: i64,
    pub package_family_name: String,
    pub qualified_at: Option<i64>,
    pub attempted_at: Option<i64>,
    pub failure_reason: Option<String>,
    pub selected: bool,
    pub revoked: bool,
}
fn aad(tenant: &str, revision: i64) -> Result<DerivedAad, Error> {
    ProtectionContext::new(
        rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
        &revision.to_string(),
        "windows.wns.material",
        1,
    )
    .map(|v| v.derive())
    .map_err(|_| Error::Malformed)
}
fn request_aad(tenant: &str, id: Uuid) -> Result<DerivedAad, Error> {
    ProtectionContext::new(
        rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
        &id.to_string(),
        "windows.wns.operation",
        1,
    )
    .map(|v| v.derive())
    .map_err(|_| Error::Malformed)
}
fn corrupt(_: impl std::fmt::Debug) -> Error {
    Error::Unavailable(Failure::Protocol)
}
fn receipt(row: &sqlx::postgres::PgRow) -> Result<Receipt, Error> {
    Ok(Receipt {
        operation_id: row.try_get("operation_id").map_err(db)?,
        revision: row.try_get("revision").map_err(db)?,
        package_family_name: row.try_get("pfn").map_err(db)?,
        qualified_at: row.try_get("qualified_at").map_err(db)?,
        attempted_at: row.try_get("attempted_at").map_err(db)?,
        failure_reason: row.try_get("failure_reason").map_err(db)?,
        selected: row.try_get("selected").map_err(db)?,
        revoked: row.try_get("revoked").map_err(db)?,
    })
}
/// 调用方持有原业务事务和授权；相同操作异参及异主体始终冲突。
pub async fn prepare(
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
    actor: &str,
    input: &Request,
    key: &Protector,
) -> Result<Receipt, Error> {
    if id.is_nil() || actor.is_empty() || input.expected_revision < 0 {
        return Err(Error::Malformed);
    }
    let revoked_operation:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_wns.revocations WHERE tenant_id=$1::uuid AND operation_id=$2)").bind(tenant).bind(id).fetch_one(&mut *c).await.map_err(db)?;
    if revoked_operation {
        return Err(Error::Conflict);
    }
    crate::push::validate(&input.package_family_name, &input.sid, &input.client_secret)?;
    let bytes = Zeroizing::new(serde_json::to_vec(&(actor, input)).map_err(corrupt)?);
    let binding = request_aad(tenant, id)?;
    if let Some(row) =
        sqlx::query("SELECT * FROM mdm_wns.versions WHERE tenant_id=$1::uuid AND operation_id=$2")
            .bind(tenant)
            .bind(id)
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?
    {
        let fingerprint: Vec<u8> = row.try_get("fingerprint").map_err(db)?;
        let fingerprint_key: String = row.try_get("fingerprint_key").map_err(db)?;
        key.verify_mac_with_key(&fingerprint_key, &bytes, &binding, &fingerprint)
            .map_err(|_| Error::Conflict)?;
        return receipt(&row);
    }
    sqlx::query("INSERT INTO mdm_wns.heads VALUES($1::uuid,0,NULL) ON CONFLICT DO NOTHING")
        .bind(tenant)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    let (revision, desired): (i64, Option<i64>) = sqlx::query_as(
        "SELECT revision,desired_revision FROM mdm_wns.heads WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(tenant)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if revision != input.expected_revision {
        return Err(Error::Conflict);
    }
    let revision = revision.checked_add(1).ok_or(Error::Conflict)?;
    let sid_digest = Sha256::digest(input.sid.as_bytes()).to_vec();
    let old:Option<Vec<u8>>=sqlx::query_scalar("SELECT configuration FROM mdm_wns.versions WHERE tenant_id=$1::uuid AND revision=$2 AND pfn=$3 AND sid_digest=$4 AND NOT revoked").bind(tenant).bind(desired).bind(&input.package_family_name).bind(&sid_digest).fetch_optional(&mut *c).await.map_err(db)?;
    // 同一 WNS 应用的秘密轮换不改变设备通道绑定；应用身份变化则等待设备重新查询。
    let configuration = old.unwrap_or_else(|| Sha256::digest(Uuid::new_v4().as_bytes()).to_vec());
    let material = Zeroizing::new(
        serde_json::to_vec(&Material {
            sid: input.sid.clone(),
            secret: input.client_secret.clone(),
        })
        .map_err(corrupt)?,
    );
    let encrypted = key
        .seal_bytes(&material, &aad(tenant, revision)?)
        .map_err(corrupt)?;
    let fingerprint = key.mac(&bytes, &binding).map_err(corrupt)?;
    let row=sqlx::query("INSERT INTO mdm_wns.versions(tenant_id,revision,operation_id,actor,fingerprint_key,fingerprint,pfn,sid_digest,configuration,material) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *").bind(tenant).bind(revision).bind(id).bind(actor).bind(key.fingerprint_id()).bind(fingerprint.as_slice()).bind(&input.package_family_name).bind(sid_digest).bind(configuration).bind(encrypted).fetch_one(&mut *c).await.map_err(db)?;
    sqlx::query("UPDATE mdm_wns.heads SET revision=$2 WHERE tenant_id=$1::uuid")
        .bind(tenant)
        .bind(revision)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    receipt(&row)
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub revision: i64,
    pub desired_revision: Option<i64>,
    pub versions: Vec<Receipt>,
}
pub async fn directory(c: &mut PgConnection, tenant: &str) -> Result<Directory, Error> {
    let (revision, desired_revision): (i64, Option<i64>) = sqlx::query_as(
        "SELECT revision,desired_revision FROM mdm_wns.heads WHERE tenant_id=$1::uuid",
    )
    .bind(tenant)
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?
    .unwrap_or((0, None));
    let versions = sqlx::query(
        "SELECT * FROM mdm_wns.versions WHERE tenant_id=$1::uuid ORDER BY revision DESC LIMIT 64",
    )
    .bind(tenant)
    .fetch_all(c)
    .await
    .map_err(db)?
    .iter()
    .map(receipt)
    .collect::<Result<Vec<_>, _>>()?;
    Ok(Directory {
        revision,
        desired_revision,
        versions,
    })
}
pub async fn load(
    c: &mut PgConnection,
    tenant: &str,
    revision: i64,
    key: &Protector,
    clock: std::sync::Arc<dyn rss_observation::Clock>,
    require_selected: bool,
) -> Result<crate::push::Push, Error> {
    let row = sqlx::query(
        "SELECT * FROM mdm_wns.versions WHERE tenant_id=$1::uuid AND revision=$2 AND NOT revoked",
    )
    .bind(tenant)
    .bind(revision)
    .fetch_optional(c)
    .await
    .map_err(db)?
    .ok_or(Error::Conflict)?;
    if require_selected
        && (!row.try_get::<bool, _>("selected").map_err(db)?
            || row
                .try_get::<Option<i64>, _>("qualified_at")
                .map_err(db)?
                .is_none())
    {
        return Err(Error::Conflict);
    }
    let encrypted: Vec<u8> = row.try_get("material").map_err(db)?;
    let bytes = key
        .open_bytes(&encrypted, &aad(tenant, revision)?)
        .map_err(corrupt)?;
    let material: Material = serde_json::from_slice(bytes.expose()).map_err(corrupt)?;
    let mut push = crate::push::Push::new(
        row.try_get("pfn").map_err(db)?,
        material.sid.to_string(),
        material.secret.to_string(),
        clock,
    )?;
    push.configuration = row
        .try_get::<Vec<u8>, _>("configuration")
        .map_err(db)?
        .try_into()
        .map_err(corrupt)?;
    if require_selected {
        push.material_revision = Some(revision);
    }
    Ok(push)
}
pub async fn qualify(
    c: &mut PgConnection,
    tenant: &str,
    revision: i64,
    now: i64,
) -> Result<(), Error> {
    let owner: bool =
        sqlx::query_scalar("SELECT session_user='mdm_owner' AND current_user='mdm_owner'")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    if !owner || now <= 0 {
        return Err(Error::Forbidden);
    }
    let head: i64 = sqlx::query_scalar(
        "SELECT revision FROM mdm_wns.heads WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(tenant)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if head != revision {
        return Err(Error::Conflict);
    }
    let changed=sqlx::query("UPDATE mdm_wns.versions SET qualified_at=COALESCE(qualified_at,$3),attempted_at=$3,failure_reason=NULL,selected=true WHERE tenant_id=$1::uuid AND revision=$2 AND NOT revoked").bind(tenant).bind(revision).bind(now).execute(&mut *c).await.map_err(db)?;
    if changed.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    sqlx::query("UPDATE mdm_wns.heads SET desired_revision=$2 WHERE tenant_id=$1::uuid")
        .bind(tenant)
        .bind(revision)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}

pub fn routes(state: std::sync::Arc<crate::HttpState>) -> axum::Router {
    use axum::routing::get;
    axum::Router::new()
        .route("/api/v1/windows/wns", get(read).post(create))
        .route(
            "/api/v1/windows/wns/revoke",
            axum::routing::post(revoke_http),
        )
        .route("/api/v1/windows/wns/operations/{id}", get(operation))
        .layer(axum::extract::DefaultBodyLimit::max(16384))
        .with_state(state)
}
fn proof<'a>(
    app: &crate::HttpState,
    auth: &'a rss_mdm_authorization_service::context::RequestAuth,
    write: bool,
) -> Result<&'a rss_mdm_authorization_service::context::AuthorizedPrincipal, Error> {
    let p = &auth.proof;
    if p.tenant_id() != app.identity.tenant().to_string() {
        return Err(Error::Forbidden);
    }
    p.require(
        if write {
            rss_mdm_authorization_service::Permission::RegistrationConfigurationWrite
        } else {
            rss_mdm_authorization_service::Permission::RegistrationConfigurationRead
        },
        None,
    )?;
    if write {
        let now = app
            .clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?;
        let authenticated = p.session()?.view().auth_time;
        if authenticated > now || now - authenticated > 300 {
            return Err(Error::Unauthorized);
        }
    }
    Ok(p)
}
async fn read(
    axum::extract::State(app): axum::extract::State<std::sync::Arc<crate::HttpState>>,
    axum::Extension(auth): axum::Extension<rss_mdm_authorization_service::context::RequestAuth>,
) -> Result<axum::Json<Directory>, Error> {
    let p = proof(&app, &auth, false)?;
    let mut tx = app.access.begin_read(p.tenant_id()).await?;
    let out = directory(&mut tx, p.tenant_id()).await?;
    tx.rollback().await.map_err(db)?;
    p.check_live()?;
    Ok(axum::Json(out))
}
async fn operation(
    axum::extract::State(app): axum::extract::State<std::sync::Arc<crate::HttpState>>,
    axum::Extension(auth): axum::Extension<rss_mdm_authorization_service::context::RequestAuth>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<axum::Json<Operation>, Error> {
    let p = proof(&app, &auth, false)?;
    let mut tx = app.access.begin_read(p.tenant_id()).await?;
    let value = if let Some(row) =
        sqlx::query("SELECT * FROM mdm_wns.versions WHERE tenant_id=$1::uuid AND operation_id=$2")
            .bind(p.tenant_id())
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
    {
        Operation::Material(receipt(&row)?)
    } else {
        let row=sqlx::query("SELECT revision,material_revision FROM mdm_wns.revocations WHERE tenant_id=$1::uuid AND operation_id=$2").bind(p.tenant_id()).bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::NotFound)?;
        Operation::Revocation(Revocation {
            operation_id: id,
            revision: row.try_get("revision").map_err(db)?,
            material_revision: row.try_get("material_revision").map_err(db)?,
        })
    };
    tx.rollback().await.map_err(db)?;
    p.check_live()?;
    Ok(axum::Json(value))
}
async fn create(
    axum::extract::State(app): axum::extract::State<std::sync::Arc<crate::HttpState>>,
    axum::Extension(auth): axum::Extension<rss_mdm_authorization_service::context::RequestAuth>,
    axum::Extension(audit): axum::Extension<rss_mdm_audit_integration::RequestAudit>,
    headers: axum::http::HeaderMap,
    axum::Json(input): axum::Json<Request>,
) -> Result<(axum::http::StatusCode, axum::Json<Operation>), Error> {
    mutate(app, auth, audit, headers, Change::Import(input)).await
}
async fn revoke_http(
    axum::extract::State(app): axum::extract::State<std::sync::Arc<crate::HttpState>>,
    axum::Extension(auth): axum::Extension<rss_mdm_authorization_service::context::RequestAuth>,
    axum::Extension(audit): axum::Extension<rss_mdm_audit_integration::RequestAudit>,
    headers: axum::http::HeaderMap,
    axum::Json(input): axum::Json<RevokeRequest>,
) -> Result<(axum::http::StatusCode, axum::Json<Operation>), Error> {
    mutate(app, auth, audit, headers, Change::Revoke(input)).await
}
async fn mutate(
    app: std::sync::Arc<crate::HttpState>,
    auth: rss_mdm_authorization_service::context::RequestAuth,
    audit: rss_mdm_audit_integration::RequestAudit,
    headers: axum::http::HeaderMap,
    input: Change,
) -> Result<(axum::http::StatusCode, axum::Json<Operation>), Error> {
    let p = proof(&app, &auth, true)?;
    let mut values = headers.get_all("idempotency-key").iter();
    let id = values
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| Uuid::parse_str(v).ok())
        .filter(|v| !v.is_nil())
        .ok_or(Error::Malformed)?;
    if values.next().is_some() {
        return Err(Error::Malformed);
    }
    p.bind_audit(&audit)?;
    audit.operation(id, "windows_wns_material");
    audit.require_request_settlement();
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(8));
    let result=app.audit_store.write(app.identity.tenant(),&budget.control(),(&app,p,&audit,id,&input),|ctx,tx|Box::pin(async move {
        let (app,p,audit,id,input)=ctx;
        let mut context=(*app,*p,*id,*input);
        let (value,replayed)=tx.with_connection_context(&mut context,|(app,p,id,input),c|Box::pin(async move {
            rss_mdm_authorization_service::lock_on(c,p.tenant_id(),p.instance_id()).await?;
            let rules=rss_mdm_authorization_service::snapshot_on(c,p.tenant_id(),p.instance_id()).await?;
            rules.require(p,rss_mdm_authorization_service::Permission::RegistrationConfigurationWrite,None)?;
            let replayed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_wns.versions WHERE tenant_id=$1::uuid AND operation_id=$2 UNION ALL SELECT 1 FROM mdm_wns.revocations WHERE tenant_id=$1::uuid AND operation_id=$2)").bind(p.tenant_id()).bind(*id).fetch_one(&mut *c).await.map_err(db)?;
            let actor=format!("{}:{}:{}",p.tenant_id(),p.instance_id(),p.principal_id());
            let value=match input {Change::Import(input)=>Operation::Material(prepare(c,p.tenant_id(),*id,&actor,input,&app.protection).await?),Change::Revoke(input)=>Operation::Revocation(revoke(c,p.tenant_id(),*id,&actor,input,&app.protection).await?)};
            p.check_live()?;Ok::<_,Error>((value,replayed))
        })).await?;
        let bytes=serde_json::to_vec(&(*id,value.revision())).map_err(corrupt)?;
        let fact=rss_mdm_audit_integration::Fact::business(audit,&format!("wns-material:{id}"),&bytes,202,"success",None).map_err(corrupt)?;
        app.audit_store.append(tx,&fact,replayed).await?;
        if replayed {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
        audit.mark_commit_started();Ok(value)
    })).await;
    crate::operations::settle(result, &audit)
        .map(|value| (axum::http::StatusCode::ACCEPTED, axum::Json(value)))
}

pub async fn rewrap(c: &mut PgConnection, tenant: &str, key: &Protector) -> Result<u64, Error> {
    let prefix = key.ciphertext_prefix();
    let rows:Vec<(i64,Vec<u8>)>=sqlx::query_as("SELECT revision,material FROM mdm_wns.versions WHERE tenant_id=$1::uuid AND substring(material FROM 1 FOR $2)<>$3 ORDER BY revision LIMIT 64 FOR UPDATE").bind(tenant).bind(prefix.len() as i32).bind(prefix).fetch_all(&mut *c).await.map_err(db)?;
    for (revision, bytes) in &rows {
        let wrapped = key
            .rewrap_bytes(bytes, &aad(tenant, *revision)?)
            .map_err(corrupt)?;
        sqlx::query(
            "UPDATE mdm_wns.versions SET material=$3 WHERE tenant_id=$1::uuid AND revision=$2",
        )
        .bind(tenant)
        .bind(revision)
        .bind(wrapped)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    }
    Ok(rows.len() as u64)
}

/// 目录和独立读取入口共享同一授权及状态 owner。
pub async fn snapshot(
    store: &crate::Store,
    p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
) -> Result<Directory, Error> {
    p.require(
        rss_mdm_authorization_service::Permission::RegistrationConfigurationRead,
        None,
    )?;
    let mut tx = store.begin_read(p.tenant_id()).await?;
    let values = directory(&mut tx, p.tenant_id()).await?;
    tx.rollback().await.map_err(db)?;
    p.check_live()?;
    Ok(values)
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeRequest {
    pub expected_revision: i64,
    pub material_revision: i64,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Revocation {
    pub operation_id: Uuid,
    pub revision: i64,
    pub material_revision: i64,
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "receipt", rename_all = "snake_case")]
pub enum Operation {
    Material(Receipt),
    Revocation(Revocation),
}
impl Operation {
    fn revision(&self) -> i64 {
        match self {
            Self::Material(r) => r.revision,
            Self::Revocation(r) => r.revision,
        }
    }
}
enum Change {
    Import(Request),
    Revoke(RevokeRequest),
}
pub async fn revoke(
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
    actor: &str,
    input: &RevokeRequest,
    key: &Protector,
) -> Result<Revocation, Error> {
    if id.is_nil() || input.expected_revision < 0 || input.material_revision < 1 {
        return Err(Error::Malformed);
    }
    let bytes = Zeroizing::new(serde_json::to_vec(&("revoke", actor, input)).map_err(corrupt)?);
    let binding = request_aad(tenant, id)?;
    if let Some(row) = sqlx::query(
        "SELECT * FROM mdm_wns.revocations WHERE tenant_id=$1::uuid AND operation_id=$2",
    )
    .bind(tenant)
    .bind(id)
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?
    {
        key.verify_mac_with_key(
            &row.try_get::<String, _>("fingerprint_key").map_err(db)?,
            &bytes,
            &binding,
            &row.try_get::<Vec<u8>, _>("fingerprint").map_err(db)?,
        )
        .map_err(|_| Error::Conflict)?;
        return Ok(Revocation {
            operation_id: id,
            revision: row.try_get("revision").map_err(db)?,
            material_revision: row.try_get("material_revision").map_err(db)?,
        });
    }
    let used:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_wns.versions WHERE tenant_id=$1::uuid AND operation_id=$2)").bind(tenant).bind(id).fetch_one(&mut *c).await.map_err(db)?;
    if used {
        return Err(Error::Conflict);
    }
    let head: i64 = sqlx::query_scalar(
        "SELECT revision FROM mdm_wns.heads WHERE tenant_id=$1::uuid FOR UPDATE",
    )
    .bind(tenant)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if head != input.expected_revision {
        return Err(Error::Conflict);
    }
    let revision = head.checked_add(1).ok_or(Error::Conflict)?;
    let updated = sqlx::query(
        "UPDATE mdm_wns.versions SET revoked=true WHERE tenant_id=$1::uuid AND revision=$2",
    )
    .bind(tenant)
    .bind(input.material_revision)
    .execute(&mut *c)
    .await
    .map_err(db)?;
    if updated.rows_affected() != 1 {
        return Err(Error::NotFound);
    }
    let fingerprint = key.mac(&bytes, &binding).map_err(corrupt)?;
    sqlx::query("INSERT INTO mdm_wns.revocations VALUES($1::uuid,$2,$3,$4,$5,$6)")
        .bind(tenant)
        .bind(id)
        .bind(revision)
        .bind(input.material_revision)
        .bind(key.fingerprint_id())
        .bind(fingerprint.as_slice())
        .execute(&mut *c)
        .await
        .map_err(db)?;
    sqlx::query("UPDATE mdm_wns.heads SET revision=$2 WHERE tenant_id=$1::uuid")
        .bind(tenant)
        .bind(revision)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(Revocation {
        operation_id: id,
        revision,
        material_revision: input.material_revision,
    })
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    #[test]
    fn published_wns_schema_matches_the_runtime_contract() {
        let actual = serde_json::json!({"Import":schemars::schema_for!(Request),"Revoke":schemars::schema_for!(RevokeRequest),"Operation":schemars::schema_for!(Operation),"Directory":schemars::schema_for!(Directory)});
        let published: serde_json::Value =
            serde_json::from_str(include_str!("../schema/Wns.json")).unwrap();
        assert_eq!(actual, published);
    }
}
