//! Apple runtime material authority. Candidates, selected revisions and runtime observations differ.
mod crypto;
pub mod runtime;
mod storage;
use crate::{Error, Failure, HttpState, database::db};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{
    Permission,
    context::{AuthorizedPrincipal, RequestAuth},
};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const INSTALL_SQL: &str = include_str!("../../schema/runtime-materials.sql");
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Apns,
    Profile,
    ManagedAccount,
}
impl Purpose {
    pub fn name(self) -> &'static str {
        match self {
            Self::Apns => "apns",
            Self::Profile => "profile",
            Self::ManagedAccount => "managed_account",
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeySource {
    Generate,
    Import { private_key_pem: Zeroizing<String> },
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyRequest {
    expected_revision: i64,
    source: KeySource,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificateRequest {
    expected_revision: i64,
    key_revision: i64,
    certificate_chain_pem: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyRequest {
    expected_revision: i64,
    material_revision: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicVersion {
    pub revision: i64,
    pub key_id: Uuid,
    pub public_key_digest: String,
    pub csr: String,
    pub certificate_chain_pem: Option<String>,
    pub certificate_digest: Option<String>,
    pub topic: Option<String>,
    pub expires_at: Option<i64>,
    pub revoked: bool,
}
pub(crate) fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/api/v1/apple/materials/{purpose}", get(status))
        .route("/api/v1/apple/materials/{purpose}/keys", post(key))
        .route(
            "/api/v1/apple/materials/{purpose}/certificates",
            post(certificate),
        )
        .route("/api/v1/apple/materials/{purpose}/apply", post(apply))
        .route(
            "/api/v1/apple/material-operations/{operation}",
            get(operation),
        )
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
}
fn now(app: &HttpState) -> Result<i64, Error> {
    app.clock
        .unix_seconds()
        .ok_or(Error::Unavailable(Failure::Clock))
}
fn proof<'a>(
    app: &HttpState,
    auth: &'a RequestAuth,
    write: bool,
) -> Result<&'a AuthorizedPrincipal, Error> {
    let p = &auth.proof;
    if p.tenant_id() != app.identity.tenant().to_string() {
        return Err(Error::Forbidden);
    }
    p.require(
        if write {
            Permission::RegistrationConfigurationWrite
        } else {
            Permission::RegistrationConfigurationRead
        },
        None,
    )?;
    if write {
        let t = now(app)?;
        let auth_time = p.session()?.view().auth_time;
        if auth_time > t || t.saturating_sub(auth_time) > 300 {
            return Err(Error::Unauthorized);
        }
    }
    Ok(p)
}
fn aad(tenant: &str, purpose: Purpose, revision: i64, key: Uuid) -> Result<DerivedAad, Error> {
    ProtectionContext::new(
        rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
        &format!("{}:{revision}:{key}", purpose.name()),
        "apple.runtime.private-key",
        1,
    )
    .map(|c| c.derive())
    .map_err(|_| Error::Malformed)
}
fn request_aad(tenant: &str, id: Uuid) -> Result<DerivedAad, Error> {
    ProtectionContext::new(
        rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
        &id.to_string(),
        "apple.runtime.operation",
        1,
    )
    .map(|c| c.derive())
    .map_err(|_| Error::Malformed)
}
async fn status(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(purpose): Path<Purpose>,
) -> Result<Json<Value>, Error> {
    let p = proof(&app, &auth, false)?;
    let mut tx = app.access.begin_read(p.tenant_id()).await?;
    let (revision, desired) = storage::head(&mut tx, p.tenant_id(), purpose).await?;
    let values = storage::versions(&mut tx, p.tenant_id(), purpose).await?;
    tx.rollback().await.map_err(db)?;
    p.check_live()?;
    Ok(Json(
        json!({"revision":revision,"desiredRevision":desired,"versions":values,"runtimeObservation":"separate"}),
    ))
}
async fn operation(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(operation): Path<Uuid>,
) -> Result<Json<Value>, Error> {
    let p = proof(&app, &auth, false)?;
    let mut tx = app.access.begin_read(p.tenant_id()).await?;
    let value = storage::receipt(&mut tx, p.tenant_id(), operation)
        .await?
        .ok_or(Error::NotFound)?;
    tx.rollback().await.map_err(db)?;
    p.check_live()?;
    Ok(Json(value))
}
async fn key(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(purpose): Path<Purpose>,
    headers: HeaderMap,
    Json(input): Json<KeyRequest>,
) -> Result<Json<Value>, Error> {
    let p = proof(&app, &auth, true)?;
    let id = crate::account_enrollment::management::operation(&headers)?;
    let request =
        Zeroizing::new(serde_json::to_vec(&(purpose, &input)).map_err(|_| Error::Malformed)?);
    let tenant = p.tenant_id().to_owned();
    let material = tokio::task::spawn_blocking(move || {
        crypto::prepare(
            &tenant,
            purpose,
            match &input.source {
                KeySource::Generate => None,
                KeySource::Import { private_key_pem } => Some(private_key_pem.as_str()),
            },
        )
    })
    .await
    .map_err(|_| Error::Unavailable(Failure::Database))??;
    write(
        &app,
        p,
        &audit,
        id,
        purpose,
        input.expected_revision,
        &request,
        Change::Key(material),
    )
    .await
    .map(Json)
}
async fn certificate(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(purpose): Path<Purpose>,
    headers: HeaderMap,
    Json(input): Json<CertificateRequest>,
) -> Result<Json<Value>, Error> {
    let p = proof(&app, &auth, true)?;
    let id = crate::account_enrollment::management::operation(&headers)?;
    if input.certificate_chain_pem.len() > 128 * 1024 || input.key_revision < 1 {
        return Err(Error::Malformed);
    }
    let request =
        Zeroizing::new(serde_json::to_vec(&(purpose, &input)).map_err(|_| Error::Malformed)?);
    write(
        &app,
        p,
        &audit,
        id,
        purpose,
        input.expected_revision,
        &request,
        Change::Certificate(input),
    )
    .await
    .map(Json)
}
async fn apply(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(purpose): Path<Purpose>,
    headers: HeaderMap,
    Json(input): Json<ApplyRequest>,
) -> Result<Json<Value>, Error> {
    let p = proof(&app, &auth, true)?;
    let id = crate::account_enrollment::management::operation(&headers)?;
    let request =
        Zeroizing::new(serde_json::to_vec(&(purpose, &input)).map_err(|_| Error::Malformed)?);
    write(
        &app,
        p,
        &audit,
        id,
        purpose,
        input.expected_revision,
        &request,
        Change::Apply(input.material_revision),
    )
    .await
    .map(Json)
}
enum Change {
    Key(crypto::Key),
    Certificate(CertificateRequest),
    Apply(i64),
}
#[allow(clippy::too_many_arguments)]
async fn write(
    app: &HttpState,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
    purpose: Purpose,
    expected: i64,
    request: &[u8],
    change: Change,
) -> Result<Value, Error> {
    if expected < 0 || expected == i64::MAX || id.is_nil() {
        return Err(Error::Malformed);
    }
    p.bind_audit(audit)?;
    audit.operation(id, "apple_runtime_material");
    audit.require_request_settlement();
    let fingerprint = app
        .protection
        .mac(request, &request_aad(p.tenant_id(), id)?)
        .map_err(|_| Error::Conflict)?;
    let budget = AuditBudget::new(Duration::from_secs(10));
    let outcome=app.audit_store.write(app.identity.tenant(),&budget.control(),(app,p,audit,id,purpose,expected,request,change,fingerprint),|ctx,tx|Box::pin(async move{
        let(app,p,audit,id,purpose,expected,request,change,fingerprint)=ctx;
        let mut context=(*app,*p,*id,*purpose,*expected,*request,&*change,*fingerprint);
        let (value,replayed,original_fingerprint)=tx.with_connection_context(&mut context,|(app,p,id,purpose,expected,request,change,fingerprint),c|Box::pin(async move{
            rss_mdm_authorization_service::lock_on(c,p.tenant_id(),p.instance_id()).await?;
            let rules=rss_mdm_authorization_service::snapshot_on(c,p.tenant_id(),p.instance_id()).await?;
            rules.require(p,Permission::RegistrationConfigurationWrite,None)?;
            storage::lock(c,p.tenant_id(),*purpose).await?;
            if let Some((value,original))=storage::replay(c,app,p.tenant_id(),*id,request).await? {return Ok((value,true,original));}
            let(current,desired)=storage::head(c,p.tenant_id(),*purpose).await?;
            if current!=*expected{return Err(Error::Conflict);}
            let revision=current.checked_add(1).ok_or(Error::Conflict)?;
            let value=match change {
                Change::Key(key)=>{
                    let key_id=Uuid::new_v4();
                    storage::insert(c,app,p.tenant_id(),*purpose,revision,key_id,key,None).await?;
                    json!({"operationId":id,"revision":revision,"keyId":key_id,"csr":key.csr,"publicKeyDigest":key.public_digest,"state":"awaiting_certificate"})
                },
                Change::Certificate(input)=>{
                    let (previous,private)=storage::material(c,app,p.tenant_id(),*purpose,input.key_revision).await?;
                    let validated=crypto::certificate(*purpose,&input.certificate_chain_pem,private.expose(),&app.material_roots,now(app)?)?;
                    if let Some(selected)=desired {
                        let old=storage::version(c,p.tenant_id(),*purpose,selected).await?;
                        if old.topic.is_some() && old.topic!=validated.topic {return Err(Error::Conflict);}
                    }
                    let key=crypto::Key {private:Zeroizing::new(private.expose().to_vec()),csr:previous.csr,public_digest:previous.public_key_digest};
                    storage::insert(c,app,p.tenant_id(),*purpose,revision,previous.key_id,&key,Some((&input.certificate_chain_pem,&validated))).await?;
                    json!({"operationId":id,"revision":revision,"keyId":previous.key_id,"certificateDigest":validated.digest,"expiresAt":validated.expires,"state":"validated"})
                },
                Change::Apply(selected)=>{
                    let (candidate,private)=storage::material(c,app,p.tenant_id(),*purpose,*selected).await?;
                    if candidate.revoked{return Err(Error::Conflict);}
                    crypto::certificate(*purpose,candidate.certificate_chain_pem.as_deref().ok_or(Error::Conflict)?,private.expose(),&app.material_roots,now(app)?)?;
                    if let Some(old_revision)=desired {
                        let old=storage::version(c,p.tenant_id(),*purpose,old_revision).await?;
                        if old.topic.is_some() && old.topic!=candidate.topic {return Err(Error::Conflict);}
                    }
                    storage::select(c,p.tenant_id(),*purpose,*selected).await?;
                    json!({"operationId":id,"revision":revision,"desiredRevision":selected,"state":"pending_application"})
                }
            };
            storage::save(c,p.tenant_id(),*id,app.protection.id(),fingerprint,&value).await?;
            p.check_live()?;Ok::<_,Error>((value,false,*fingerprint))
        })).await?;
        let fact=Fact::business(audit,&format!("apple-runtime:{id}"),&original_fingerprint,200,"saved",None).map_err(|_|Error::Malformed)?;
        app.audit_store.append(tx,&fact,replayed).await?;
        if replayed {audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);}
        audit.mark_commit_started();Ok(value)
    })).await;
    crate::operations::settle(outcome, audit)
}
