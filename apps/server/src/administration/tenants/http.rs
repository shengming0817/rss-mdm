//! Installation tenant HTTP adapter; CLI and HTTP share the registry mutation owner.
use super::*;
use super::directory;
use super::service::{Service,Read,ReadReply};
use super::provisioning::Provision;
use super::administrator::AdministratorInput;
use crate::installation::model::Phase;
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::HeaderMap,
};
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{
    Permission,
    context::{AuthorizedPrincipal, RequestAuth},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use rss_request_context::TenantId;
use serde::Deserialize;
use sqlx::PgPool;
use std::{path::PathBuf, sync::Arc};

#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateBody {
    expected_revision: i64,
    name: Option<String>,
    notes: Option<String>,
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeleteBody {
    expected_revision: i64,
}
fn operation(headers: &HeaderMap) -> std::result::Result<Uuid, Error> {
    let mut values = headers.get_all("Idempotency-Key").iter();
    let text = values
        .next()
        .ok_or(Error::Malformed)?
        .to_str()
        .map_err(|_| Error::Malformed)?;
    let id = Uuid::parse_str(text).map_err(|_| Error::Malformed)?;
    if values.next().is_some() || id.is_nil() || id.to_string() != text {
        return Err(Error::Malformed);
    }
    Ok(id)
}
pub(crate) fn routes(
    service: Option<Arc<Service>>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    let enabled = service.is_some();
    mount_registry(service, enabled)
}
pub(crate) fn mount_registry(
    runtime: Option<Arc<Service>>,
    enabled: bool,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
 rss_mdm_http_contract::route_module! { struct MountRegistryModule1 for [Browser] { get_list, get_provisionings, post_create, get_receipt, get_detail, put_update, delete_delete, post_administrator, get_receipt_2 } }
 MountRegistryModule1 { get_list: rss_mdm_http_contract::module::Route::new("/tenants", get(list, &contracts::TENANTS, &[RouteOperation::List])),
get_provisionings: rss_mdm_http_contract::module::Route::new("/provisionings", rss_mdm_http_contract::routing::get(provisionings, &contracts::PROVISIONINGS, &[RouteOperation::List])),
post_create: rss_mdm_http_contract::module::Route::new("/provisionings", rss_mdm_http_contract::routing::post(provisioning::create, &contracts::TENANTS, &[RouteOperation::Create])),
get_receipt: rss_mdm_http_contract::module::Route::new("/provisionings/{operation}", get(receipt, &contracts::PROVISIONINGS, &[RouteOperation::Get])),
get_detail: rss_mdm_http_contract::module::Route::new("/tenants/{tenant}", rss_mdm_http_contract::routing::get(detail, &contracts::TENANTS, &[RouteOperation::Get])),
put_update: rss_mdm_http_contract::module::Route::new("/tenants/{tenant}", rss_mdm_http_contract::routing::put(update, &contracts::TENANTS, &[RouteOperation::Update])),
delete_delete: rss_mdm_http_contract::module::Route::new("/tenants/{tenant}", rss_mdm_http_contract::routing::delete(delete, &contracts::TENANTS, &[RouteOperation::Delete])),
post_administrator: rss_mdm_http_contract::module::Route::new("/tenants/{tenant}/administrators", post(administrator, &contracts::TENANTS, &[RouteOperation::Action])),
get_receipt_2: rss_mdm_http_contract::module::Route::new("/operations/{operation}", get(receipt, &contracts::PROVISIONINGS, &[RouteOperation::Get])) }.assemble()
}
        .bind_with(runtime.as_ref(), Clone::clone).when("tenant_administration", enabled)
}
async fn list(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<TenantDirectory>,
    >,
) -> std::result::Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<Tenant>>>,
    >,
    HttpFailure,
> {
    (async {
        let q = query.parse().map_err(|_| HttpFailure(Error::Malformed))?;
        service
            .read(&auth.proof, Read::List(q))
            .await
            .and_then(ReadReply::list)
            .map(Json)
            .map_err(HttpFailure)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn provisionings(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<ProvisioningDirectory>,
    >,
) -> std::result::Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<Receipt>>>,
    >,
    HttpFailure,
> {
    (async {
        let q = query.parse().map_err(|_| HttpFailure(Error::Malformed))?;
        service
            .read(&auth.proof, Read::Provisionings(q))
            .await
            .and_then(ReadReply::provisionings)
            .map(Json)
            .map_err(HttpFailure)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn detail(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    Path(tenant): Path<String>,
) -> std::result::Result<Json<Tenant>, HttpFailure> {
    service
        .read(&auth.proof, Read::Tenant(tenant))
        .await
        .and_then(ReadReply::tenant)
        .map(Json)
        .map_err(HttpFailure)
}
async fn receipt(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    path: std::result::Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
) -> std::result::Result<Json<Receipt>, HttpFailure> {
    service
        .read(
            &auth.proof,
            Read::Operation(path.map_err(|_| HttpFailure(Error::Malformed))?.0),
        )
        .await
        .and_then(ReadReply::receipt)
        .map(Json)
        .map_err(HttpFailure)
}
async fn update(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(tenant): Path<String>,
    WriteHeaders(headers): WriteHeaders,
    body: std::result::Result<Json<UpdateBody>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Receipt>, HttpFailure> {
    let Json(body) = body.map_err(|e| HttpFailure(Error::Http(e.into())))?;
    service
        .mutate(
            &auth.proof,
            &audit,
            Mutation {
                installation: &service.installation,
                tenant_id: &tenant,
                operation_id: operation(&headers)?,
                action: Action::Update,
                initial_epoch: None,
                expected_revision: Some(body.expected_revision),
                name: body.name.as_deref(),
                notes: body.notes.as_deref(),
            },
        )
        .await
        .map(Json)
        .map_err(HttpFailure)
}
async fn delete(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(tenant): Path<String>,
    WriteHeaders(headers): WriteHeaders,
    body: std::result::Result<Json<DeleteBody>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Receipt>, HttpFailure> {
    let Json(body) = body.map_err(|e| HttpFailure(Error::Http(e.into())))?;
    service
        .mutate(
            &auth.proof,
            &audit,
            Mutation {
                installation: &service.installation,
                tenant_id: &tenant,
                operation_id: operation(&headers)?,
                action: Action::Delete,
                initial_epoch: None,
                expected_revision: Some(body.expected_revision),
                name: None,
                notes: None,
            },
        )
        .await
        .map(Json)
        .map_err(HttpFailure)
}
#[path = "provisioning.rs"]
mod provisioning;


#[derive(Debug)]
pub(super) struct HttpFailure(Error);
impl From<Error> for HttpFailure {
    fn from(error: Error) -> Self {
        Self(error)
    }
}
impl axum::response::IntoResponse for HttpFailure {
    fn into_response(self) -> axum::response::Response {
        use rss_mdm_management_http::Error as Http;
        let error = match self.0 {
            Error::Http(error) => error,
            Error::Malformed => Http::Malformed,
            Error::Unauthorized => Http::Unauthorized,
            Error::Forbidden => Http::Forbidden,
            Error::Conflict => Http::Conflict,
            Error::CommitUnknown => Http::CommitUnknown,
            Error::RollbackFailed => Http::RollbackFailed,
            Error::Authorization(error) => error.into(),
            Error::Unavailable(reason) => {
                use rss_mdm_management_http::Failure as F;
                Http::Unavailable(match reason {
                    Failure::RequestDeadline => F::RequestDeadline,
                    Failure::Audit => F::Audit,
                    Failure::AuditIntegrity => F::AuditIntegrity,
                    Failure::AuditIsolation => F::AuditIsolation,
                    Failure::AuditAdmission => F::AuditAdmission,
                    Failure::AuditContract => F::AuditContract,

                    _ => F::Database,
                })
            }
            _ => Http::Unavailable(rss_mdm_management_http::Failure::Database),
        };
        error.into_response()
    }
}

struct TenantDirectory;
impl rss_mdm_http_contract::query::DirectoryOwner for TenantDirectory {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &directory::TENANTS
    }
}

struct ProvisioningDirectory;
impl rss_mdm_http_contract::query::DirectoryOwner for ProvisioningDirectory {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &directory::PROVISIONINGS
    }
}

impl rss_mdm_http_contract::signature::Output for HttpFailure {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        <rss_mdm_management_http::Error as rss_mdm_http_contract::signature::Output>::responses()
    }
}
pub(super) struct WriteHeaders(HeaderMap);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for WriteHeaders {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl rss_mdm_http_contract::signature::Input for WriteHeaders {
    fn request() -> rss_mdm_http_contract::signature::Request {
        let mut request = rss_mdm_http_contract::signature::Request::default();
        let mut schema = rss_mdm_http_contract::signature::Schema::request::<Uuid>();
        schema.value["not"] = serde_json::json!({"const":"00000000-0000-0000-0000-000000000000"});
        request.headers.insert("idempotency-key".into(), schema);
        request.required_headers.push("idempotency-key");
        request
    }
}

#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub(super) async fn create(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    WriteHeaders(headers): WriteHeaders,
    body: std::result::Result<Json<Provision>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<ProvisioningResponse, HttpFailure> {
    let Json(body) = body.map_err(|e| HttpFailure(Error::Http(e.into())))?;
    let operation = operation(&headers)?;
    let receipt = service
        .provision(&auth.proof, &audit, operation, &body)
        .await?;
    Ok(ProvisioningResponse(receipt))
}

pub(super) struct ProvisioningResponse(Receipt);
impl ProvisioningResponse {
    fn status(&self) -> u16 {
        if matches!(&self.0.result,ReceiptResult::Provisioning(p) if p.phase==Phase::Enabled) {
            200
        } else {
            202
        }
    }
}
impl axum::response::IntoResponse for ProvisioningResponse {
    fn into_response(self) -> axum::response::Response {
        (
            axum::http::StatusCode::from_u16(self.status()).expect("provisioning status"),
            Json(self.0),
        )
            .into_response()
    }
}
impl rss_mdm_http_contract::signature::Output for ProvisioningResponse {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        [200, 202]
            .into_iter()
            .map(rss_mdm_http_contract::signature::Response::json::<Receipt>)
            .collect()
    }
}
pub(super) async fn administrator(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(tenant): Path<String>,
    WriteHeaders(headers): WriteHeaders,
    body: std::result::Result<Json<AdministratorInput>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Receipt>, HttpFailure> {
    service
        .create_administrator(
            &auth.proof,
            &audit,
            &tenant,
            operation(&headers)?,
            body.map_err(|e| HttpFailure(Error::Http(e.into())))?.0,
        )
        .await
        .map(Json)
        .map_err(HttpFailure)
}
