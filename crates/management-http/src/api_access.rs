//! Tenant key management and installation-wide programmatic admission.
use crate::Error;
use axum::{
    Extension, Json,
    extract::{Path, Query, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{
    api_key::KeyMetadata,
    api_key_store::{self, KeyChange, KeyMutation},
    context::RequestAuth,
    network_policy::{self, NetworkChange},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

pub struct Management {
    pub access: Arc<rss_mdm_authorization_service::Store>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
}
pub fn key_routes(state: Arc<Management>) -> Router {
    Router::new()
        .route(
            "/api-keys",
            get(list)
                .owned(&contracts::API_KEYS, &[RouteOperation::List])
                .post(create)
                .owned(&contracts::API_KEYS, &[RouteOperation::Create]),
        )
        .route(
            "/api-keys/{id}",
            get(detail)
                .owned(&contracts::API_KEYS, &[RouteOperation::Get])
                .put(update)
                .owned(&contracts::API_KEYS, &[RouteOperation::Update]),
        )
        .route(
            "/api-keys/{id}/rotate",
            post(rotate).owned(&contracts::API_KEYS, &[RouteOperation::Action]),
        )
        .route(
            "/api-keys/{id}/revoke",
            post(revoke).owned(&contracts::API_KEYS, &[RouteOperation::Lifecycle]),
        )
        .with_state(state)
}
pub fn network_routes(state: Arc<Management>) -> Router {
    Router::new()
        .route(
            "/api-access/network-policy",
            get(network)
                .owned(&contracts::API_NETWORK_POLICY, &[RouteOperation::Get])
                .put(network_change)
                .owned(&contracts::API_NETWORK_POLICY, &[RouteOperation::Update]),
        )
        .with_state(state)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Page {
    after: Option<Uuid>,
}
async fn list(
    Extension(auth): Extension<RequestAuth>,
    Query(page): Query<Page>,
) -> Result<Json<Value>, Error> {
    let (items, next) = api_key_store::list_keys(&auth.proof, page.after)?;
    Ok(Json(json!({"items": items, "nextCursor": next})))
}
async fn detail(
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, Error> {
    auth.proof.user()?;
    auth.proof.require(
        rss_mdm_authorization_service::Permission::AuthorizationRead,
        None,
    )?;
    Ok(Json(
        serde_json::to_value(
            auth.proof
                .authorization()?
                .key_record(id)
                .ok_or(Error::NotFound)?,
        )
        .map_err(|_| Error::Malformed)?,
    ))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Create {
    id: Uuid,
    operation_id: Uuid,
    metadata: KeyMetadata,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Update {
    operation_id: Uuid,
    expected_revision: u64,
    metadata: KeyMetadata,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Mutation {
    operation_id: Uuid,
    expected_revision: u64,
}
async fn apply(
    state: &Management,
    auth: &RequestAuth,
    audit: &RequestAudit,
    id: Uuid,
    change: KeyChange,
) -> Result<Json<Value>, Error> {
    let result = api_key_store::change_key(&state.audit, &auth.proof, id, change, audit).await?;
    Ok(Json(
        json!({"receipt": result.receipt, "secret": result.secret.as_ref().map(|secret| secret.expose())}),
    ))
}
async fn create(
    State(state): State<Arc<Management>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<Json<Create>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, Error> {
    let Json(input) = body.map_err(Error::from)?;
    apply(
        &state,
        &auth,
        &audit,
        input.id,
        KeyChange {
            operation_id: input.operation_id,
            expected_revision: 0,
            mutation: KeyMutation::Create {
                metadata: input.metadata,
            },
        },
    )
    .await
}
async fn update(
    State(state): State<Arc<Management>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Update>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, Error> {
    let Json(input) = body.map_err(Error::from)?;
    apply(
        &state,
        &auth,
        &audit,
        id,
        KeyChange {
            operation_id: input.operation_id,
            expected_revision: input.expected_revision,
            mutation: KeyMutation::Update {
                metadata: input.metadata,
            },
        },
    )
    .await
}
async fn rotate(
    State(state): State<Arc<Management>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Mutation>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, Error> {
    let Json(input) = body.map_err(Error::from)?;
    apply(
        &state,
        &auth,
        &audit,
        id,
        KeyChange {
            operation_id: input.operation_id,
            expected_revision: input.expected_revision,
            mutation: KeyMutation::Rotate,
        },
    )
    .await
}
async fn revoke(
    State(state): State<Arc<Management>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Mutation>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, Error> {
    let Json(input) = body.map_err(Error::from)?;
    apply(
        &state,
        &auth,
        &audit,
        id,
        KeyChange {
            operation_id: input.operation_id,
            expected_revision: input.expected_revision,
            mutation: KeyMutation::Revoke,
        },
    )
    .await
}
async fn network(
    State(state): State<Arc<Management>>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<network_policy::NetworkPolicy>, Error> {
    state
        .access
        .network_policy(&auth.proof)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn network_change(
    State(state): State<Arc<Management>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<Json<NetworkChange>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<network_policy::NetworkPolicy>, Error> {
    let Json(change) = body.map_err(Error::from)?;
    network_policy::change_network_policy(&state.audit, &auth.proof, change, &audit)
        .await
        .map(Json)
        .map_err(Into::into)
}

pub struct BearerAdmission {
    pub access: Arc<rss_mdm_authorization_service::Store>,
    pub tenant: String,
}
/// Marks a product rejection before Identity can own authentication settlement.
#[derive(Clone, Copy)]
pub(crate) struct AdmissionRejected;
pub async fn admit_bearer(
    State(state): State<Arc<BearerAdmission>>,
    request: Request,
    next: Next,
) -> Response {
    let audit = request
        .extensions()
        .get::<rss_mdm_audit_integration::RequestAudit>()
        .cloned();
    let reject = |error: Error| {
        // This owner distinguishes a tenant/network boundary violation from ordinary
        // authentication noise. The Identity SDK still owns settled authentication events.
        if matches!(error, Error::Forbidden)
            && let Some(audit) = &audit
        {
            audit.intent(rss_mdm_audit_integration::AuditIntent::Security);
        }
        let mut response = error.into_response();
        response.extensions_mut().insert(AdmissionRejected);
        response
    };
    if request.headers().contains_key("x-api-key") {
        return reject(Error::Malformed);
    }
    let permitted = request
        .uri()
        .path()
        .strip_prefix("/api/v1/identity/tenants/")
        .is_some_and(|path| path.split('/').next() == Some(state.tenant.as_str()));
    if !permitted {
        return reject(Error::Forbidden);
    }
    let Some(address) = request
        .extensions()
        .get::<rss_identity_http_axum::ClientAddress>()
        .map(|address| address.0)
    else {
        return reject(Error::Forbidden);
    };
    match state.access.require_api_source(address).await {
        Ok(()) => next.run(request).await,
        Err(error) => reject(error.into()),
    }
}
