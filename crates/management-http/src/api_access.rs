//! Tenant key management and installation-wide programmatic admission.
use crate::Error;
use axum::{
    Extension, Json,
    extract::{Path, Request, State},
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
use rss_mdm_http_contract::{Router, routing::post};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

pub struct Management {
    pub cursor: rss_mdm_query::cursor::CursorCodec,
    pub access: Arc<rss_mdm_authorization_service::Store>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
}
pub fn key_routes(
    state: Arc<Management>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register_keys().with_state(state)
}
pub(crate) fn register_keys()
-> Router<Arc<Management>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RegisterKeysModule1 for [Browser] { get_list, post_create, get_detail, put_update, post_rotate, post_revoke } }
        RegisterKeysModule1 {
            get_list: rss_mdm_http_contract::module::Route::new(
                "/api-keys",
                rss_mdm_http_contract::routing::get(
                    list,
                    &contracts::API_KEYS,
                    &[RouteOperation::List],
                ),
            ),
            post_create: rss_mdm_http_contract::module::Route::new(
                "/api-keys",
                rss_mdm_http_contract::routing::post(
                    create,
                    &contracts::API_KEYS,
                    &[RouteOperation::Create],
                ),
            ),
            get_detail: rss_mdm_http_contract::module::Route::new(
                "/api-keys/{id}",
                rss_mdm_http_contract::routing::get(
                    detail,
                    &contracts::API_KEYS,
                    &[RouteOperation::Get],
                ),
            ),
            put_update: rss_mdm_http_contract::module::Route::new(
                "/api-keys/{id}",
                rss_mdm_http_contract::routing::put(
                    update,
                    &contracts::API_KEYS,
                    &[RouteOperation::Update],
                ),
            ),
            post_rotate: rss_mdm_http_contract::module::Route::new(
                "/api-keys/{id}/rotate",
                post(
                    rotate,
                    &contracts::API_KEYS,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
            post_revoke: rss_mdm_http_contract::module::Route::new(
                "/api-keys/{id}/revoke",
                post(revoke, &contracts::API_KEYS, &[RouteOperation::Lifecycle]),
            ),
        }
        .assemble()
    }
}
pub fn network_routes(
    state: Arc<Management>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register_network().with_state(state)
}
pub(crate) fn register_network()
-> Router<Arc<Management>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RegisterNetworkModule1 for [Browser] { get_network, put_network_change } }
        RegisterNetworkModule1 {
            get_network: rss_mdm_http_contract::module::Route::new(
                "/api-access/network-policy",
                rss_mdm_http_contract::routing::get(
                    network,
                    &contracts::API_NETWORK_POLICY,
                    &[RouteOperation::Get],
                ),
            ),
            put_network_change: rss_mdm_http_contract::module::Route::new(
                "/api-access/network-policy",
                rss_mdm_http_contract::routing::put(
                    network_change,
                    &contracts::API_NETWORK_POLICY,
                    &[RouteOperation::Update],
                ),
            ),
        }
        .assemble()
    }
}
async fn list(
    State(state): State<Arc<Management>>,
    Extension(auth): Extension<RequestAuth>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<KeysQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<
                    rss_mdm_authorization_service::directory::KeyRow,
                >,
            >,
        >,
    >,
    Error,
> {
    (async {
        use rss_mdm_authorization_service::directory::{self, Directory};
        let q = query.parse().map_err(|_| Error::Malformed)?;
        Ok(Json(
            directory::list(
                &state.audit,
                &auth.proof,
                &state.cursor,
                Directory::Keys,
                &q,
            )
            .await?
            .ok_or(Error::NotFound)?
            .keys()?,
        ))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn detail(
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_authorization_service::api_key::KeyRecord>, Error> {
    auth.proof.user()?;
    auth.proof.require(
        rss_mdm_authorization_service::Permission::AuthorizationRead,
        None,
    )?;
    Ok(Json(
        auth.proof
            .authorization()?
            .key_record(id)
            .cloned()
            .ok_or(Error::NotFound)?,
    ))
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Create {
    id: Uuid,
    operation_id: Uuid,
    metadata: KeyMetadata,
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Update {
    operation_id: Uuid,
    expected_revision: u64,
    metadata: KeyMetadata,
}
#[derive(schemars::JsonSchema, Deserialize)]
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
) -> Result<Json<KeyChangeBody>, Error> {
    let result = api_key_store::change_key(&state.audit, &auth.proof, id, change, audit).await?;
    Ok(Json(KeyChangeBody(result)))
}
async fn create(
    State(state): State<Arc<Management>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<Json<Create>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<KeyChangeBody>, Error> {
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
) -> Result<Json<KeyChangeBody>, Error> {
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
) -> Result<Json<KeyChangeBody>, Error> {
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
) -> Result<Json<KeyChangeBody>, Error> {
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

struct KeysQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for KeysQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_authorization_service::directory::KEYS
    }
}

/// Secret exposure remains confined to this management response boundary.
#[derive(schemars::JsonSchema)]
#[schemars(transparent)]
struct KeyChangeBody(api_key_store::KeyChangeResult);
impl serde::Serialize for KeyChangeBody {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut output = serializer.serialize_struct("KeyChangeResult", 2)?;
        output.serialize_field("receipt", &self.0.receipt)?;
        output.serialize_field(
            "secret",
            &self.0.secret.as_ref().map(|secret| secret.expose()),
        )?;
        output.end()
    }
}
