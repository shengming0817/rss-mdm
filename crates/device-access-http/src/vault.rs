//! Self-service ciphertext sync; no management permissions or device enrollment required.
use crate::business_error::Error;
use axum::{Extension, Json, extract::State};
use rss_mdm_agent_wire::vault::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::RequestAuth;
use rss_mdm_http_contract::{
    Category, Operation, QueryPolicy, Resource, Router, module::Route, routing::post,
};
use std::sync::Arc;
static RESOURCE: Resource = Resource {
    id: "protocol_vault_sync",
    category: Category::Protocol,
    owner: "vault-sync",
    proof: "vault.sync",
    query: QueryPolicy::Protocol,
    collection: None,
};
pub fn routes(
    state: Option<Arc<rss_mdm_vault_sync::Service>>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! {struct VaultRoutes for [Browser]{prepare,execute}}
    VaultRoutes {
        prepare: Route::new(
            "/api/v1/da/vault/challenges",
            post(prepare, &RESOURCE, &[Operation::Action]),
        ),
        execute: Route::new(
            "/api/v1/da/vault/execute",
            post(execute, &RESOURCE, &[Operation::Action]),
        ),
    }
    .assemble()
    .bind_with(state.as_ref(), Arc::clone)
}
async fn prepare(
    State(s): State<Arc<rss_mdm_vault_sync::Service>>,
    Extension(p): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    body: Result<Json<Prepare>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Challenge>, Error> {
    s.prepare(&p.proof, &a, body.map_err(|_| Error::Malformed)?.0)
        .await
        .map(Json)
        .map_err(map)
}
async fn execute(
    State(s): State<Arc<rss_mdm_vault_sync::Service>>,
    Extension(p): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    body: Result<Json<Execute>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Response>, Error> {
    s.execute(&p.proof, &a, body.map_err(|_| Error::Malformed)?.0)
        .await
        .map(Json)
        .map_err(map)
}
fn map(e: rss_mdm_vault_sync::Error) -> Error {
    use rss_mdm_vault_sync::Error as E;
    match e {
        E::Invalid => Error::Malformed,
        E::Denied => Error::Forbidden,
        E::Conflict => Error::Conflict,
        E::NotFound => Error::NotFound,
        E::Capacity => Error::RequestTooLarge,
        E::Cursor => Error::CursorInvalidated,
        E::Storage => Error::Unavailable,
        E::CommitUnknown => Error::CommitUnknown,
        E::RollbackFailed => Error::RollbackFailed,
    }
}
