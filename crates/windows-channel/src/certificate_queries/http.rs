use super::*;
use axum::{
    Extension, Json,
    extract::{Path, Query as HttpQuery, State},
};
use rss_mdm_authorization_service::context::RequestAuth;
use rss_mdm_http_contract::{
    CollectionResponse, Operation as RouteOperation, Router, catalog as contracts,
    query::{Directory, DirectoryOwner, OwnedQuery},
    routing::get,
};
use std::sync::Arc;
struct Requests;
impl DirectoryOwner for Requests {
    fn schema() -> &'static Schema {
        &REQUESTS
    }
}
struct Operations;
impl DirectoryOwner for Operations {
    fn schema() -> &'static Schema {
        &pki::OPERATIONS
    }
}
pub fn mount(state: Option<Arc<crate::HttpState>>) -> Router {
    Router::new()
        .route("/api/v1/devices/{device}/windows-certificate-requests",get(list).owned(&contracts::WINDOWS_CERTIFICATE_REQUESTS,&[RouteOperation::List]))
        .route("/api/v1/devices/{device}/windows-certificate-requests/{attempt}",get(read).owned(&contracts::WINDOWS_CERTIFICATE_REQUESTS,&[RouteOperation::Get]))
        .route("/api/v1/devices/{device}/windows-certificate-requests/{attempt}/recovery-operations",get(operations).owned(&contracts::WINDOWS_SIGNING_RECOVERY_OPERATIONS,&[RouteOperation::List]))
        .route("/api/v1/devices/{device}/windows-certificate-requests/{attempt}/recovery-operations/{operation}",get(operation).owned(&contracts::WINDOWS_SIGNING_RECOVERY_OPERATION,&[RouteOperation::Get]))
        .bind_with(state.as_ref(),Clone::clone)
}
fn proof<'a>(
    app: &crate::HttpState,
    auth: &'a RequestAuth,
) -> Result<&'a AuthorizedPrincipal, Error> {
    if auth.proof.tenant_id() != app.identity.tenant().to_string() {
        return Err(Error::Forbidden);
    }
    auth.proof.check_live()?;
    Ok(&auth.proof)
}
async fn list(
    State(app): State<Arc<crate::HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(device): Path<String>,
    query: OwnedQuery<Directory<Requests>>,
) -> Result<CollectionResponse<Json<Page<Projection<Request>>>>, Error> {
    let p = proof(&app, &auth)?;
    let now = app
        .clock
        .unix_seconds()
        .ok_or(Error::Unavailable(Failure::Clock))?;
    let q = query.parse().map_err(|_| Error::Malformed)?;
    app.access
        .certificate_requests(p, &device, &q, &app.query_cursor, now)
        .await
        .map(Json)
        .map(CollectionResponse)
}
async fn read(
    State(app): State<Arc<crate::HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path((device, attempt)): Path<(String, Uuid)>,
) -> Result<Json<Request>, Error> {
    let p = proof(&app, &auth)?;
    let now = app
        .clock
        .unix_seconds()
        .ok_or(Error::Unavailable(Failure::Clock))?;
    app.access
        .certificate_request(p, &device, attempt, now)
        .await
        .map(Json)
}
async fn operations(
    State(app): State<Arc<crate::HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path((device, attempt)): Path<(String, Uuid)>,
    query: OwnedQuery<Directory<Operations>>,
) -> Result<CollectionResponse<Json<Page<Projection<pki::Operation>>>>, Error> {
    let p = proof(&app, &auth)?;
    let q = query.parse().map_err(|_| Error::Malformed)?;
    app.access
        .certificate_recovery_operations(p, &device, attempt, &q, &app.query_cursor)
        .await
        .map(Json)
        .map(CollectionResponse)
}
async fn operation(
    State(app): State<Arc<crate::HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path((device, attempt, operation)): Path<(String, Uuid, Uuid)>,
    HttpQuery(identity): HttpQuery<pki::ReceiptIdentity>,
) -> Result<Json<Option<rss_mdm_pki_service::recovery::Receipt>>, Error> {
    let p = proof(&app, &auth)?;
    app.access
        .certificate_recovery_operation(p, &device, attempt, operation, &identity)
        .await
        .map(Json)
}
