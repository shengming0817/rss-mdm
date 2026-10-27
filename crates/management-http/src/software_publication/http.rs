use super::wire;
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use rss_mdm_software_service::{
    catalog::Operation,
    management::publication::{
        model::Change,
        service::{self, PublicationDirectory},
    },
};
use std::sync::Arc;
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/software/publications",
            get(list)
                .owned(&contracts::PUBLICATIONS, &[RouteOperation::List])
                .post(create)
                .owned(&contracts::PUBLICATIONS, &[RouteOperation::Create]),
        )
        .route(
            "/software/publications/{id}",
            get(read)
                .owned(&contracts::PUBLICATIONS, &[RouteOperation::Get])
                .post(change)
                .owned(&contracts::PUBLICATIONS, &[RouteOperation::Lifecycle]),
        )
        .route(
            "/software/publication-targets",
            get(targets).owned(&contracts::PUBLICATION_TARGETS, &[RouteOperation::List]),
        )
}
async fn read(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
) -> Result<Json<wire::Publication>, Error> {
    service::read(&app.publications, &app.access, &auth.proof, &audit, id)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn create(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<Json<Operation<Change>>, axum::extract::rejection::JsonRejection>,
) -> Result<rss_mdm_http_contract::signature::WithStatus<202, Json<wire::Publication>>, Error> {
    let Json(request) = body.map_err(Error::from)?;
    let value = service::write(
        &app.publications,
        &app.access,
        &auth.proof,
        &audit,
        None,
        request,
    )
    .await?;
    Ok(rss_mdm_http_contract::signature::WithStatus(Json(value)))
}
async fn change(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
    body: Result<Json<Operation<Change>>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<wire::Publication>, Error> {
    let Json(request) = body.map_err(Error::from)?;
    service::write(
        &app.publications,
        &app.access,
        &auth.proof,
        &audit,
        Some(id),
        request,
    )
    .await
    .map(Json)
    .map_err(Into::into)
}
async fn list(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<ListQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<wire::Publication>>>,
    >,
    Error,
> {
    (async {
        service::list(
            &app.publications,
            &app.access,
            &auth.proof,
            &audit,
            query.parse().map_err(|_| Error::Malformed)?,
        )
        .await
        .map(Json)
        .map_err(Into::into)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn targets(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<TargetsQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<
                    rss_mdm_software_service::publication::PublicTarget,
                >,
            >,
        >,
    >,
    Error,
> {
    (async {
        service::targets(
            &app.publications,
            &app.access,
            &auth.proof,
            query.parse().map_err(|_| Error::Malformed)?,
        )
        .await
        .map(Json)
        .map_err(Into::into)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
pub struct HttpState {
    pub publications: Arc<PublicationDirectory>,
    pub access: Arc<rss_mdm_authorization_service::Store>,
}

struct ListQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for ListQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_software_service::management::publication::directory::PUBLICATIONS
    }
}

struct TargetsQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for TargetsQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_software_service::management::publication::directory::TARGETS
    }
}
