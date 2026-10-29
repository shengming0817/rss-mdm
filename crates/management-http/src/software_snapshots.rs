//! One JSON replacement endpoint and read-only current source records.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{
    Operation, Router, catalog,
    routing::{get, post},
};
use rss_mdm_software_service::{catalog::Operation as Mutation, source_snapshots as owner};
use std::sync::Arc;
use uuid::Uuid;
type HttpState = rss_mdm_software_service::management::catalog::Access<
    rss_mdm_content_service::software::SoftwareContent,
>;
pub(crate) fn routes()
-> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! { struct Routes for [Browser] {
        sources, replace, snapshot, entries, entry, operation
    } }
    Routes {
        sources: rss_mdm_http_contract::module::Route::new(
            "/software/source-snapshots",
            get(
                sources,
                &catalog::SOFTWARE_SOURCE_SNAPSHOTS,
                &[Operation::List],
            ),
        ),
        replace: rss_mdm_http_contract::module::Route::new(
            "/software/source-snapshots/{source}",
            post(
                replace,
                &catalog::SOFTWARE_SOURCE_SNAPSHOTS,
                &[Operation::Update],
            ),
        ),
        snapshot: rss_mdm_http_contract::module::Route::new(
            "/software/source-snapshots/{source}",
            get(
                snapshot,
                &catalog::SOFTWARE_SOURCE_SNAPSHOTS,
                &[Operation::Get],
            ),
        ),
        entries: rss_mdm_http_contract::module::Route::new(
            "/software/source-snapshots/{source}/entries",
            get(
                entries,
                &catalog::SOFTWARE_SOURCE_ENTRIES,
                &[Operation::List],
            ),
        ),
        entry: rss_mdm_http_contract::module::Route::new(
            "/software/source-snapshots/{source}/entries/{entry}",
            get(entry, &catalog::SOFTWARE_SOURCE_ENTRIES, &[Operation::Get]),
        ),
        operation: rss_mdm_http_contract::module::Route::new(
            "/software/source-snapshots/{source}/operations/{operation}",
            get(
                operation,
                &catalog::SOFTWARE_SOURCE_SNAPSHOTS,
                &[Operation::Action],
            ),
        ),
    }
    .assemble()
}
async fn replace(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(source): Path<String>,
    Json(input): Json<Mutation<owner::Import>>,
) -> Result<Json<owner::Receipt>, Error> {
    owner::replace(&app, &auth.proof, &audit, source, input)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn snapshot(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(source): Path<String>,
) -> Result<Json<owner::SnapshotDetail>, Error> {
    owner::snapshot(&app, &auth.proof, &audit, source)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn entry(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((source, id)): Path<(String, Uuid)>,
) -> Result<Json<owner::EntryDetail>, Error> {
    owner::entry(&app, &auth.proof, &audit, source, id)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn operation(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((source, id)): Path<(String, Uuid)>,
) -> Result<Json<owner::Receipt>, Error> {
    owner::operation(&app, &auth.proof, &audit, source, id)
        .await
        .map(Json)
        .map_err(Into::into)
}
type Collection<T> = rss_mdm_http_contract::CollectionResponse<
    Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<T>>>,
>;
async fn sources(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<Sources>,
    >,
) -> Result<Collection<owner::Snapshot>, Error> {
    let query = query.parse().map_err(|_| Error::Malformed)?;
    owner::sources(&app, &auth.proof, &audit, query)
        .await
        .map(Json)
        .map(rss_mdm_http_contract::CollectionResponse)
        .map_err(Into::into)
}
async fn entries(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(source): Path<String>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<Entries>,
    >,
) -> Result<Collection<owner::Entry>, Error> {
    let query = query.parse().map_err(|_| Error::Malformed)?;
    owner::entries(&app, &auth.proof, &audit, source, query)
        .await
        .map(Json)
        .map(rss_mdm_http_contract::CollectionResponse)
        .map_err(Into::into)
}
struct Sources;
impl rss_mdm_http_contract::query::DirectoryOwner for Sources {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &owner::SOURCES
    }
}
struct Entries;
impl rss_mdm_http_contract::query::DirectoryOwner for Entries {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &owner::ENTRIES
    }
}
