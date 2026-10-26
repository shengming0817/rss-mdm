//! Policy event creation and device-scoped batch queries.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_agent_wire::runtime::PolicyEventRequest;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_flow_service::planning::events::{Events, queries};
use rss_mdm_http_contract::{
    CollectionResponse, Operation, Router, catalog,
    routing::{get, post},
};
use std::sync::Arc;
use uuid::Uuid;
pub fn routes(events: Arc<Events>) -> Router {
    register().with_state(events)
}
pub(crate) fn register() -> Router<Arc<Events>> {
    Router::new()
        .route(
            "/devices/{device}/policy-events",
            post(invoke).owned(&catalog::POLICY_EVENT_BATCHES, &[Operation::Action]),
        )
        .route(
            "/devices/{device}/policy-event-batches",
            get(list).owned(&catalog::POLICY_EVENT_BATCHES, &[Operation::List]),
        )
        .route(
            "/devices/{device}/policy-event-batches/{batch}",
            get(read).owned(&catalog::POLICY_EVENT_BATCHES, &[Operation::Get]),
        )
        .route(
            "/devices/{device}/policy-event-batches/{batch}/members",
            get(members).owned(&catalog::POLICY_EVENT_MEMBERS, &[Operation::List]),
        )
}
async fn invoke(
    State(s): State<Arc<Events>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    input: Result<Json<PolicyEventRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<
    rss_mdm_http_contract::signature::WithStatus<
        202,
        Json<rss_mdm_agent_wire::runtime::PolicyEventAccepted>,
    >,
    Error,
> {
    let Json(input) = input.map_err(Error::from)?;
    s.invoke_management(&auth.proof, &device, &input, &audit)
        .await
        .map(|v| rss_mdm_http_contract::signature::WithStatus(Json(v)))
        .map_err(Into::into)
}
async fn list(
    State(s): State<Arc<Events>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<Batches>,
    >,
) -> Result<
    CollectionResponse<
        Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<queries::Batch>>>,
    >,
    Error,
> {
    s.read_management(
        &auth.proof,
        &device,
        None,
        false,
        &query.parse().map_err(|_| Error::Malformed)?,
        &audit,
    )
    .await
    .and_then(queries::ReadResult::batches)
    .map(|v| CollectionResponse(Json(v)))
    .map_err(Into::into)
}
async fn read(
    State(s): State<Arc<Events>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, batch)): Path<(String, Uuid)>,
) -> Result<Json<queries::Batch>, Error> {
    s.read_management(
        &auth.proof,
        &device,
        Some(batch),
        false,
        &queries::BATCHES.parse("").map_err(|_| Error::Malformed)?,
        &audit,
    )
    .await
    .and_then(queries::ReadResult::batch)
    .map(Json)
    .map_err(Into::into)
}
async fn members(
    State(s): State<Arc<Events>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, batch)): Path<(String, Uuid)>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<Members>,
    >,
) -> Result<
    CollectionResponse<
        Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<queries::Member>>>,
    >,
    Error,
> {
    s.read_management(
        &auth.proof,
        &device,
        Some(batch),
        true,
        &query.parse().map_err(|_| Error::Malformed)?,
        &audit,
    )
    .await
    .and_then(queries::ReadResult::members)
    .map(|v| CollectionResponse(Json(v)))
    .map_err(Into::into)
}

struct Batches;
impl rss_mdm_http_contract::query::DirectoryOwner for Batches {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &queries::BATCHES
    }
}
struct Members;
impl rss_mdm_http_contract::query::DirectoryOwner for Members {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &queries::MEMBERS
    }
}
