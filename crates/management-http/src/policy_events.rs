//! Policy event creation and device-scoped batch queries.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, RawQuery, State},
};
use rss_mdm_agent_wire::runtime::PolicyEventRequest;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_flow_service::planning::events::{Events, queries};
use rss_mdm_http_contract::{
    CollectionResponse, Operation, Router, catalog,
    routing::{get, post},
};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
pub fn routes(events: Arc<Events>) -> Router {
    Router::new()
        .route(
            "/devices/{device}/policy-events",
            post(invoke).owned(&catalog::POLICY_EVENT_BATCHES, &[Operation::Action]),
        )
        .route(
            "/devices/{device}/policy-event-batches",
            get(list)
                .owned(&catalog::POLICY_EVENT_BATCHES, &[Operation::List])
                .queried(&queries::BATCHES),
        )
        .route(
            "/devices/{device}/policy-event-batches/{batch}",
            get(read).owned(&catalog::POLICY_EVENT_BATCHES, &[Operation::Get]),
        )
        .route(
            "/devices/{device}/policy-event-batches/{batch}/members",
            get(members)
                .owned(&catalog::POLICY_EVENT_MEMBERS, &[Operation::List])
                .queried(&queries::MEMBERS),
        )
        .with_state(events)
}
async fn invoke(
    State(s): State<Arc<Events>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    input: Result<Json<PolicyEventRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(axum::http::StatusCode, Json<Value>), Error> {
    let Json(input) = input.map_err(Error::from)?;
    s.invoke_management(&auth.proof, &device, &input, &audit)
        .await
        .map(|v| (axum::http::StatusCode::ACCEPTED, Json(v)))
        .map_err(Into::into)
}
async fn list(
    State(s): State<Arc<Events>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<CollectionResponse<Json<Value>>, Error> {
    s.read_management(
        &auth.proof,
        &device,
        None,
        false,
        raw.as_deref().unwrap_or_default(),
        &audit,
    )
    .await
    .map(|v| CollectionResponse(Json(v)))
    .map_err(Into::into)
}
async fn read(
    State(s): State<Arc<Events>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, batch)): Path<(String, Uuid)>,
) -> Result<Json<Value>, Error> {
    s.read_management(&auth.proof, &device, Some(batch), false, "", &audit)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn members(
    State(s): State<Arc<Events>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, batch)): Path<(String, Uuid)>,
    RawQuery(raw): RawQuery,
) -> Result<CollectionResponse<Json<Value>>, Error> {
    s.read_management(
        &auth.proof,
        &device,
        Some(batch),
        true,
        raw.as_deref().unwrap_or_default(),
        &audit,
    )
    .await
    .map(|v| CollectionResponse(Json(v)))
    .map_err(Into::into)
}
