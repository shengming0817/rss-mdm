//! Authenticated Agent event entry, separate from self-service publication.
use crate::{AgentError, Error, TaskState, tasks};
use axum::{
    Extension, Json,
    extract::{Path, RawQuery, State},
    http::HeaderMap,
};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_flow_service::planning::events::{Events, queries};
use rss_mdm_http_contract::{
    Operation, Router, catalog,
    routing::{get, post},
};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
struct StateServices {
    tasks: Arc<TaskState>,
    events: Arc<Events>,
}
pub fn routes(tasks: Arc<TaskState>, events: Arc<Events>) -> Router {
    Router::new()
        .route(
            "/policy-events",
            post(invoke).owned(&catalog::PROTOCOL_AGENT_CHANNEL, &[Operation::Action]),
        )
        .route(
            "/policy-event-batches",
            get(list)
                .owned(&catalog::PROTOCOL_AGENT_CHANNEL, &[Operation::Action])
                .queried(&queries::BATCHES),
        )
        .route(
            "/policy-event-batches/{batch}",
            get(read).owned(&catalog::PROTOCOL_AGENT_CHANNEL, &[Operation::Action]),
        )
        .route(
            "/policy-event-batches/{batch}/members",
            get(members)
                .owned(&catalog::PROTOCOL_AGENT_CHANNEL, &[Operation::Action])
                .queried(&queries::MEMBERS),
        )
        .with_state(Arc::new(StateServices { tasks, events }))
}
fn error(e: rss_mdm_flow_service::Error) -> AgentError {
    use rss_mdm_flow_service::Error as E;
    match e {
        E::Malformed => Error::Malformed,
        E::Conflict => Error::Conflict,
        E::CommitUnknown => Error::CommitUnknown,
        E::RollbackFailed => Error::RollbackFailed,
        E::Forbidden | E::Unauthorized => Error::Forbidden,
        E::NotFound => Error::NotFound,
        E::Unsupported => Error::Unsupported,
        _ => return AgentError::Wire(wire::ErrorCode::ServiceUnavailable),
    }
    .into()
}
async fn invoke(
    State(s): State<Arc<StateServices>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    input: Result<Json<wire::PolicyEventRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(axum::http::StatusCode, Json<Value>), AgentError> {
    crate::bounded(async {
        let Json(input) = input.map_err(|_| Error::Malformed)?;
        let p =
            tasks::authenticate(&s.tasks, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        s.events
            .invoke_agent(&p, &input, &audit)
            .await
            .map(|v| (axum::http::StatusCode::ACCEPTED, Json(v)))
            .map_err(error)
    })
    .await
}
async fn list(
    State(s): State<Arc<StateServices>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Json<Value>, AgentError> {
    crate::bounded(async {
        let p =
            tasks::authenticate(&s.tasks, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        s.events
            .read_agent(&p, None, false, raw.as_deref().unwrap_or_default(), &audit)
            .await
            .map(Json)
            .map_err(error)
    })
    .await
}
async fn read(
    State(s): State<Arc<StateServices>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    Path(batch): Path<Uuid>,
) -> Result<Json<Value>, AgentError> {
    crate::bounded(async {
        let p =
            tasks::authenticate(&s.tasks, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        s.events
            .read_agent(&p, Some(batch), false, "", &audit)
            .await
            .map(Json)
            .map_err(error)
    })
    .await
}
async fn members(
    State(s): State<Arc<StateServices>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    Path(batch): Path<Uuid>,
    RawQuery(raw): RawQuery,
) -> Result<Json<Value>, AgentError> {
    crate::bounded(async {
        let p =
            tasks::authenticate(&s.tasks, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        s.events
            .read_agent(
                &p,
                Some(batch),
                true,
                raw.as_deref().unwrap_or_default(),
                &audit,
            )
            .await
            .map(Json)
            .map_err(error)
    })
    .await
}
