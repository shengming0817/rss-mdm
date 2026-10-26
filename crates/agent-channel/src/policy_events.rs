//! Authenticated Agent event entry, separate from self-service publication.
use crate::{AgentError, Error, TaskState, tasks};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_flow_service::planning::events::{Events, queries};
use rss_mdm_http_contract::{
    CollectionResponse, Operation, Router, catalog,
    routing::{get, post},
};
use std::sync::Arc;
use uuid::Uuid;
struct StateServices {
    tasks: Arc<TaskState>,
    events: Arc<Events>,
}
pub fn routes(tasks: Arc<TaskState>, events: Arc<Events>) -> Router {
    mount(Some(&(tasks, events)))
}
pub(crate) fn mount(runtime: Option<&(Arc<TaskState>, Arc<Events>)>) -> Router {
    declarations().bind_with(runtime, |(tasks, events)| {
        Arc::new(StateServices {
            tasks: tasks.clone(),
            events: events.clone(),
        })
    })
}
fn declarations() -> Router<Arc<StateServices>> {
    Router::new()
        .route(
            "/policy-events",
            post(invoke).owned(&catalog::PROTOCOL_AGENT_CHANNEL, &[Operation::Action]),
        )
        .route(
            "/policy-event-batches",
            get(list).owned(&catalog::POLICY_EVENT_BATCHES, &[Operation::List]),
        )
        .route(
            "/policy-event-batches/{batch}",
            get(read).owned(&catalog::POLICY_EVENT_BATCHES, &[Operation::Get]),
        )
        .route(
            "/policy-event-batches/{batch}/members",
            get(members).owned(&catalog::POLICY_EVENT_MEMBERS, &[Operation::List]),
        )
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
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    input: Result<Json<wire::PolicyEventRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<
    rss_mdm_http_contract::signature::WithStatus<
        202,
        Json<rss_mdm_agent_wire::runtime::PolicyEventAccepted>,
    >,
    AgentError,
> {
    crate::bounded(async {
        let Json(input) = input.map_err(|_| Error::Malformed)?;
        let p =
            tasks::authenticate(&s.tasks, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        s.events
            .invoke_agent(&p, &input, &audit)
            .await
            .map(|v| rss_mdm_http_contract::signature::WithStatus(Json(v)))
            .map_err(error)
    })
    .await
}
async fn list(
    State(s): State<Arc<StateServices>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<Batches>,
    >,
) -> Result<
    CollectionResponse<
        Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<queries::Batch>>>,
    >,
    AgentError,
> {
    crate::bounded(async {
        let p =
            tasks::authenticate(&s.tasks, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        s.events
            .read_agent(
                &p,
                None,
                false,
                &query.parse().map_err(|_| Error::Malformed)?,
                &audit,
            )
            .await
            .and_then(queries::ReadResult::batches)
            .map(|v| CollectionResponse(Json(v)))
            .map_err(error)
    })
    .await
}
async fn read(
    State(s): State<Arc<StateServices>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    Path(batch): Path<Uuid>,
) -> Result<Json<queries::Batch>, AgentError> {
    crate::bounded(async {
        let p =
            tasks::authenticate(&s.tasks, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        s.events
            .read_agent(
                &p,
                Some(batch),
                false,
                &queries::BATCHES.parse("").map_err(|_| Error::Malformed)?,
                &audit,
            )
            .await
            .and_then(queries::ReadResult::batch)
            .map(Json)
            .map_err(error)
    })
    .await
}
async fn members(
    State(s): State<Arc<StateServices>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    Path(batch): Path<Uuid>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<Members>,
    >,
) -> Result<
    CollectionResponse<
        Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<queries::Member>>>,
    >,
    AgentError,
> {
    crate::bounded(async {
        let p =
            tasks::authenticate(&s.tasks, &headers, peer.as_ref().map(|p| &p.0), &audit).await?;
        s.events
            .read_agent(
                &p,
                Some(batch),
                true,
                &query.parse().map_err(|_| Error::Malformed)?,
                &audit,
            )
            .await
            .and_then(queries::ReadResult::members)
            .map(|v| CollectionResponse(Json(v)))
            .map_err(error)
    })
    .await
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
