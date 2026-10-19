use crate::{
    Error,
    authorization::context::{AuthorizedPrincipal, RequestAuth},
};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_webhook_service::storage::Mutation;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
#[derive(Clone, serde::Serialize)]
pub enum Command {
    Materials,
    MaterialOperation(Uuid),
    PrepareMaterial(Uuid, rss_mdm_webhook_service::materials::Prepare),
    TransitionMaterial(Uuid, rss_mdm_webhook_service::materials::Transition),
    Types,
    Health,
    Subscriptions(Option<Uuid>),
    Subscription(Uuid),
    Change(Uuid, Mutation),
    Test {
        subscription: Uuid,
        operation: Uuid,
        device: String,
    },
    Deliveries(Option<Uuid>),
    Delivery(Uuid),
    Replay {
        delivery: Uuid,
        operation: Uuid,
    },
    Redrive {
        delivery: Uuid,
        operation: Uuid,
        version: u64,
    },
}
pub trait Source: Send + Sync {
    fn execute<'a>(
        &'a self,
        proof: Arc<AuthorizedPrincipal>,
        audit: RequestAudit,
        command: Command,
    ) -> futures::future::BoxFuture<'a, Result<Value, Error>>;
}
pub fn routes(source: Arc<dyn Source>) -> Router {
    Router::new()
        .route("/webhooks/materials", get(materials).post(prepare_material))
        .route("/webhooks/materials/transitions", post(transition_material))
        .route(
            "/webhooks/materials/operations/{id}",
            get(material_operation),
        )
        .route("/webhooks/health", get(health))
        .route("/webhooks/event-types", get(types))
        .route("/webhooks/subscriptions", get(subscriptions))
        .route(
            "/webhooks/subscriptions/{id}",
            get(subscription).put(change),
        )
        .route("/webhooks/subscriptions/{id}/test", post(test))
        .route("/webhooks/deliveries", get(deliveries))
        .route("/webhooks/deliveries/{id}", get(delivery))
        .route("/webhooks/deliveries/{id}/replay", post(replay))
        .route("/webhooks/deliveries/{id}/redrive", post(redrive))
        .with_state(source)
}
type Response = Result<Json<Value>, Error>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    after: Option<Uuid>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Test {
    operation_id: Uuid,
    device_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Replay {
    operation_id: Uuid,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Redrive {
    operation_id: Uuid,
    expected_version: u64,
}
async fn call(s: Arc<dyn Source>, a: RequestAuth, audit: RequestAudit, c: Command) -> Response {
    s.execute(a.proof, audit, c).await.map(Json)
}
fn idempotency(headers: &axum::http::HeaderMap) -> Result<Uuid, Error> {
    if headers.get_all("idempotency-key").iter().count() != 1 {
        return Err(Error::Malformed);
    }
    let id = Uuid::parse_str(
        headers
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .ok_or(Error::Malformed)?,
    )
    .map_err(|_| Error::Malformed)?;
    if id.is_nil() {
        return Err(Error::Malformed);
    }
    Ok(id)
}
async fn materials(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Response {
    call(s, a, audit, Command::Materials).await
}
async fn material_operation(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    path: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
) -> Response {
    call(
        s,
        a,
        audit,
        Command::MaterialOperation(path.map_err(|_| Error::Malformed)?.0),
    )
    .await
}
async fn prepare_material(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: axum::http::HeaderMap,
    body: Result<
        Json<rss_mdm_webhook_service::materials::Prepare>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    call(
        s,
        a,
        audit,
        Command::PrepareMaterial(
            idempotency(&headers)?,
            body.map_err(|_| Error::Malformed)?.0,
        ),
    )
    .await
}
async fn transition_material(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: axum::http::HeaderMap,
    body: Result<
        Json<rss_mdm_webhook_service::materials::Transition>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    call(
        s,
        a,
        audit,
        Command::TransitionMaterial(
            idempotency(&headers)?,
            body.map_err(|_| Error::Malformed)?.0,
        ),
    )
    .await
}
async fn types(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Response {
    call(s, a, audit, Command::Types).await
}
async fn subscriptions(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    q: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Response {
    call(
        s,
        a,
        audit,
        Command::Subscriptions(q.map_err(|_| Error::Malformed)?.after),
    )
    .await
}
async fn subscription(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Response {
    call(s, a, audit, Command::Subscription(id)).await
}
async fn change(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Mutation>, axum::extract::rejection::JsonRejection>,
) -> Response {
    call(
        s,
        a,
        audit,
        Command::Change(id, body.map_err(Error::from)?.0),
    )
    .await
}
async fn test(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Test>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let v = body.map_err(Error::from)?.0;
    call(
        s,
        a,
        audit,
        Command::Test {
            subscription: id,
            operation: v.operation_id,
            device: v.device_id,
        },
    )
    .await
}
async fn deliveries(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    q: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Response {
    call(
        s,
        a,
        audit,
        Command::Deliveries(q.map_err(|_| Error::Malformed)?.after),
    )
    .await
}
async fn delivery(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Response {
    call(s, a, audit, Command::Delivery(id)).await
}
async fn replay(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Replay>, axum::extract::rejection::JsonRejection>,
) -> Response {
    call(
        s,
        a,
        audit,
        Command::Replay {
            delivery: id,
            operation: body.map_err(Error::from)?.operation_id,
        },
    )
    .await
}
async fn redrive(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Redrive>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let v = body.map_err(Error::from)?.0;
    call(
        s,
        a,
        audit,
        Command::Redrive {
            delivery: id,
            operation: v.operation_id,
            version: v.expected_version,
        },
    )
    .await
}

async fn health(
    State(s): State<Arc<dyn Source>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Response {
    call(s, a, audit, Command::Health).await
}
