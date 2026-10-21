//! Telemetry management stays inside the existing account/session HTTP boundary.
use crate::{Error, Failure, authorization::context::RequestAuth};
use axum::{Extension, Json, Router, extract::State, routing::post};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_telemetry_service::{
    Service,
    query::{AggregateRequest, HealthRequest, HistoryRequest, ResourceRequest},
};
use std::sync::Arc;
type App = Arc<Option<Arc<Service>>>;
pub fn routes(service: Option<Arc<Service>>) -> Router {
    Router::new()
        .route("/telemetry/resources", post(resources))
        .route("/telemetry/history", post(history))
        .route("/telemetry/aggregate", post(aggregate))
        .route("/telemetry/maintenance", post(maintenance))
        .route("/telemetry/health", post(health))
        .with_state(Arc::new(service))
}
pub(crate) fn error(e: rss_mdm_telemetry_service::Error) -> Error {
    use rss_mdm_telemetry_service::Error as T;
    match e {
        T::Unsupported => Error::Unsupported,
        T::Invalid => Error::Malformed,
        T::Denied => Error::Forbidden,
        T::Conflict => Error::Conflict,
        T::Unknown => Error::CommitUnknown,
        T::Storage | T::Capacity => Error::Unavailable(Failure::Database),
    }
}
async fn history(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    input: Result<Json<HistoryRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, Error> {
    let input = input.map_err(Error::from)?.0;
    audit.set_action("telemetry_history_read");
    audit.target_device(&input.device);
    let service = app.as_ref().as_ref().ok_or(Error::Unsupported)?;
    service
        .history(&auth.proof, &input, &audit)
        .await
        .map(Json)
        .map_err(error)
}

async fn aggregate(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    input: Result<Json<AggregateRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, Error> {
    let input = input.map_err(Error::from)?.0;
    audit.set_action("telemetry_aggregate_read");
    audit.target_device(&input.query.device);
    let service = app.as_ref().as_ref().ok_or(Error::Unsupported)?;
    service
        .aggregate(&auth.proof, &input, &audit)
        .await
        .map(Json)
        .map_err(error)
}

async fn maintenance(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    input: Result<
        Json<rss_mdm_telemetry_service::maintenance::Request>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<serde_json::Value>, Error> {
    let input = input.map_err(Error::from)?.0;
    audit.operation(input.id, "telemetry_maintenance");
    audit.target_device(&input.device);
    let service = app.as_ref().as_ref().ok_or(Error::Unsupported)?;
    service
        .maintenance(&auth.proof, &input, &audit)
        .await
        .map(Json)
        .map_err(error)
}

async fn health(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    input: Result<Json<HealthRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, Error> {
    let input = input.map_err(Error::from)?.0;
    audit.set_action("telemetry_health_read");
    audit.target_device(&input.device);
    let service = app.as_ref().as_ref().ok_or(Error::Unsupported)?;
    service
        .health(&auth.proof, &input, &audit)
        .await
        .map(Json)
        .map_err(error)
}

async fn resources(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    input: Result<Json<ResourceRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, Error> {
    let input = input.map_err(Error::from)?.0;
    audit.set_action("telemetry_resources_read");
    audit.target_device(&input.device);
    app.as_ref()
        .as_ref()
        .ok_or(Error::Unsupported)?
        .resources(&auth.proof, &input, &audit)
        .await
        .map(Json)
        .map_err(error)
}
