//! Telemetry management stays inside the existing account/session HTTP boundary.
use crate::{Error, Failure, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use rss_mdm_telemetry_service::{
    Service,
    query::{AggregateRequest, HealthRequest, HistoryRequest, ResourceRequest},
};
use std::sync::Arc;
type App = Arc<Option<Arc<Service>>>;
pub fn routes(
    service: Option<Arc<Service>>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register().with_state(Arc::new(service))
}
pub(crate) fn register() -> Router<App, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_configurations, post_resources, post_history, post_aggregate, post_maintenance, post_health, post_gaps } }
        RegisterModule1 {
            get_configurations: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/telemetry-configurations",
                get(
                    configurations,
                    &contracts::DEVICES,
                    &[RouteOperation::Action],
                ),
            ),
            post_resources: rss_mdm_http_contract::module::Route::new(
                "/telemetry/resources",
                post(
                    resources,
                    &contracts::TELEMETRY_QUERIES,
                    &[RouteOperation::Action],
                ),
            ),
            post_history: rss_mdm_http_contract::module::Route::new(
                "/telemetry/history",
                post(
                    history,
                    &contracts::TELEMETRY_QUERIES,
                    &[RouteOperation::Action],
                ),
            ),
            post_aggregate: rss_mdm_http_contract::module::Route::new(
                "/telemetry/aggregate",
                post(
                    aggregate,
                    &contracts::TELEMETRY_QUERIES,
                    &[RouteOperation::Action],
                ),
            ),
            post_maintenance: rss_mdm_http_contract::module::Route::new(
                "/telemetry/maintenance",
                post(
                    maintenance,
                    &contracts::TELEMETRY_QUERIES,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
            post_health: rss_mdm_http_contract::module::Route::new(
                "/telemetry/health",
                post(
                    health,
                    &contracts::TELEMETRY_QUERIES,
                    &[RouteOperation::Action],
                ),
            ),
            post_gaps: rss_mdm_http_contract::module::Route::new(
                "/telemetry/gaps/query",
                post(
                    gaps,
                    &contracts::TELEMETRY_QUERIES,
                    &[RouteOperation::Action],
                ),
            ),
        }
        .assemble()
    }
}
async fn configurations(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
) -> Result<Json<rss_mdm_telemetry_service::configurations::Configurations>, Error> {
    audit.set_action(
        "telemetry_configurations_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.target_device(&device);
    app.as_ref()
        .as_ref()
        .ok_or(Error::Unsupported)?
        .configurations(&auth.proof, &device, &audit)
        .await
        .map(Json)
        .map_err(error)
}
pub(crate) fn error(e: rss_mdm_telemetry_service::Error) -> Error {
    use rss_mdm_telemetry_service::Error as T;
    match e {
        T::Unsupported => Error::Unsupported,
        T::NotFound => Error::NotFound,
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
) -> Result<Json<rss_mdm_telemetry_service::query::History>, Error> {
    let input = input.map_err(Error::from)?.0;
    audit.set_action(
        "telemetry_history_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
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
) -> Result<Json<rss_mdm_telemetry_service::query::Aggregate>, Error> {
    let input = input.map_err(Error::from)?.0;
    audit.set_action(
        "telemetry_aggregate_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
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
) -> Result<Json<rss_mdm_telemetry_service::maintenance::Progress>, Error> {
    let input = input.map_err(Error::from)?.0;
    audit.operation(
        input.id,
        "telemetry_maintenance",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
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
) -> Result<Json<rss_mdm_telemetry_service::query::Health>, Error> {
    let input = input.map_err(Error::from)?.0;
    audit.set_action(
        "telemetry_health_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
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
) -> Result<Json<rss_mdm_telemetry_service::query::Resources>, Error> {
    let input = input.map_err(Error::from)?.0;
    audit.set_action(
        "telemetry_resources_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.target_device(&input.device);
    app.as_ref()
        .as_ref()
        .ok_or(Error::Unsupported)?
        .resources(&auth.proof, &input, &audit)
        .await
        .map(Json)
        .map_err(error)
}

async fn gaps(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    input: Result<
        Json<rss_mdm_telemetry_service::gap_query::Request>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<rss_mdm_telemetry_service::gap_query::Page>, Error> {
    let input = input.map_err(Error::from)?.0;
    audit.set_action(
        "telemetry_gaps_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.target_device(&input.device);
    app.as_ref()
        .as_ref()
        .ok_or(Error::Unsupported)?
        .gaps(&auth.proof, &input, &audit)
        .await
        .map(Json)
        .map_err(error)
}
