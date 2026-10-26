//! Session-authenticated Agent authorization, separate from native Enrollment passwords.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rss_mdm_agent_wire::enroll as wire;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use rss_mdm_registration_service::agent::{Failure, Service};
use std::sync::Arc;
use uuid::Uuid;
type App = Arc<Option<Arc<Service>>>;
type Body<T> = Result<Json<T>, axum::extract::rejection::JsonRejection>;
fn service(app: &App) -> Result<&Service, HttpFailure> {
    app.as_ref()
        .as_deref()
        .ok_or_else(|| rss_mdm_registration_service::Error::Configuration.into())
}
fn body<T>(v: Body<T>) -> Result<T, HttpFailure> {
    v.map(|v| v.0)
        .map_err(|error| HttpFailure::Request(Error::from(error)))
}
#[derive(schemars::JsonSchema, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Operation {
    operation_id: Uuid,
}
pub fn routes(app: Option<Arc<Service>>) -> Router {
    register().with_state(Arc::new(app))
}
pub(crate) fn register() -> Router<App> {
    Router::new()
        .route(
            "/agent-connections",
            get(connection_state)
                .owned(&contracts::AGENT_CONNECTIONS, &[RouteOperation::Get])
                .put(save_connections)
                .owned(&contracts::AGENT_CONNECTIONS, &[RouteOperation::Update]),
        )
        .route(
            "/agent-connections/publish",
            post(publish_connections)
                .owned(&contracts::AGENT_CONNECTIONS, &[RouteOperation::Update]),
        )
        .route(
            "/agent-connections/devices",
            get(unconfirmed_devices).owned(&contracts::AGENT_CONNECTIONS, &[RouteOperation::Get]),
        )
        .route(
            "/agent-connections/configuration",
            get(download_connections).owned(
                &contracts::DOWNLOAD_MANAGEMENT_HTTP,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/agent-connection-operations/{id}",
            get(connection_operation).owned(
                &contracts::AGENT_CONNECTION_OPERATIONS,
                &[RouteOperation::Get],
            ),
        )
        .route(
            "/agent-connections/devices/{device}/observation",
            get(connection_observation)
                .owned(&contracts::AGENT_CONNECTIONS, &[RouteOperation::Get]),
        )
        .route(
            "/agent-configurations",
            post(create_configuration)
                .owned(&contracts::AGENT_CONFIGURATIONS, &[RouteOperation::Create])
                .get(list_configurations)
                .owned(&contracts::AGENT_CONFIGURATIONS, &[RouteOperation::List]),
        )
        .route(
            "/agent-configurations/{id}",
            get(read_configuration).owned(&contracts::AGENT_CONFIGURATIONS, &[RouteOperation::Get]),
        )
        .route(
            "/agent-configuration-operations/{id}",
            get(configuration_operation).owned(
                &contracts::AGENT_CONFIGURATION_OPERATIONS,
                &[RouteOperation::Get],
            ),
        )
        .route(
            "/agent-configurations/{id}/revoke",
            post(revoke_configuration).owned(
                &contracts::AGENT_CONFIGURATIONS,
                &[RouteOperation::Lifecycle],
            ),
        )
        .route(
            "/agent-requests/{id}/authorize",
            post(authorize).owned(
                &contracts::AGENT_REQUEST_COMMANDS,
                &[RouteOperation::Action, RouteOperation::Lifecycle],
            ),
        )
        .route(
            "/agent-requests/{id}/reenroll/{device}",
            post(reenroll).owned(
                &contracts::AGENT_REQUEST_COMMANDS,
                &[RouteOperation::Action, RouteOperation::Lifecycle],
            ),
        )
        .route(
            "/agent-requests/{id}/cancel",
            post(revoke).owned(
                &contracts::AGENT_REQUEST_COMMANDS,
                &[RouteOperation::Action, RouteOperation::Lifecycle],
            ),
        )
        .route(
            "/agent-enrollment-settings",
            get(settings)
                .owned(
                    &contracts::AGENT_ENROLLMENT_SETTINGS,
                    &[RouteOperation::Get],
                )
                .put(update_settings)
                .owned(
                    &contracts::AGENT_ENROLLMENT_SETTINGS,
                    &[RouteOperation::Update],
                ),
        )
        .route(
            "/agent-registrations/{id}/recovery",
            post(recovery).owned(
                &contracts::AGENT_REGISTRATION_RECOVERY,
                &[RouteOperation::Action, RouteOperation::Lifecycle],
            ),
        )
        .route(
            "/agent-issuances/{id}/recover",
            post(recover_issuance).owned(
                &contracts::AGENT_ISSUANCE_RECOVERY,
                &[RouteOperation::Action, RouteOperation::Lifecycle],
            ),
        )
        .route(
            "/agent-issuances/{id}/recovery-operations/{operation}",
            get(issuance_recovery_operation).owned(
                &contracts::AGENT_ISSUANCE_RECOVERY,
                &[RouteOperation::Action],
            ),
        )
}
async fn connection_state(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<rss_mdm_registration_service::agent::connections::State>, HttpFailure> {
    Ok(Json(service(&app)?.connection_state(&auth.proof).await?))
}
async fn save_connections(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    input: Body<rss_mdm_registration_service::agent::connections::Save>,
) -> Result<Json<rss_mdm_registration_service::agent::connections::Draft>, HttpFailure> {
    Ok(Json(
        service(&app)?
            .save_connections(&auth.proof, &body(input)?, &a)
            .await?,
    ))
}
async fn publish_connections(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    input: Body<rss_mdm_registration_service::agent::connections::Publish>,
) -> Result<Json<rss_mdm_agent_wire::connections::SignedConfiguration>, HttpFailure> {
    Ok(Json(
        service(&app)?
            .publish_connections(&auth.proof, &body(input)?, &a)
            .await?,
    ))
}
async fn connection_operation(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<Json<Option<rss_mdm_registration_service::agent::connections::Receipt>>, HttpFailure> {
    Ok(Json(
        service(&app)?.connection_operation(&auth.proof, id).await?,
    ))
}
async fn connection_observation(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path(device): Path<String>,
) -> Result<Json<Option<rss_mdm_registration_service::agent::connections::Observation>>, HttpFailure>
{
    Ok(Json(
        service(&app)?
            .connection_observation(&auth.proof, &device)
            .await?,
    ))
}
async fn settings(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<rss_mdm_registration_service::agent::settings::DeliverySettings>, HttpFailure> {
    Ok(Json(service(&app)?.settings(&auth.proof).await?.into()))
}
async fn update_settings(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    input: Body<rss_mdm_registration_service::agent::settings::Update>,
) -> Result<Json<rss_mdm_registration_service::agent::settings::DeliverySettings>, HttpFailure> {
    Ok(Json(
        service(&app)?
            .update_settings(&auth.proof, &body(input)?, &a)
            .await?
            .into(),
    ))
}
async fn authorize(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: Body<Operation>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    Ok(Json(
        service(&app)?
            .authorize(&auth.proof, id, body(input)?.operation_id, &a)
            .await?,
    ))
}
async fn reenroll(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    Path((id, device)): Path<(Uuid, String)>,
    input: Body<Operation>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    Ok(Json(
        service(&app)?
            .authorize_reenrollment(&auth.proof, id, body(input)?.operation_id, &device, &a)
            .await?,
    ))
}
async fn revoke(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: Body<Operation>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    Ok(Json(
        service(&app)?
            .revoke(&auth.proof, id, body(input)?.operation_id, &a)
            .await?,
    ))
}
async fn recovery(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: Body<wire::GrantRequest>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    Ok(Json(
        service(&app)?
            .recovery(&auth.proof, id, &body(input)?, &a)
            .await?,
    ))
}
async fn recover_issuance(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: Body<wire::RecoverIssuance>,
) -> Result<Json<wire::Candidate>, HttpFailure> {
    Ok(Json(
        service(&app)?
            .recover_issuance(&auth.proof, id, &body(input)?, &a)
            .await?,
    ))
}
async fn issuance_recovery_operation(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path((id, operation)): Path<(Uuid, Uuid)>,
) -> Result<Json<Option<wire::Candidate>>, HttpFailure> {
    Ok(Json(
        service(&app)?
            .issuance_recovery_operation(&auth.proof, id, operation)
            .await?,
    ))
}
enum HttpFailure {
    Agent(Failure),
    Request(Error),
}
impl From<Failure> for HttpFailure {
    fn from(e: Failure) -> Self {
        Self::Agent(e)
    }
}
impl From<rss_mdm_registration_service::Error> for HttpFailure {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        Self::Agent(e.into())
    }
}
impl IntoResponse for HttpFailure {
    fn into_response(self) -> Response {
        let failure = match self {
            Self::Request(error) => return error.into_response(),
            Self::Agent(failure) => failure,
        };
        let status = failure_status(failure.code);
        let mut response = (
            status,
            Json(wire::ErrorBody {
                code: failure.code,
                issuance_id: failure.issuance_id,
            }),
        )
            .into_response();
        if let Some(e) = failure.source {
            response.extensions_mut().insert(Error::from(e));
        }
        response
    }
}

async fn create_configuration(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    input: Body<rss_mdm_registration_service::agent::configurations::Create>,
) -> Result<
    rss_mdm_http_contract::download::Attachment<
        Json<rss_mdm_agent_wire::enroll::configuration::ConfigurationFile>,
    >,
    HttpFailure,
> {
    let file = Json(
        service(&app)?
            .create_configuration(&auth.proof, &body(input)?, &a)
            .await?,
    );
    let disposition = format!(
        "attachment; filename=\"{}\"",
        rss_mdm_registration_service::agent::settings::CONFIGURATION_FILENAME
    );
    Ok(rss_mdm_http_contract::download::Attachment {
        body: file,
        disposition: axum::http::HeaderValue::from_str(&disposition)
            .expect("fixed configuration filename"),
    })
}
async fn read_configuration(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_registration_service::agent::configurations::Read>, HttpFailure> {
    Ok(Json(
        service(&app)?.read_configuration(&auth.proof, id).await?,
    ))
}
async fn configuration_operation(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<Json<Option<rss_mdm_registration_service::agent::configurations::Read>>, HttpFailure> {
    Ok(Json(
        service(&app)?
            .configuration_operation(&auth.proof, id)
            .await?,
    ))
}
async fn revoke_configuration(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: Body<Operation>,
) -> Result<rss_mdm_http_contract::signature::WithStatus<204, ()>, HttpFailure> {
    service(&app)?
        .revoke_configuration(&auth.proof, id, body(input)?.operation_id, &a)
        .await?;
    Ok(rss_mdm_http_contract::signature::WithStatus(()))
}

async fn download_connections(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<
    rss_mdm_http_contract::download::Attachment<
        Json<rss_mdm_agent_wire::connections::SignedConfiguration>,
    >,
    HttpFailure,
> {
    let state = service(&app)?.connection_state(&auth.proof).await?;
    let configuration = state
        .published
        .ok_or(rss_mdm_registration_service::Error::Conflict)?;
    Ok(rss_mdm_http_contract::download::Attachment {
        body: Json(configuration),
        disposition: axum::http::HeaderValue::from_static(
            "attachment; filename=\"rss-agent-connections.json\"",
        ),
    })
}

async fn unconfirmed_devices(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Query(input): Query<rss_mdm_registration_service::agent::connections::DeviceQuery>,
) -> Result<Json<rss_mdm_registration_service::agent::connections::UnconfirmedDevices>, HttpFailure>
{
    Ok(Json(
        service(&app)?
            .unconfirmed_connection_devices(&auth.proof, &input)
            .await?,
    ))
}

async fn list_configurations(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<ListConfigurationsQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<
                    rss_mdm_registration_service::agent::configurations::directory::Metadata,
                >,
            >,
        >,
    >,
    HttpFailure,
> {
    (async {
        let q = query
            .parse()
            .map_err(|_| HttpFailure::Request(Error::Malformed))?;
        Ok(Json(
            service(&app)?
                .configuration_directory(&auth.proof, &q, &audit)
                .await?,
        ))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

struct ListConfigurationsQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for ListConfigurationsQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_registration_service::agent::configurations::directory::SCHEMA
    }
}

fn failure_status(code: wire::ErrorCode) -> StatusCode {
    use wire::ErrorCode as C;
    match code {
        C::MalformedRequest => StatusCode::BAD_REQUEST,
        C::InvalidIdentity
        | C::CertificateExpired
        | C::CredentialRevoked
        | C::CredentialRetired => StatusCode::UNAUTHORIZED,
        C::PermissionDenied | C::GrantRevoked | C::GrantExpired => StatusCode::FORBIDDEN,
        C::EnrollmentPaused => StatusCode::CONFLICT,
        C::RegistrationLimit => StatusCode::TOO_MANY_REQUESTS,
        C::OperationConflict
        | C::ConnectionDeploymentUnobserved
        | C::ConnectionRetirementBlocked => StatusCode::CONFLICT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}
impl rss_mdm_http_contract::signature::Output for HttpFailure {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        use rss_mdm_http_contract::signature::{Response, Schema};
        let mut responses = Error::responses();
        let codes = Schema::response::<wire::ErrorCode>();
        for value in codes.string_values() {
            let code = serde_json::from_value(value.clone()).expect("actual enrollment error code");
            let mut response = Response::json::<wire::ErrorBody>(failure_status(code).as_u16());
            response
                .body
                .as_mut()
                .expect("JSON error body")
                .schema
                .value["properties"]["code"]["const"] = value.clone();
            responses.push(response);
        }
        responses
    }
}
