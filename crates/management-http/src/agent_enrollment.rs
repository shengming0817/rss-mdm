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
pub fn routes(
    app: Option<Arc<Service>>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register().with_state(Arc::new(app))
}
pub(crate) fn register() -> Router<App, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_request_directory, get_request_details, get_registration_recovery_operation, get_issuance_recovery_operations, get_connection_state, put_save_connections, post_publish_connections, get_unconfirmed_devices, get_download_connections, get_connection_operation, get_connection_observation, post_create_configuration, get_list_configurations, get_read_configuration, get_configuration_operation, post_revoke_configuration, post_authorize, post_reenroll, post_revoke, get_settings, put_update_settings, post_recovery, post_recover_issuance, get_issuance_recovery_operation } }
        RegisterModule1 {
            get_request_directory: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/agent-requests",
                get(
                    request_directory,
                    &contracts::AGENT_REQUESTS,
                    &[RouteOperation::List],
                ),
            ),
            get_request_details: rss_mdm_http_contract::module::Route::new(
                "/agent-requests/{id}",
                get(
                    request_details,
                    &contracts::AGENT_REQUESTS,
                    &[RouteOperation::Get],
                ),
            ),
            get_registration_recovery_operation: rss_mdm_http_contract::module::Route::new(
                "/agent-registrations/{id}/recovery-operations/{operation}",
                get(
                    registration_recovery_operation,
                    &contracts::AGENT_REGISTRATION_RECOVERY,
                    &[RouteOperation::Action],
                ),
            ),
            get_issuance_recovery_operations: rss_mdm_http_contract::module::Route::new(
                "/agent-issuances/{id}/recovery-operations",
                get(
                    issuance_recovery_operations,
                    &contracts::AGENT_ISSUANCE_RECOVERY_OPERATIONS,
                    &[RouteOperation::List],
                ),
            ),
            get_connection_state: rss_mdm_http_contract::module::Route::new(
                "/agent-connections",
                rss_mdm_http_contract::routing::get(
                    connection_state,
                    &contracts::AGENT_CONNECTIONS,
                    &[RouteOperation::Get],
                ),
            ),
            put_save_connections: rss_mdm_http_contract::module::Route::new(
                "/agent-connections",
                rss_mdm_http_contract::routing::put(
                    save_connections,
                    &contracts::AGENT_CONNECTIONS,
                    &[RouteOperation::Update],
                ),
            ),
            post_publish_connections: rss_mdm_http_contract::module::Route::new(
                "/agent-connections/publish",
                post(
                    publish_connections,
                    &contracts::AGENT_CONNECTIONS,
                    &[RouteOperation::Update],
                ),
            ),
            get_unconfirmed_devices: rss_mdm_http_contract::module::Route::new(
                "/agent-connections/devices",
                get(
                    unconfirmed_devices,
                    &contracts::AGENT_CONNECTIONS,
                    &[RouteOperation::Get],
                ),
            ),
            get_download_connections: rss_mdm_http_contract::module::Route::new(
                "/agent-connections/configuration",
                get(
                    download_connections,
                    &contracts::DOWNLOAD_MANAGEMENT_HTTP,
                    &[RouteOperation::Action],
                ),
            ),
            get_connection_operation: rss_mdm_http_contract::module::Route::new(
                "/agent-connection-operations/{id}",
                get(
                    connection_operation,
                    &contracts::AGENT_CONNECTION_OPERATIONS,
                    &[RouteOperation::Get],
                ),
            ),
            get_connection_observation: rss_mdm_http_contract::module::Route::new(
                "/agent-connections/devices/{device}/observation",
                get(
                    connection_observation,
                    &contracts::AGENT_CONNECTIONS,
                    &[RouteOperation::Get],
                ),
            ),
            post_create_configuration: rss_mdm_http_contract::module::Route::new(
                "/agent-configurations",
                rss_mdm_http_contract::routing::post(
                    create_configuration,
                    &contracts::AGENT_CONFIGURATIONS,
                    &[RouteOperation::Create],
                ),
            ),
            get_list_configurations: rss_mdm_http_contract::module::Route::new(
                "/agent-configurations",
                rss_mdm_http_contract::routing::get(
                    list_configurations,
                    &contracts::AGENT_CONFIGURATIONS,
                    &[RouteOperation::List],
                ),
            ),
            get_read_configuration: rss_mdm_http_contract::module::Route::new(
                "/agent-configurations/{id}",
                get(
                    read_configuration,
                    &contracts::AGENT_CONFIGURATIONS,
                    &[RouteOperation::Get],
                ),
            ),
            get_configuration_operation: rss_mdm_http_contract::module::Route::new(
                "/agent-configuration-operations/{id}",
                get(
                    configuration_operation,
                    &contracts::AGENT_CONFIGURATION_OPERATIONS,
                    &[RouteOperation::Get],
                ),
            ),
            post_revoke_configuration: rss_mdm_http_contract::module::Route::new(
                "/agent-configurations/{id}/revoke",
                post(
                    revoke_configuration,
                    &contracts::AGENT_CONFIGURATIONS,
                    &[RouteOperation::Lifecycle],
                ),
            ),
            post_authorize: rss_mdm_http_contract::module::Route::new(
                "/agent-requests/{id}/authorize",
                post(
                    authorize,
                    &contracts::AGENT_REQUEST_COMMANDS,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
            post_reenroll: rss_mdm_http_contract::module::Route::new(
                "/agent-requests/{id}/reenroll/{device}",
                post(
                    reenroll,
                    &contracts::AGENT_REQUEST_COMMANDS,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
            post_revoke: rss_mdm_http_contract::module::Route::new(
                "/agent-requests/{id}/cancel",
                post(
                    revoke,
                    &contracts::AGENT_REQUEST_COMMANDS,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
            get_settings: rss_mdm_http_contract::module::Route::new(
                "/agent-enrollment-settings",
                rss_mdm_http_contract::routing::get(
                    settings,
                    &contracts::AGENT_ENROLLMENT_SETTINGS,
                    &[RouteOperation::Get],
                ),
            ),
            put_update_settings: rss_mdm_http_contract::module::Route::new(
                "/agent-enrollment-settings",
                rss_mdm_http_contract::routing::put(
                    update_settings,
                    &contracts::AGENT_ENROLLMENT_SETTINGS,
                    &[RouteOperation::Update],
                ),
            ),
            post_recovery: rss_mdm_http_contract::module::Route::new(
                "/agent-registrations/{id}/recovery",
                post(
                    recovery,
                    &contracts::AGENT_REGISTRATION_RECOVERY,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
            post_recover_issuance: rss_mdm_http_contract::module::Route::new(
                "/agent-issuances/{id}/recover",
                post(
                    recover_issuance,
                    &contracts::AGENT_ISSUANCE_RECOVERY,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
            get_issuance_recovery_operation: rss_mdm_http_contract::module::Route::new(
                "/agent-issuances/{id}/recovery-operations/{operation}",
                get(
                    issuance_recovery_operation,
                    &contracts::AGENT_ISSUANCE_RECOVERY,
                    &[RouteOperation::Action],
                ),
            ),
        }
        .assemble()
    }
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
    identity: Result<
        Query<rss_mdm_registration_service::agent::queries::ReceiptIdentity>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<Option<wire::Candidate>>, Error> {
    let Query(identity) = identity.map_err(|_| Error::Malformed)?;
    app.as_ref()
        .as_deref()
        .ok_or(Error::Unsupported)?
        .issuance_recovery_operation(&auth.proof, id, operation, &identity)
        .await
        .map(Json)
        .map_err(Into::into)
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

struct RequestsQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for RequestsQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_registration_service::agent::queries::REQUESTS
    }
}
struct RecoveryOperationsQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for RecoveryOperationsQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_registration_service::agent::queries::OPERATIONS
    }
}
async fn request_directory(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path(device): Path<String>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<RequestsQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<
                    rss_mdm_registration_service::agent::queries::Request,
                >,
            >,
        >,
    >,
    Error,
> {
    let service = app.as_ref().as_deref().ok_or(Error::Unsupported)?;
    let query = query.parse().map_err(|_| Error::Malformed)?;
    service
        .request_directory(&auth.proof, &device, &query)
        .await
        .map(Json)
        .map(rss_mdm_http_contract::CollectionResponse)
        .map_err(Into::into)
}
async fn request_details(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_registration_service::agent::queries::Request>, Error> {
    app.as_ref()
        .as_deref()
        .ok_or(Error::Unsupported)?
        .request_details(&auth.proof, id)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn registration_recovery_operation(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path((id, operation)): Path<(Uuid, Uuid)>,
    identity: Result<
        Query<rss_mdm_registration_service::agent::queries::ReceiptIdentity>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<Option<wire::GrantReceipt>>, Error> {
    let Query(identity) = identity.map_err(|_| Error::Malformed)?;
    app.as_ref()
        .as_deref()
        .ok_or(Error::Unsupported)?
        .registration_recovery_operation(&auth.proof, id, operation, &identity)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn issuance_recovery_operations(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<RecoveryOperationsQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<
                    rss_mdm_registration_service::agent::queries::Operation,
                >,
            >,
        >,
    >,
    Error,
> {
    let service = app.as_ref().as_deref().ok_or(Error::Unsupported)?;
    let query = query.parse().map_err(|_| Error::Malformed)?;
    service
        .issuance_recovery_operations(&auth.proof, id, &query)
        .await
        .map(Json)
        .map(rss_mdm_http_contract::CollectionResponse)
        .map_err(Into::into)
}
