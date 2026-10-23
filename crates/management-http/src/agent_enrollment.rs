//! Session-authenticated Agent authorization, separate from native Enrollment passwords.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rss_mdm_agent_wire::enroll as wire;
use rss_mdm_audit_integration::RequestAudit;
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
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Operation {
    operation_id: Uuid,
}
pub fn routes(app: Option<Arc<Service>>) -> Router {
    Router::new()
        .route(
            "/agent-connections",
            get(connection_state).put(save_connections),
        )
        .route("/agent-connections/publish", post(publish_connections))
        .route("/agent-connections/devices", get(unconfirmed_devices))
        .route(
            "/agent-connections/configuration",
            get(download_connections),
        )
        .route(
            "/agent-connection-operations/{id}",
            get(connection_operation),
        )
        .route(
            "/agent-connections/devices/{device}/observation",
            get(connection_observation),
        )
        .route("/agent-configurations", post(create_configuration))
        .route("/agent-configurations/{id}", get(read_configuration))
        .route(
            "/agent-configuration-operations/{id}",
            get(configuration_operation),
        )
        .route(
            "/agent-configurations/{id}/revoke",
            post(revoke_configuration),
        )
        .route("/agent-requests/{id}/authorize", post(authorize))
        .route("/agent-requests/{id}/reenroll/{device}", post(reenroll))
        .route("/agent-requests/{id}/cancel", post(revoke))
        .route(
            "/agent-enrollment-settings",
            get(settings).put(update_settings),
        )
        .route("/agent-registrations/{id}/recovery", post(recovery))
        .route("/agent-issuances/{id}/recover", post(recover_issuance))
        .route(
            "/agent-issuances/{id}/recovery-operations/{operation}",
            get(issuance_recovery_operation),
        )
        .with_state(Arc::new(app))
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
        use wire::ErrorCode as C;
        let status = match failure.code {
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
        };
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
) -> Result<Response, HttpFailure> {
    let file = Json(
        service(&app)?
            .create_configuration(&auth.proof, &body(input)?, &a)
            .await?,
    );
    let disposition = format!(
        "attachment; filename=\"{}\"",
        rss_mdm_registration_service::agent::settings::CONFIGURATION_FILENAME
    );
    Ok((
        [(axum::http::header::CONTENT_DISPOSITION, disposition)],
        file,
    )
        .into_response())
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
) -> Result<StatusCode, HttpFailure> {
    service(&app)?
        .revoke_configuration(&auth.proof, id, body(input)?.operation_id, &a)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn download_connections(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Response, HttpFailure> {
    let state = service(&app)?.connection_state(&auth.proof).await?;
    let configuration = state
        .published
        .ok_or(rss_mdm_registration_service::Error::Conflict)?;
    let mut response = Json(configuration).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_static("attachment; filename=\"rss-agent-connections.json\""),
    );
    Ok(response)
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
