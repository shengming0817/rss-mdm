//! Session-authenticated Agent authorization, separate from native Enrollment passwords.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
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
        .map_err(|_| rss_mdm_registration_service::Error::Malformed.into())
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Operation {
    operation_id: Uuid,
}
pub fn routes(app: Option<Arc<Service>>) -> Router {
    Router::new()
        .route("/agent-requests/{id}", get(preview))
        .route("/agent-grants", post(create))
        .route("/self-enrollments/agent", post(create_self))
        .route("/self-enrollments/agent/{id}/cancel", post(cancel_self))
        .route("/agent-grants/{id}", get(status))
        .route("/agent-grants/{id}/approve", post(approve))
        .route("/agent-grants/{id}/revoke", post(revoke))
        .route("/agent-registrations/{id}/recovery", post(recovery))
        .route("/agent-issuances/{id}/recover", post(recover_issuance))
        .with_state(Arc::new(app))
}
async fn preview(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<Json<wire::AuthorizationRequest>, HttpFailure> {
    Ok(Json(service(&app)?.preview(&auth.proof, id).await?))
}
async fn create(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    input: Body<wire::GrantRequest>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    Ok(Json(
        service(&app)?
            .create(&auth.proof, &body(input)?, &a)
            .await?,
    ))
}
async fn status(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<Json<wire::Progress>, HttpFailure> {
    Ok(Json(service(&app)?.status(&auth.proof, id).await?))
}
async fn approve(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: Body<Operation>,
) -> Result<Json<wire::GrantReceipt>, HttpFailure> {
    Ok(Json(
        service(&app)?
            .approve(&auth.proof, id, body(input)?.operation_id, &a)
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
struct HttpFailure(Failure);
impl From<Failure> for HttpFailure {
    fn from(e: Failure) -> Self {
        Self(e)
    }
}
impl From<rss_mdm_registration_service::Error> for HttpFailure {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        Self(e.into())
    }
}
impl IntoResponse for HttpFailure {
    fn into_response(self) -> Response {
        use wire::ErrorCode as C;
        let status = match self.0.code {
            C::MalformedRequest => StatusCode::BAD_REQUEST,
            C::InvalidIdentity
            | C::CertificateExpired
            | C::CredentialRevoked
            | C::CredentialRetired => StatusCode::UNAUTHORIZED,
            C::PermissionDenied | C::GrantRevoked | C::GrantExpired => StatusCode::FORBIDDEN,
            C::RegistrationLimit => StatusCode::TOO_MANY_REQUESTS,
            C::OperationConflict => StatusCode::CONFLICT,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        let mut response = (
            status,
            Json(wire::ErrorBody {
                code: self.0.code,
                issuance_id: self.0.issuance_id,
            }),
        )
            .into_response();
        if let Some(e) = self.0.source {
            response.extensions_mut().insert(Error::from(e));
        }
        response
    }
}

async fn create_self(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    input: Body<wire::GrantRequest>,
) -> Result<Json<wire::GrantReceipt>, crate::Error> {
    let service = service(&app).map_err(|e| {
        crate::Error::from(
            e.0.source
                .unwrap_or(rss_mdm_registration_service::Error::Configuration),
        )
    })?;
    let input = input.map_err(|_| crate::Error::Malformed)?.0;
    service
        .create(&auth.proof, &input, &a)
        .await
        .map(Json)
        .map_err(|e| {
            crate::Error::from(
                e.source
                    .unwrap_or(rss_mdm_registration_service::Error::Storage),
            )
        })
}

async fn cancel_self(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: Body<Operation>,
) -> Result<Json<wire::GrantReceipt>, crate::Error> {
    let service = app
        .as_ref()
        .as_deref()
        .ok_or_else(|| crate::Error::from(rss_mdm_registration_service::Error::Configuration))?;
    let input = input.map_err(|_| crate::Error::Malformed)?.0;
    service
        .revoke(&auth.proof, id, input.operation_id, &a)
        .await
        .map(Json)
        .map_err(|e| {
            crate::Error::from(
                e.source
                    .unwrap_or(rss_mdm_registration_service::Error::Storage),
            )
        })
}
