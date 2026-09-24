//! Registration routes receive only the enrollment lifecycle dependencies.
use super::{Create, Resume};
use crate::{Error, api::write_key, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::HeaderMap,
};
use std::sync::Arc;
async fn create_enrollment(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Extension(continuation): Extension<crate::enrollment::credentials::SessionContinuation>,
    Extension(audit): Extension<RequestAudit>,
    input: Result<Json<Create>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::enrollment::Receipt>, Error> {
    let key = write_key(&headers, &audit, "enrollment_create")?;
    let input = input.map_err(|_| Error::Malformed)?.0;
    match input.source {
        rss_mdm_inventory::ReportSource::MdmWindows => {
            app.windows()?;
        }
        rss_mdm_inventory::ReportSource::MdmApple => {
            app.apple()?;
        }
        rss_mdm_inventory::ReportSource::AgentBuiltin => {}
    }
    app.service
        .create(&auth.proof, &input, &continuation, key, &audit)
        .await
        .map(Json)
}
async fn enrollment_status(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    path: Result<Path<uuid::Uuid>, axum::extract::rejection::PathRejection>,
) -> Result<Json<crate::enrollment::read::Status>, Error> {
    let Path(id) = path.map_err(|_| Error::Malformed)?;
    let device =
        crate::enrollment::store::enrollment_target(&app.service.access, &auth.proof, id).await?;
    let permission = auth.proof.enrollment(&device)?;
    audit.target(&device);
    crate::enrollment::read::enrollment_status(&app.service.access, permission, id)
        .await
        .map(Json)
}
async fn registrations(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
    query: Result<Query<crate::enrollment::read::Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<crate::enrollment::read::Registrations>, Error> {
    let Path(device) = path.map_err(|_| Error::Malformed)?;
    let Query(page) = query.map_err(|_| Error::Malformed)?;
    audit.target(&device);
    crate::enrollment::read::registration_list(&app.service.access, &auth.proof, &device, page)
        .await
        .map(Json)
}
async fn resume_enrollment(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Extension(continuation): Extension<crate::enrollment::credentials::SessionContinuation>,
    Extension(audit): Extension<RequestAudit>,
    path: Result<Path<uuid::Uuid>, axum::extract::rejection::PathRejection>,
    input: Result<Json<Resume>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::enrollment::Receipt>, Error> {
    let Path(id) = path.map_err(|_| Error::Malformed)?;
    let key = write_key(&headers, &audit, "enrollment_resume")?;
    let input = input.map_err(|_| Error::Malformed)?.0;
    app.service
        .resume(
            &auth.proof,
            super::ResumeCommand {
                id,
                password: &input.password,
                operation: key,
            },
            &continuation,
            &audit,
        )
        .await
        .map(Json)
}
async fn cancel_enrollment(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    path: Result<Path<uuid::Uuid>, axum::extract::rejection::PathRejection>,
    input: Result<Json<EmptyRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::enrollment::Receipt>, Error> {
    let Path(id) = path.map_err(|_| Error::Malformed)?;
    let Json(EmptyRequest {}) = input.map_err(|_| Error::Malformed)?;
    let key = write_key(&headers, &audit, "enrollment_cancel")?;
    let device =
        crate::enrollment::store::enrollment_target(&app.service.access, &auth.proof, id).await?;
    let permission = auth.proof.enrollment(&device)?;
    audit.target(&device);
    crate::enrollment::store::change_enrollment(
        &app.service.audit_store,
        permission,
        id,
        None,
        key,
        &audit,
    )
    .await
    .map(Json)
}
async fn revoke_registration(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    path: Result<Path<(String, uuid::Uuid)>, axum::extract::rejection::PathRejection>,
    input: Result<Json<EmptyRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::device::RevocationReceipt>, Error> {
    let Path((device, registration)) = path.map_err(|_| Error::Malformed)?;
    let Json(EmptyRequest {}) = input.map_err(|_| Error::Malformed)?;
    let key = write_key(&headers, &audit, "credential_revoke")?;
    audit.target(&device);
    app.devices
        .revoke_inner(&auth.proof, &device, registration, key, &audit)
        .await
        .map(Json)
}
pub(crate) struct HttpState {
    pub(crate) service: Arc<super::EnrollmentService>,
    pub(crate) devices: Arc<crate::device::DeviceService>,
    pub(crate) apple: bool,
    pub(crate) windows: bool,
}
impl HttpState {
    fn apple(&self) -> Result<(), Error> {
        self.apple.then_some(()).ok_or(Error::Unsupported)
    }
    fn windows(&self) -> Result<(), Error> {
        self.windows.then_some(()).ok_or(Error::Unsupported)
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

pub(crate) fn routes() -> axum::Router<Arc<HttpState>> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/enrollments", post(create_enrollment))
        .route("/enrollments/{id}", get(enrollment_status))
        .route("/devices/{device}/registrations", get(registrations))
        .route("/enrollments/{id}/resume", post(resume_enrollment))
        .route("/enrollments/{id}/cancel", post(cancel_enrollment))
        .route(
            "/devices/{device}/registrations/{registration}/revoke",
            post(revoke_registration),
        )
}

use rss_mdm_audit_integration::RequestAudit;
