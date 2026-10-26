//! Registration routes receive only the enrollment lifecycle dependencies.
use super::{Create, Resume};
use crate::{Error, api::write_key, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::HeaderMap,
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use std::sync::Arc;
async fn create_enrollment(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Extension(continuation): Extension<crate::http_operation::RequestContinuation>,
    Extension(audit): Extension<RequestAudit>,
    input: Result<Json<Create>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::enrollment::Receipt>, Error> {
    let key = write_key(&headers, &audit, "enrollment_create")?;
    let input = input.map_err(Error::from)?.0;
    match input.source {
        rss_mdm_inventory::ReportSource::MdmWindows => {
            app.windows()?;
        }
        rss_mdm_inventory::ReportSource::MdmApple => {
            app.apple()?;
        }
        rss_mdm_inventory::ReportSource::AgentBuiltin => return Err(Error::Malformed),
    }
    app.service
        .create(&auth.proof, &input, continuation.secret(), key, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn enrollment_status(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    path: Result<Path<uuid::Uuid>, axum::extract::rejection::PathRejection>,
) -> Result<Json<crate::enrollment::read::Status>, Error> {
    let Path(id) = path.map_err(|_| Error::Malformed)?;
    app.service
        .status(&auth.proof, id, &audit, app.native.as_ref())
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn registrations(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    path: Result<Path<String>, axum::extract::rejection::PathRejection>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<Json<rss_mdm_query::Page<serde_json::Value>>>,
    Error,
> {
    (async {
        let Path(device) = path.map_err(|_| Error::Malformed)?;
        let page = rss_mdm_registration_service::enrollment::registrations::SCHEMA
            .parse(raw.as_deref().unwrap_or_default())
            .map_err(|_| Error::Malformed)?;
        audit.target_device(&device);
        app.service
            .registrations(&auth.proof, &device, &page, &codec)
            .await
            .map(Json)
            .map_err(Error::from)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn resume_enrollment(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    Extension(auth): Extension<RequestAuth>,
    Extension(continuation): Extension<crate::http_operation::RequestContinuation>,
    Extension(audit): Extension<RequestAudit>,
    path: Result<Path<uuid::Uuid>, axum::extract::rejection::PathRejection>,
    input: Result<Json<Resume>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::enrollment::Receipt>, Error> {
    let Path(id) = path.map_err(|_| Error::Malformed)?;
    let key = write_key(&headers, &audit, "enrollment_resume")?;
    let input = input.map_err(Error::from)?.0;
    app.service
        .resume(
            &auth.proof,
            super::ResumeCommand {
                id,
                password: &input.password,
                operation: key,
            },
            continuation.secret(),
            &audit,
        )
        .await
        .map(Json)
        .map_err(Error::from)
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
    let Json(EmptyRequest {}) = input.map_err(Error::from)?;
    let key = write_key(&headers, &audit, "enrollment_cancel")?;
    app.service
        .cancel(&auth.proof, id, key, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
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
    let Json(EmptyRequest {}) = input.map_err(Error::from)?;
    let key = write_key(&headers, &audit, "credential_revoke")?;
    audit.target_device(&device);
    app.devices
        .revoke_inner(&auth.proof, &device, registration, key, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
pub struct HttpState {
    pub channels: Arc<dyn super::channels::Source>,
    pub service: Arc<super::EnrollmentService>,
    pub native: Arc<dyn super::read::NativeProgress>,
    pub devices: Arc<crate::device::DeviceService>,
    pub apple: bool,
    pub windows: bool,
}
impl HttpState {
    pub(super) fn apple(&self) -> Result<(), Error> {
        self.apple.then_some(()).ok_or(Error::Unsupported)
    }
    pub(super) fn windows(&self) -> Result<(), Error> {
        self.windows.then_some(()).ok_or(Error::Unsupported)
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

pub fn routes(
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> rss_mdm_http_contract::Router<Arc<HttpState>> {
    use rss_mdm_http_contract::routing::{get, post};
    rss_mdm_http_contract::Router::new()
        .merge(super::quotas::routes())
        .merge(super::registration_user::routes())
        .merge(super::channels::routes())
        .route(
            "/enrollments",
            post(create_enrollment)
                .owned(&contracts::ENROLLMENT_ATTEMPTS, &[RouteOperation::Create]),
        )
        .route(
            "/enrollments/{id}",
            get(enrollment_status).owned(&contracts::ENROLLMENT_ATTEMPTS, &[RouteOperation::Get]),
        )
        .route(
            "/devices/{device}/registrations",
            get(registrations)
                .owned(&contracts::DEVICE_REGISTRATIONS, &[RouteOperation::List])
                .queried(&rss_mdm_registration_service::enrollment::registrations::SCHEMA),
        )
        .route(
            "/enrollments/{id}/resume",
            post(resume_enrollment).owned(
                &contracts::ENROLLMENT_ATTEMPTS,
                &[RouteOperation::Action, RouteOperation::Lifecycle],
            ),
        )
        .route(
            "/enrollments/{id}/cancel",
            post(cancel_enrollment).owned(
                &contracts::ENROLLMENT_ATTEMPTS,
                &[RouteOperation::Action, RouteOperation::Lifecycle],
            ),
        )
        .route(
            "/devices/{device}/registrations/{registration}/revoke",
            post(revoke_registration).owned(&contracts::DEVICES, &[RouteOperation::Lifecycle]),
        )
        .layer(axum::Extension(cursor))
}

use rss_mdm_audit_integration::RequestAudit;
