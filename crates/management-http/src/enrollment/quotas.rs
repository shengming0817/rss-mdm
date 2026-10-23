//! Quota configuration and self-enrollment use the existing authenticated browser owner.
use super::http::HttpState;
use crate::{Error, api::write_key, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::HeaderMap,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::User;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use rss_mdm_registration_service::quotas::{Change, Configuration, Usage};
use std::sync::Arc;
use uuid::Uuid;
type App = Arc<HttpState>;
fn user(auth: &RequestAuth, instance: Uuid, principal: Uuid) -> User {
    User {
        tenant_id: auth.proof.tenant_id().into(),
        instance_id: instance.to_string(),
        principal_id: principal.to_string(),
    }
}
pub fn routes() -> Router<App> {
    Router::new()
        .route(
            "/registration-quotas/me",
            get(me).owned(&contracts::REGISTRATION_QUOTA_USAGE, &[RouteOperation::Get]),
        )
        .route(
            "/registration-quotas/defaults",
            get(defaults)
                .owned(
                    &contracts::REGISTRATION_DEFAULT_QUOTA,
                    &[RouteOperation::Get],
                )
                .put(defaults_write)
                .owned(
                    &contracts::REGISTRATION_DEFAULT_QUOTA,
                    &[RouteOperation::Update],
                ),
        )
        .route(
            "/registration-quotas/users/{instance}/{principal}",
            get(overrides)
                .owned(&contracts::REGISTRATION_USER_QUOTA, &[RouteOperation::Get])
                .put(overrides_write)
                .owned(
                    &contracts::REGISTRATION_USER_QUOTA,
                    &[RouteOperation::Update],
                ),
        )
        .route(
            "/registration-quotas/users/{instance}/{principal}/usage",
            get(usage).owned(&contracts::REGISTRATION_USER_QUOTA, &[RouteOperation::Get]),
        )
        .route(
            "/self-enrollments",
            get(options)
                .owned(&contracts::SELF_ENROLLMENTS, &[RouteOperation::List])
                .post(create_self)
                .owned(&contracts::SELF_ENROLLMENTS, &[RouteOperation::Create]),
        )
}
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Options {
    channels: Vec<super::read::ChannelOption>,
    quotas: Usage,
}
async fn options(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<Options>, Error> {
    Ok(Json(Options {
        channels: app.native.channels(),
        quotas: app.service.quotas().usage(&auth.proof, None).await?,
    }))
}
async fn me(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<Usage>, Error> {
    app.service
        .quotas()
        .usage(&auth.proof, None)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn defaults(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<Configuration>, Error> {
    app.service
        .quotas()
        .configuration(&auth.proof, None)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn overrides(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path((instance, principal)): Path<(Uuid, Uuid)>,
) -> Result<Json<Configuration>, Error> {
    app.service
        .quotas()
        .configuration(&auth.proof, Some(&user(&auth, instance, principal)))
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn usage(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path((instance, principal)): Path<(Uuid, Uuid)>,
) -> Result<Json<Usage>, Error> {
    app.service
        .quotas()
        .usage(&auth.proof, Some(&user(&auth, instance, principal)))
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn defaults_write(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    input: Result<Json<Change>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Configuration>, Error> {
    let key = write_key(&headers, &audit, "registration_quota_change")?;
    let input = input.map_err(Error::from)?.0;
    app.service
        .quotas()
        .change(&auth.proof, None, &input, key, &audit)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn overrides_write(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    Path((instance, principal)): Path<(Uuid, Uuid)>,
    input: Result<Json<Change>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Configuration>, Error> {
    let key = write_key(&headers, &audit, "registration_quota_change")?;
    let input = input.map_err(Error::from)?.0;
    app.service
        .quotas()
        .change(
            &auth.proof,
            Some(&user(&auth, instance, principal)),
            &input,
            key,
            &audit,
        )
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn create_self(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(continuation): Extension<crate::http_operation::RequestContinuation>,
    headers: HeaderMap,
    input: Result<Json<super::SelfCreate>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<super::SelfReceipt>, Error> {
    let key = write_key(&headers, &audit, "enrollment_create")?;
    let input = input.map_err(Error::from)?.0;
    match input.source {
        rss_mdm_inventory::ReportSource::MdmWindows => app.windows()?,
        rss_mdm_inventory::ReportSource::MdmApple => app.apple()?,
        rss_mdm_inventory::ReportSource::AgentBuiltin => return Err(Error::Malformed),
    }
    app.service
        .create_self(&auth.proof, &input, continuation.secret(), key, &audit)
        .await
        .map(Json)
        .map_err(Into::into)
}
