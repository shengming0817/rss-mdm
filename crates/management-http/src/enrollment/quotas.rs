//! Quota configuration and self-enrollment use the existing authenticated browser owner.
use super::http::HttpState;
use crate::{Error, api::write_key, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
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
pub fn routes() -> Router<App, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Browser] { get_me, get_defaults, put_defaults_write, get_overrides, put_overrides_write, get_usage, get_options, post_create_self } }
        RoutesModule1 {
            get_me: rss_mdm_http_contract::module::Route::new(
                "/registration-quotas/me",
                get(
                    me,
                    &contracts::REGISTRATION_QUOTA_USAGE,
                    &[RouteOperation::Get],
                ),
            ),
            get_defaults: rss_mdm_http_contract::module::Route::new(
                "/registration-quotas/defaults",
                rss_mdm_http_contract::routing::get(
                    defaults,
                    &contracts::REGISTRATION_DEFAULT_QUOTA,
                    &[RouteOperation::Get],
                ),
            ),
            put_defaults_write: rss_mdm_http_contract::module::Route::new(
                "/registration-quotas/defaults",
                rss_mdm_http_contract::routing::put(
                    defaults_write,
                    &contracts::REGISTRATION_DEFAULT_QUOTA,
                    &[RouteOperation::Update],
                ),
            ),
            get_overrides: rss_mdm_http_contract::module::Route::new(
                "/registration-quotas/users/{instance}/{principal}",
                rss_mdm_http_contract::routing::get(
                    overrides,
                    &contracts::REGISTRATION_USER_QUOTA,
                    &[RouteOperation::Get],
                ),
            ),
            put_overrides_write: rss_mdm_http_contract::module::Route::new(
                "/registration-quotas/users/{instance}/{principal}",
                rss_mdm_http_contract::routing::put(
                    overrides_write,
                    &contracts::REGISTRATION_USER_QUOTA,
                    &[RouteOperation::Update],
                ),
            ),
            get_usage: rss_mdm_http_contract::module::Route::new(
                "/registration-quotas/users/{instance}/{principal}/usage",
                get(
                    usage,
                    &contracts::REGISTRATION_USER_QUOTA,
                    &[RouteOperation::Get],
                ),
            ),
            get_options: rss_mdm_http_contract::module::Route::new(
                "/self-enrollments",
                rss_mdm_http_contract::routing::get(
                    options,
                    &contracts::SELF_ENROLLMENTS,
                    &[RouteOperation::Get],
                ),
            ),
            post_create_self: rss_mdm_http_contract::module::Route::new(
                "/self-enrollments",
                rss_mdm_http_contract::routing::post(
                    create_self,
                    &contracts::SELF_ENROLLMENTS,
                    &[RouteOperation::Create],
                ),
            ),
        }
        .assemble()
    }
}
#[derive(schemars::JsonSchema, serde::Serialize)]
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
    headers: crate::api::WriteHeaders,
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
    headers: crate::api::WriteHeaders,
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
    headers: crate::api::WriteHeaders,
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
