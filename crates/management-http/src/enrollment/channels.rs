//! One authenticated projection of deployment readiness and tenant admission.
use super::http::HttpState;
use crate::{Error, api::write_key, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, put},
};
use rss_mdm_registration_service::{
    admission::{Change, Setting},
    quotas::Channel,
};
use serde::Serialize;
use std::sync::Arc;

#[derive(schemars::JsonSchema, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Unconfigured,
    Ready,
    Fault,
}
#[derive(schemars::JsonSchema, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    NotConfigured,
    CertificateUnavailable,
    PushUnavailable,
    ClockUnavailable,
}
#[derive(schemars::JsonSchema, Clone, Copy, Serialize)]
pub struct Status {
    pub availability: Availability,
    pub reason: Option<Reason>,
}
/// App observes existing channel owners; admission never changes their runtime.
pub trait Source: Send + Sync {
    fn status<'a>(
        &'a self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        channel: Channel,
    ) -> futures::future::BoxFuture<'a, Status>;
    fn endpoints(&self, tenant: rss_request_context::TenantId) -> PublicEndpoints;
}
/// Runtime public locators; they do not authorize browser sessions or change native device URLs.
#[derive(schemars::JsonSchema, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicEndpoints {
    pub console: String,
    pub agent: Vec<String>,
    pub windows_enrollment: Option<String>,
    pub windows_management: Vec<String>,
    pub apple_management: Option<String>,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
struct Channels {
    tenant_id: String,
    instance_id: String,
    public_endpoints: PublicEndpoints,
    channels: Vec<Entry>,
}
#[derive(schemars::JsonSchema, Serialize)]
struct Entry {
    #[serde(flatten)]
    setting: Setting,
    #[serde(flatten)]
    status: Status,
}
pub fn routes() -> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Browser] { get_read, put_change } }
        RoutesModule1 {
            get_read: rss_mdm_http_contract::module::Route::new(
                "/registration-channels",
                get(
                    read,
                    &contracts::REGISTRATION_CHANNELS,
                    &[RouteOperation::Get],
                ),
            ),
            put_change: rss_mdm_http_contract::module::Route::new(
                "/registration-channels/{channel}/admission",
                put(
                    change,
                    &contracts::REGISTRATION_CHANNELS,
                    &[RouteOperation::Update],
                ),
            ),
        }
        .assemble()
    }
}
async fn read(
    axum::extract::Path(_tenant): axum::extract::Path<uuid::Uuid>,

    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<Channels>, Error> {
    let settings = app.service.admission().read(&auth.proof).await?;
    let mut channels = Vec::new();
    for setting in settings {
        channels.push(Entry {
            status: app
                .channels
                .status(auth.proof.binding(), setting.channel)
                .await,
            setting,
        });
    }
    Ok(Json(Channels {
        tenant_id: auth.proof.tenant_id().into(),
        instance_id: auth.proof.instance_id().into(),
        public_endpoints: app.channels.endpoints(auth.proof.binding().tenant()),
        channels,
    }))
}
async fn change(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((_tenant, channel)): Path<(uuid::Uuid, Channel)>,
    headers: crate::api::WriteHeaders,
    input: Result<Json<Change>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Setting>, Error> {
    let key = write_key(&headers, &audit, "registration_admission_change")?;
    app.service
        .admission()
        .change(
            &auth.proof,
            channel,
            &input.map_err(Error::from)?.0,
            key,
            &audit,
        )
        .await
        .map(Json)
        .map_err(Into::into)
}
