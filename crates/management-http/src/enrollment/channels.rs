//! One authenticated projection of deployment readiness and tenant admission.
use super::http::HttpState;
use crate::{Error, api::write_key, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, put},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_registration_service::{
    admission::{Change, Setting},
    quotas::Channel,
};
use serde::Serialize;
use std::sync::Arc;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Unconfigured,
    Ready,
    Fault,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    NotConfigured,
    CertificateUnavailable,
    PushUnavailable,
    ClockUnavailable,
}
#[derive(Clone, Copy, Serialize)]
pub struct Status {
    pub availability: Availability,
    pub reason: Option<Reason>,
}
/// App observes existing channel owners; admission never changes their runtime.
pub trait Source: Send + Sync {
    fn status(&self, channel: Channel) -> Status;
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Channels {
    tenant_id: String,
    instance_id: String,
    channels: Vec<Entry>,
}
#[derive(Serialize)]
struct Entry {
    #[serde(flatten)]
    setting: Setting,
    #[serde(flatten)]
    status: Status,
}
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/registration-channels", get(read))
        .route("/registration-channels/{channel}/admission", put(change))
}
async fn read(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<Channels>, Error> {
    let settings = app.service.admission().read(&auth.proof).await?;
    Ok(Json(Channels {
        tenant_id: auth.proof.tenant_id().into(),
        instance_id: auth.proof.instance_id().into(),
        channels: settings
            .into_iter()
            .map(|setting| Entry {
                status: app.channels.status(setting.channel),
                setting,
            })
            .collect(),
    }))
}
async fn change(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(channel): Path<Channel>,
    headers: HeaderMap,
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
