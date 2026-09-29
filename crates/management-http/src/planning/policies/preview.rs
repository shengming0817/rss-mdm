use super::*;
use crate::authorization::context::RequestAuth;
use axum::{Extension, Json, extract::State};
use rss_mdm_flow_service::planning::policies::preview::Preview;
pub async fn preview(
    State(s): State<Arc<Policies>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: std::result::Result<Json<Preview>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<serde_json::Value>, Error> {
    let Json(input) = body.map_err(|_| Error::Malformed)?;
    rss_mdm_flow_service::planning::policies::preview::preview(&s, &a.proof, &audit, &input)
        .await
        .map(Json)
        .map_err(Into::into)
}
