use super::*;
use crate::authorization::context::RequestAuth;
use axum::{Extension, Json, extract::State};
use rss_mdm_execution_service::queries::preview::Preview;
pub async fn preview(
    State(s): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: std::result::Result<Json<Preview>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<serde_json::Value>, Error> {
    let Json(input) = body.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    rss_mdm_execution_service::queries::preview::preview(&s, &a.proof, &audit, &input)
        .await
        .map(|v| Json(serde_json::to_value(v).expect("execution preview serializes")))
        .map_err(Into::into)
}
