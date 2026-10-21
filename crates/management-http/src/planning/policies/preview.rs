use super::*;
use crate::authorization::context::RequestAuth;
use axum::{Extension, Json, extract::State};
use rss_mdm_execution_service::queries::preview::Preview;
pub struct StateServices {
    pub queries: Arc<rss_mdm_execution_service::queries::Queries>,
    pub telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
}
pub async fn preview(
    State(s): State<Arc<StateServices>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: std::result::Result<Json<Preview>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<serde_json::Value>, Error> {
    let Json(input) = body.map_err(Error::from)?;
    if matches!(
        input.definition.action,
        rss_mdm_policy::Action::TelemetryProfile { .. }
    ) {
        audit.set_action("telemetry_profile_preview");
        return s
            .telemetry
            .as_ref()
            .ok_or(Error::Unsupported)?
            .preview(&a.proof, input, &audit)
            .await
            .map(Json)
            .map_err(crate::telemetry::error);
    }
    rss_mdm_execution_service::queries::preview::preview(&s.queries, &a.proof, &audit, &input)
        .await
        .map(|v| Json(serde_json::to_value(v).expect("execution preview serializes")))
        .map_err(Into::into)
}
