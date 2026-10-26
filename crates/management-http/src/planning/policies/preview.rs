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
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
    body: std::result::Result<Json<Preview>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<Json<serde_json::Value>>, Error>
{
    (async {
        let Json(input) = body.map_err(Error::from)?;
        let (query, _) = rss_mdm_execution_service::queries::preview::SCHEMA
            .parse(raw.as_deref().unwrap_or_default())
            .map_err(|_| Error::Malformed)?;
        if matches!(
            input.definition.action,
            rss_mdm_policy::Action::TelemetryProfile { .. }
        ) {
            audit.set_action(
                "telemetry_profile_preview",
                rss_mdm_audit_integration::AuditIntent::Routine,
            );
            return s
                .telemetry
                .as_ref()
                .ok_or(Error::Unsupported)?
                .preview(&a.proof, input, &audit, query, codec)
                .await
                .map(Json)
                .map_err(crate::telemetry::error);
        }
        rss_mdm_execution_service::queries::preview::preview(
            &s.queries, &a.proof, &audit, &input, &query, &codec,
        )
        .await
        .map(|v| Json(serde_json::to_value(v).expect("execution preview serializes")))
        .map_err(Into::into)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
