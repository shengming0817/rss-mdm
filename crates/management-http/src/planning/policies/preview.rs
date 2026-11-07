use super::*;
use crate::authorization::context::RequestAuth;
use axum::{Extension, Json, extract::State};
use rss_mdm_policy::pages::Preview;
pub struct StateServices {
    pub configuration: Arc<rss_mdm_policy_service::configuration::preview::Previews>,
    pub tasks: Arc<dyn crate::execution::task_reads::Reads>,
    pub telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
}
pub async fn preview(
    State(s): State<Arc<StateServices>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<PreviewQuery>,
    >,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
    body: std::result::Result<Json<Preview>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<Json<PreviewResponse>>, Error> {
    (async {
        let Json(input) = body.map_err(Error::from)?;
        let (query, _) = query.parse().map_err(|_| Error::Malformed)?;
        if matches!(
            input.definition.action,
            rss_mdm_policy::Action::Configuration { .. }
        ) {
            return s
                .configuration
                .preview(&a.proof, &audit, &input, &query, &codec)
                .await
                .map(|v| Json(PreviewResponse::Configuration(v)))
                .map_err(Into::into);
        }
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
                .map(|v| Json(PreviewResponse::Telemetry(v)))
                .map_err(crate::telemetry::error);
        }
        s.tasks
            .preview(&a, &audit, &input, &query, &codec)
            .await
            .map(|v| Json(PreviewResponse::Execution(v)))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

pub(crate) struct PreviewQuery;
impl rss_mdm_http_contract::query::WindowOwner for PreviewQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_policy::pages::PREVIEW_SCHEMA
    }
}

#[derive(schemars::JsonSchema, serde::Serialize)]
#[serde(untagged)]
pub enum PreviewResponse {
    Configuration(rss_mdm_policy_service::configuration::preview::Response),
    Execution(crate::execution::task_reads::Preview),
    Telemetry(rss_mdm_telemetry_service::preview::PreviewResponse),
}
