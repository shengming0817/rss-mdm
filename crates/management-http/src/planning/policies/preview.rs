use super::*;
use crate::authorization::context::RequestAuth;
use axum::{Extension, Json, extract::State};
use rss_mdm_policy_service::management::scopes::Qualification;
pub struct StateServices {
    pub policies: Arc<Policies>,
    pub configuration: Arc<rss_mdm_policy_service::configuration::preview::Previews>,
    pub tasks: Arc<dyn crate::execution::task_reads::Reads>,
    pub telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
}
pub async fn preview(
    State(s): State<Arc<StateServices>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    axum::extract::Path(policy): axum::extract::Path<Uuid>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<PreviewQuery>,
    >,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
    body: std::result::Result<Json<Qualification>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<Json<PreviewResponse>>, Error> {
    (async {
        let Json(draft) = body.map_err(Error::from)?;
        let input = s.policies.qualify(&a.proof, policy, &draft).await?;
        let (query, _) = query.parse().map_err(|_| Error::Malformed)?;
        let response = if matches!(
            input.definition.action,
            rss_mdm_policy::Action::Configuration { .. }
        ) {
            PreviewResponse::Configuration(
                s.configuration
                    .preview(&a.proof, &audit, &input, &query, &codec)
                    .await?,
            )
        } else if matches!(
            input.definition.action,
            rss_mdm_policy::Action::TelemetryProfile { .. }
        ) {
            audit.set_action(
                "telemetry_profile_preview",
                rss_mdm_audit_integration::AuditIntent::Routine,
            );
            PreviewResponse::Telemetry(
                s.telemetry
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .preview(&a.proof, input, &audit, query, codec)
                    .await
                    .map_err(crate::telemetry::error)?,
            )
        } else {
            PreviewResponse::Execution(s.tasks.preview(&a, &audit, &input, &query, &codec).await?)
        };
        // The owner may finish in another read transaction; fence intervening Policy edits.
        s.policies.qualify(&a.proof, policy, &draft).await?;
        Ok(Json(response))
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
