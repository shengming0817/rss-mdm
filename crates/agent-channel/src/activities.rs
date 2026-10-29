//! Device-authenticated activity reads, independent of task execution capabilities.
//! ref: axum axum/src/extract/query.rs@axum-v0.8.9
use crate::{AgentError, TaskState, boundary};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::HeaderMap,
};
use rss_mdm_agent_wire::{activities::*, runtime::ErrorCode};
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
use rss_mdm_http_contract::query::{OwnedQuery, QueryOwner};
use rss_mdm_http_contract::{CollectionResponse, Operation, Router, catalog, routing::get};
use rss_mdm_timeline_service::{
    Timeline,
    activities::{ACTIVITIES, Query, Reader},
};
use std::sync::Arc;
struct Services {
    tasks: Arc<TaskState>,
    timeline: Arc<Timeline>,
}
pub fn router(
    tasks: Arc<TaskState>,
    timeline: Arc<Timeline>,
    envelope: boundary::Envelope,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    boundary::wrap(mount(Some(&(tasks, timeline))), envelope)
}
pub(crate) fn mount(
    runtime: Option<&(Arc<TaskState>, Arc<Timeline>)>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    declarations().bind_with(runtime, |(tasks, timeline)| {
        Arc::new(Services {
            tasks: tasks.clone(),
            timeline: timeline.clone(),
        })
    })
}
fn declarations() -> Router<Arc<Services>, impl rss_mdm_http_contract::module::Declaration + use<>>
{
    {
        rss_mdm_http_contract::route_module! { struct DeclarationsModule1 for [Agent] { get_history, get_changes, get_detail } }
        DeclarationsModule1 {
            get_history: rss_mdm_http_contract::module::Route::new(
                "/management-activities",
                get(history, &catalog::MANAGEMENT_ACTIVITIES, &[Operation::List]),
            ),
            get_changes: rss_mdm_http_contract::module::Route::new(
                "/management-activities/changes",
                get(changes, &catalog::MANAGEMENT_ACTIVITIES, &[Operation::List]),
            ),
            get_detail: rss_mdm_http_contract::module::Route::new(
                "/management-activities/{id}",
                get(detail, &catalog::MANAGEMENT_ACTIVITIES, &[Operation::Get]),
            ),
        }
        .assemble()
    }
}

fn error(e: rss_mdm_timeline_service::Error) -> AgentError {
    use rss_mdm_timeline_service::Error as E;
    AgentError::Wire(match e {
        E::Malformed => ErrorCode::MalformedRequest,
        E::Conflict => ErrorCode::ActivityCursorInvalidated,
        E::NotFound => ErrorCode::ActivityNotFound,
        E::Forbidden => ErrorCode::PermissionDenied,
        E::Storage | E::Integrity | E::Deadline => ErrorCode::ServiceUnavailable,
    })
}
async fn history(
    State(s): State<Arc<Services>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    raw: OwnedQuery<ActivityQuery>,
) -> Result<CollectionResponse<Json<ManagementActivityPage>>, AgentError> {
    page(s, audit, peer, headers, raw, false).await
}
async fn changes(
    State(s): State<Arc<Services>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    raw: OwnedQuery<ActivityQuery>,
) -> Result<CollectionResponse<Json<ManagementActivityPage>>, AgentError> {
    page(s, audit, peer, headers, raw, true).await
}
async fn page(
    s: Arc<Services>,
    audit: RequestAudit,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    raw: OwnedQuery<ActivityQuery>,
    changes: bool,
) -> Result<CollectionResponse<Json<ManagementActivityPage>>, AgentError> {
    crate::bounded(async {
        let p =
            crate::authenticate(&s.tasks.enrollment, &headers, peer.as_ref().map(|p| &p.0)).await?;
        audit.set_action("management_activity_read", AuditIntent::Routine);
        let query = raw.parse().map_err(error)?;
        let proof = if query.view.as_deref() == Some("personal") {
            Some(
                crate::tasks::employee(&s.tasks, &headers, &audit)
                    .await?
                    .ok_or(AgentError::Wire(ErrorCode::PermissionDenied))?,
            )
        } else {
            None
        };
        s.timeline
            .activities(
                &Reader::Agent {
                    device: &p,
                    user: proof.as_ref(),
                },
                &query,
                changes,
            )
            .await
            .map(|v| CollectionResponse(Json(v)))
            .map_err(error)
    })
    .await
}
async fn detail(
    State(s): State<Arc<Services>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    Path(id): Path<String>,
    raw: OwnedQuery<ActivityView>,
) -> Result<Json<ManagementActivityDetail>, AgentError> {
    crate::bounded(async {
        let personal = raw.parse()?;
        let p =
            crate::authenticate(&s.tasks.enrollment, &headers, peer.as_ref().map(|p| &p.0)).await?;
        audit.set_action("management_activity_read", AuditIntent::Routine);
        let proof = if personal {
            Some(
                crate::tasks::employee(&s.tasks, &headers, &audit)
                    .await?
                    .ok_or(AgentError::Wire(ErrorCode::PermissionDenied))?,
            )
        } else {
            None
        };
        s.timeline
            .activity_detail(
                &Reader::Agent {
                    device: &p,
                    user: proof.as_ref(),
                },
                &id,
                personal,
            )
            .await
            .map(Json)
            .map_err(error)
    })
    .await
}

struct ActivityQuery;
impl QueryOwner for ActivityQuery {
    type Parsed = Query;
    type Error = rss_mdm_timeline_service::Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Window(&ACTIVITIES))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let mut schema = rss_mdm_http_contract::signature::Schema::request::<Query>();
        schema.value["properties"]["limit"]["minimum"] = 1.into();
        schema.value["properties"]["limit"]["maximum"] = ACTIVITIES.max_limit.into();
        schema.value["properties"]["limit"]["default"] = ACTIVITIES.default_limit.into();
        schema
    }
    fn parse(raw: &str) -> Result<Query, Self::Error> {
        Query::parse(raw)
    }
}
struct ActivityView;
impl QueryOwner for ActivityView {
    type Parsed = bool;
    type Error = AgentError;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        None
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        rss_mdm_http_contract::signature::Schema {
            direction: rss_mdm_http_contract::signature::Direction::Request,
            value: serde_json::json!({
                "type":"object", "properties":{"view":{"type":"string", "enum":["summary","personal"],"default":"summary"}}, "additionalProperties":false
            }),
        }
    }
    fn parse(raw: &str) -> Result<bool, AgentError> {
        match raw {
            "" | "view=summary" => Ok(false),
            "view=personal" => Ok(true),
            _ => Err(AgentError::Wire(ErrorCode::MalformedRequest)),
        }
    }
}
