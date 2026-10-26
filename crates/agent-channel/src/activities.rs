//! Device-authenticated activity reads, independent of task execution capabilities.
//! ref: axum axum/src/extract/query.rs@axum-v0.8.9
use crate::{AgentError, TaskState, boundary};
use axum::{
    Extension, Json,
    extract::{Path, RawQuery, State},
    http::HeaderMap,
};
use rss_mdm_agent_wire::{activities::*, runtime::ErrorCode};
use rss_mdm_audit_integration::{AuditIntent, RequestAudit};
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
) -> Router {
    let routes = Router::new()
        .route(
            "/management-activities",
            get(history)
                .owned(&catalog::MANAGEMENT_ACTIVITIES, &[Operation::List])
                .windowed(&ACTIVITIES),
        )
        .route(
            "/management-activities/changes",
            get(changes)
                .owned(&catalog::MANAGEMENT_ACTIVITIES, &[Operation::List])
                .windowed(&ACTIVITIES),
        )
        .route(
            "/management-activities/{id}",
            get(detail).owned(&catalog::MANAGEMENT_ACTIVITIES, &[Operation::Get]),
        )
        .with_state(Arc::new(Services { tasks, timeline }));
    boundary::wrap(routes, envelope)
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
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<CollectionResponse<Json<ManagementActivityPage>>, AgentError> {
    page(s, audit, peer, headers, raw, false).await
}
async fn changes(
    State(s): State<Arc<Services>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<CollectionResponse<Json<ManagementActivityPage>>, AgentError> {
    page(s, audit, peer, headers, raw, true).await
}
async fn page(
    s: Arc<Services>,
    audit: RequestAudit,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    raw: Option<String>,
    changes: bool,
) -> Result<CollectionResponse<Json<ManagementActivityPage>>, AgentError> {
    crate::bounded(async {
        let p =
            crate::authenticate(&s.tasks.enrollment, &headers, peer.as_ref().map(|p| &p.0)).await?;
        audit.set_action("management_activity_read", AuditIntent::Routine);
        let query = Query::parse(raw.as_deref().unwrap_or_default()).map_err(error)?;
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
    headers: HeaderMap,
    Path(id): Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<Json<ManagementActivityDetail>, AgentError> {
    crate::bounded(async {
        let personal = match raw.as_deref().unwrap_or_default() {
            "" | "view=summary" => false,
            "view=personal" => true,
            _ => return Err(AgentError::Wire(ErrorCode::MalformedRequest)),
        };
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
