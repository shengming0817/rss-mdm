use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, RawQuery, State},
};
use rss_mdm_execution_service::queries::Queries;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

pub fn routes(cursor: rss_mdm_query::cursor::CursorCodec) -> Router<Arc<Queries>> {
    Router::new()
        .route(
            "/policies/{id}/runs",
            get(runs)
                .owned(&contracts::POLICY_RUNS, &[RouteOperation::List])
                .windowed(&super::history::SCHEMA),
        )
        .route(
            "/policies/{id}/software/rollout",
            get(rollout).owned(&contracts::POLICIES, &[RouteOperation::Action]),
        )
        .route(
            "/policies/{id}/runs/{task}",
            get(run).owned(&contracts::POLICIES, &[RouteOperation::Action]),
        )
        .layer(axum::Extension(cursor))
}
async fn rollout(
    State(app): State<Arc<Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, Error> {
    audit.operation(
        id,
        "command_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    app.software_rollout(&auth.proof, id, &audit)
        .await
        .map(|v| Json(serde_json::to_value(v).expect("execution facts serialize")))
        .map_err(Error::from)
}

async fn runs(
    State(app): State<Arc<Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    RawQuery(raw): RawQuery,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<Value>>, Error> {
    (async {
        audit.operation(
            id,
            "command_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        audit.plan(id);
        let (page, _) = super::history::SCHEMA
            .parse(raw.as_deref().unwrap_or_default())
            .map_err(|_| Error::Malformed)?;
        app.action_runs(&auth.proof, id, &page, &codec, &audit)
            .await
            .map(|v| Json(serde_json::to_value(v).expect("execution facts serialize")))
            .map_err(Error::from)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn run(
    State(app): State<Arc<Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, task)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, Error> {
    audit.operation(
        task,
        "command_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.plan(id);
    audit.target(&task.to_string());
    app.action_run(&auth.proof, id, task, &audit)
        .await
        .map(|v| Json(serde_json::to_value(v).expect("execution facts serialize")))
        .map_err(Error::from)
}

use rss_mdm_audit_integration::RequestAudit;
