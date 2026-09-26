use super::*;
use crate::authorization::{Permission, context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use serde::Deserialize;
type Response = std::result::Result<Json<Value>, Error>;
fn authorize(auth: &RequestAuth, c: &Command) -> std::result::Result<(), Error> {
    let (permission, device) = match c {
        Command::Put { .. } => (Permission::ComplianceWrite, None),
        Command::Recompute { .. } => (Permission::ComplianceRecompute, None),
        Command::Current { device } | Command::History { device, .. } => {
            (Permission::ComplianceRead, Some(device.as_str()))
        }
        _ => (Permission::ComplianceRuleRead, None),
    };
    auth.proof.require(permission, device)
}
async fn run(s: &Compliance, a: &RequestAuth, audit: &RequestAudit, c: Command) -> Response {
    audit.set_action(if c.operation().is_some() {
        "compliance_write"
    } else {
        "compliance_read"
    });
    match &c {
        Command::Current { device } | Command::History { device, .. } => audit.target(device),
        Command::Read { id }
        | Command::Version { id, .. }
        | Command::Put { id, .. }
        | Command::Recompute { id, .. }
        | Command::Task { id, .. } => audit.target(&id.to_string()),
        _ => {}
    }
    if let Some(id) = c.operation() {
        audit.operation(id, audit.snapshot().action)
    }
    authorize(a, &c)?;
    s.execute(&c, audit, &|| authorize(a, &c)).await.map(Json)
}
pub(crate) fn routes() -> Router<Arc<Compliance>> {
    Router::new()
        .route("/compliance-rules", get(list))
        .route("/compliance-rules/{id}", get(read).put(put))
        .route("/compliance-rules/{id}/versions/{revision}", get(version))
        .route("/compliance-rules/{id}/recompute", post(recompute))
        .route("/compliance-rules/{id}/tasks/{task}", get(task))
        .route("/devices/{id}/compliance", get(current))
        .route("/devices/{id}/compliance/history", get(history))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    after: Option<Uuid>,
}
async fn list(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    q: std::result::Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Response {
    run(
        &s,
        &a,
        &audit,
        Command::List {
            after: q.map_err(|_| Error::Malformed)?.0.after,
        },
    )
    .await
}
async fn read(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Response {
    run(&s, &a, &audit, Command::Read { id }).await
}
async fn put(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: std::result::Result<
        Json<crate::http_operation::Operation<Definition>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    run(
        &s,
        &a,
        &audit,
        Command::Put {
            id,
            request: body.map_err(|_| Error::Malformed)?.0,
        },
    )
    .await
}
async fn recompute(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: std::result::Result<
        Json<crate::http_operation::Operation<Empty>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    run(
        &s,
        &a,
        &audit,
        Command::Recompute {
            id,
            request: body.map_err(|_| Error::Malformed)?.0,
        },
    )
    .await
}
async fn task(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, task)): Path<(Uuid, Uuid)>,
) -> Response {
    run(&s, &a, &audit, Command::Task { id, task }).await
}
async fn current(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
) -> Response {
    run(&s, &a, &audit, Command::Current { device }).await
}
async fn history(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    q: std::result::Result<Query<HistoryPage>, axum::extract::rejection::QueryRejection>,
) -> Response {
    run(
        &s,
        &a,
        &audit,
        Command::History {
            device,
            subject: format!("{}:{}", a.proof.instance_id(), a.proof.principal_id()),
            page: q.map_err(|_| Error::Malformed)?.0,
        },
    )
    .await
}

async fn version(
    State(s): State<Arc<Compliance>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, revision)): Path<(Uuid, i64)>,
) -> Response {
    run(&s, &a, &audit, Command::Version { id, revision }).await
}
