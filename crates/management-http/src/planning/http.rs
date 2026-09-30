//! ref: axum 0.8.9 axum/src/routing/mod.rs (protected tree composition).
use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::Value;
type BodyInput<T> = std::result::Result<Json<T>, axum::extract::rejection::JsonRejection>;
fn body<T>(value: BodyInput<T>) -> std::result::Result<T, Error> {
    value
        .map(|v| v.0)
        .map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))
}
pub fn routes_v2() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/groups", get(group_directory))
        .route("/scopes", get(scope_directory))
        .route("/groups/{id}", get(group_read).post(group_write))
        .route("/groups/{id}/previews", post(group_preview))
        .route("/groups/{group}/results/{result}/{kind}", get(group_page))
        .route("/scopes/{scope}/results/{result}/{kind}", get(scope_page))
        .route("/scopes/{id}", get(scope_read).post(scope_write))
        .route("/groups/{group}/tasks/{task}", get(group_task))
        .route("/scopes/{scope}/tasks/{task}", get(scope_task))
}
// Group receipts/read models include derived membership counts. Every result
// projection and task summary uses the full tenant input, so grant changes must
// be checked again even when reading an immutable result with an old cursor.
fn exposes_inventory(command: &Command) -> bool {
    matches!(
        command,
        Command::Group { .. }
            | Command::GroupRead { .. }
            | Command::GroupPreview { .. }
            | Command::GroupPage { .. }
            | Command::ScopePage { .. }
            | Command::TaskRead { .. }
    )
}
async fn run(
    app: &HttpState,
    auth: &RequestAuth,
    audit: &RequestAudit,
    permission: Permission,
    command: Command,
) -> std::result::Result<Response, Error> {
    match &command {
        Command::Group { id, .. }
        | Command::GroupRead { id }
        | Command::GroupPreview { id, .. }
        | Command::Scope { id, .. }
        | Command::ScopeRead { id } => audit.target(&id.to_string()),
        Command::TaskRead { id, .. } => audit.target(&id.to_string()),
        Command::GroupPage { group, .. } => audit.target(&group.to_string()),
        Command::ScopePage { scope, .. } => audit.target(&scope.to_string()),
    }

    audit.set_action(match command {
        Command::ScopePage { .. }
        | Command::GroupPage { .. }
        | Command::TaskRead { .. }
        | Command::GroupRead { .. }
        | Command::ScopeRead { .. }
        | Command::GroupPreview { .. } => "management_read",
        _ => "management_write",
    });
    let (operation, _) = storage::identity(&command, audit)
        .map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    if let Some(id) = operation {
        audit.operation(id, audit.snapshot().action);
    }
    let authorize = || {
        auth.proof.manage(permission)?;
        if exposes_inventory(&command) {
            assets::ReadScope::from_proof(&auth.proof)?
                .full()
                .map_err(rss_mdm_inventory_service::Error::from)?;
        }
        Ok(())
    };
    authorize()?;
    let response =
        wire::Response::decode(app.planning.execute(&command, audit, &authorize).await?)?;
    let status = if matches!(response, wire::Response::JobAccepted(_)) {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(response)).into_response())
}
macro_rules! read {
    ($handler:ident,$id:ty,$permission:ident,$command:ident) => {
        async fn $handler(
            State(app): State<Arc<HttpState>>,
            Extension(auth): Extension<RequestAuth>,
            Extension(audit): Extension<RequestAudit>,
            Path(id): Path<$id>,
        ) -> std::result::Result<Response, Error> {
            run(
                &app,
                &auth,
                &audit,
                Permission::$permission,
                Command::$command { id },
            )
            .await
        }
    };
}

async fn group_directory(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: Result<
        Query<rss_mdm_inventory_service::groups::directory::DirectoryQuery>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<Value>, Error> {
    audit.set_action("management_read");
    let Query(q) = query.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    Ok(Json(
        s.planning.group_directory(&auth.proof, &q, &audit).await?,
    ))
}
async fn scope_directory(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: Result<
        Query<rss_mdm_flow_service::planning::directory::ScopeQuery>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<Value>, Error> {
    audit.set_action("management_read");
    let Query(q) = query.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    Ok(Json(
        s.planning.scope_directory(&auth.proof, &q, &audit).await?,
    ))
}
read!(group_read, Uuid, GroupRead, GroupRead);
read!(scope_read, Uuid, ScopeRead, ScopeRead);
async fn group_write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    payload: BodyInput<Operation<GroupChange>>,
) -> std::result::Result<Response, Error> {
    let change = body(payload)?;
    let permission = if matches!(change.input, GroupChange::Recompute {}) {
        Permission::GroupRecompute
    } else {
        Permission::GroupWrite
    };
    run(
        &app,
        &auth,
        &audit,
        permission,
        Command::Group { id, change },
    )
    .await
}
async fn scope_write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    payload: BodyInput<Operation<ScopeChange>>,
) -> std::result::Result<Response, Error> {
    let change = body(payload)?;
    run(
        &app,
        &auth,
        &audit,
        Permission::ScopeWrite,
        Command::Scope { id, change },
    )
    .await
}
async fn group_preview(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    payload: BodyInput<Operation<EmptyInput>>,
) -> std::result::Result<Response, Error> {
    let request = body(payload)?;
    run(
        &app,
        &auth,
        &audit,
        Permission::GroupRead,
        Command::GroupPreview {
            id,
            operation: request.operation_id,
            expected_revision: request.expected_revision,
        },
    )
    .await
}

async fn group_task(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((group, task)): Path<(Uuid, Uuid)>,
) -> std::result::Result<Response, Error> {
    run(
        &app,
        &auth,
        &audit,
        Permission::GroupRead,
        Command::TaskRead {
            id: task,
            target: group.to_string(),
            family: crate::automation::TaskKind::Group,
        },
    )
    .await
}
async fn scope_task(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((scope, task)): Path<(Uuid, Uuid)>,
) -> std::result::Result<Response, Error> {
    run(
        &app,
        &auth,
        &audit,
        Permission::ScopeRead,
        Command::TaskRead {
            id: task,
            target: scope.to_string(),
            family: crate::automation::TaskKind::Scope,
        },
    )
    .await
}

async fn group_page(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((group, result, kind)): Path<(Uuid, Uuid, pages::GroupPageKind)>,
    Query(query): Query<pages::PageQuery>,
) -> std::result::Result<Response, Error> {
    run(
        &app,
        &auth,
        &audit,
        Permission::GroupRead,
        Command::GroupPage {
            group,
            result,
            projection: kind,
            query,
        },
    )
    .await
}

async fn scope_page(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((scope, result, projection)): Path<(Uuid, Uuid, pages::ScopePageKind)>,
    Query(query): Query<pages::PageQuery>,
) -> std::result::Result<Response, Error> {
    run(
        &app,
        &auth,
        &audit,
        Permission::ScopeRead,
        Command::ScopePage {
            scope,
            result,
            projection,
            query,
        },
    )
    .await
}

pub struct HttpState {
    pub planning: std::sync::Arc<crate::planning::Planning>,
}
