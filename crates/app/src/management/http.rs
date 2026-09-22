//! ref: axum 0.8.9 axum/src/routing/mod.rs (protected tree composition).
use super::*;
use crate::api::{App, RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
type BodyInput<T> = std::result::Result<Json<T>, axum::extract::rejection::JsonRejection>;
fn body<T>(value: BodyInput<T>) -> std::result::Result<T, Error> {
    value.map(|v| v.0).map_err(|_| Error::Malformed)
}
pub(crate) fn routes() -> Router<Arc<App>> {
    Router::new()
        .merge(publications::routes())
        .route("/resources/{id}", get(resource_read).post(resource_write))
}
pub(crate) fn routes_v2() -> Router<Arc<App>> {
    Router::new()
        .merge(assets::routes())
        .route("/groups/{id}", get(group_read).post(group_write))
        .route("/groups/{id}/previews", post(group_preview))
        .route("/groups/{group}/results/{result}/{kind}", get(group_page))
        .route("/scopes/{scope}/results/{result}/{kind}", get(scope_page))
        .route(
            "/policies/{policy}/results/{result}/{kind}",
            get(policy_page),
        )
        .route("/scopes/{id}", get(scope_read).post(scope_write))
        .route("/policies/{id}", get(policy_read).post(policy_write))
        .route("/policies/{id}/previews", post(preview))
        .route("/policies/{id}/plans", post(save))
        .route("/plan-previews/{id}", get(plan_read))
        .route("/groups/{group}/tasks/{task}", get(group_task))
        .route("/scopes/{scope}/tasks/{task}", get(scope_task))
}
async fn run(
    app: &App,
    auth: &RequestAuth,
    audit: &Audit,
    permission: Permission,
    command: Command,
) -> std::result::Result<Response, Error> {
    if matches!(
        &command,
        Command::GroupPreview { .. }
            | Command::Group {
                change: Operation {
                    input: GroupChange::Recompute {},
                    ..
                },
                ..
            }
    ) {
        assets::ReadScope::from_proof(&auth.proof)?.full()?;
    }
    match &command {
        Command::Asset { .. } => return Err(Error::Malformed),
        Command::Group { id, .. }
        | Command::GroupRead { id }
        | Command::GroupPreview { id, .. }
        | Command::Scope { id, .. }
        | Command::ScopeRead { id }
        | Command::PlanRead { id } => audit.target(&id.to_string()),
        Command::TaskRead { id, .. } => audit.target(&id.to_string()),
        Command::GroupPage { group, .. } => audit.target(&group.to_string()),
        Command::ScopePage { scope, .. } => audit.target(&scope.to_string()),
        Command::PolicyPage { policy, .. } => audit.target(policy),
        Command::Policy { id, .. }
        | Command::PolicyRead { id }
        | Command::Preview { id, .. }
        | Command::Save { id, .. }
        | Command::Resource { id, .. }
        | Command::ResourceRead { id }
        | Command::PublicationIntent { id, .. } => audit.target(id),
    }

    audit.set_action(match command {
        Command::Preview { .. } => "plan_preview",
        Command::Save { .. } => "plan_save",
        Command::ScopePage { .. }
        | Command::PolicyPage { .. }
        | Command::GroupPage { .. }
        | Command::TaskRead { .. }
        | Command::GroupRead { .. }
        | Command::ScopeRead { .. }
        | Command::PolicyRead { .. }
        | Command::PlanRead { .. }
        | Command::GroupPreview { .. }
        | Command::ResourceRead { .. } => "management_read",
        _ => "management_write",
    });
    let (operation, _) = storage::identity(&command, audit).map_err(|_| Error::Malformed)?;
    if let Some(id) = operation {
        audit.operation(id, audit.snapshot().action);
    }
    let authorize = || {
        auth.proof.manage(permission)?;
        if matches!(
            &command,
            Command::GroupPreview { .. }
                | Command::Group {
                    change: Operation {
                        input: GroupChange::Recompute {},
                        ..
                    },
                    ..
                }
        ) {
            assets::ReadScope::from_proof(&auth.proof)?.full()?;
        }
        Ok(())
    };
    authorize()?;
    let response =
        wire::Response::decode(app.management.execute(&command, audit, &authorize).await?)?;
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
            State(app): State<Arc<App>>,
            Extension(auth): Extension<RequestAuth>,
            Extension(audit): Extension<Audit>,
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
read!(resource_read, String, ResourceRead, ResourceRead);
read!(group_read, Uuid, GroupRead, GroupRead);
read!(scope_read, Uuid, ScopeRead, ScopeRead);
read!(policy_read, String, PolicyRead, PolicyRead);
read!(plan_read, Uuid, PolicyRead, PlanRead);
async fn group_write(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
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
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
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
async fn policy_write(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<String>,
    payload: BodyInput<Operation<PolicyChange>>,
) -> std::result::Result<Response, Error> {
    let change = body(payload)?;
    run(
        &app,
        &auth,
        &audit,
        Permission::PolicyWrite,
        Command::Policy { id, change },
    )
    .await
}
async fn preview(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<String>,
    payload: BodyInput<Operation<PreviewInput>>,
) -> std::result::Result<Response, Error> {
    let request = body(payload)?;
    if request.expected_revision != request.input.expected_revision {
        return Err(Error::Malformed);
    }
    run(
        &app,
        &auth,
        &audit,
        Permission::PlanPreview,
        Command::Preview { id, request },
    )
    .await
}
async fn save(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<String>,
    payload: BodyInput<Operation<SavePlan>>,
) -> std::result::Result<Response, Error> {
    let request = body(payload)?;
    run(
        &app,
        &auth,
        &audit,
        Permission::PlanSave,
        Command::Save { id, request },
    )
    .await
}
async fn group_preview(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
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

async fn resource_write(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<String>,
    payload: BodyInput<Operation<resources::Change>>,
) -> std::result::Result<Response, Error> {
    let change = body(payload)?;
    run(
        &app,
        &auth,
        &audit,
        Permission::ResourceWrite,
        Command::Resource { id, change },
    )
    .await
}

async fn group_task(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
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
            family: automation::TaskKind::Group,
        },
    )
    .await
}
async fn scope_task(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
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
            family: automation::TaskKind::Scope,
        },
    )
    .await
}

async fn group_page(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
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
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
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
async fn policy_page(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path((policy, result, projection)): Path<(String, Uuid, pages::PolicyPageKind)>,
    Query(query): Query<pages::PageQuery>,
) -> std::result::Result<Response, Error> {
    run(
        &app,
        &auth,
        &audit,
        Permission::PolicyRead,
        Command::PolicyPage {
            policy,
            result,
            projection,
            query,
        },
    )
    .await
}
