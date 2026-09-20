//! ref: axum 0.8.9 axum/src/routing/mod.rs (protected tree composition).
use super::*;
use crate::api::{App, RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
pub(crate) fn routes() -> Router<Arc<App>> {
    Router::new()
        .merge(publications::routes())
        .route("/resources/{id}", get(resource_read).post(resource_write))
        .route("/groups/{id}", get(group_read).post(group_write))
        .route("/groups/{id}/preview", get(group_preview))
        .route("/scopes/{id}", get(scope_read).post(scope_write))
        .route("/policies/{id}", get(policy_read).post(policy_write))
        .route("/policies/{id}/previews", post(preview))
        .route("/policies/{id}/plans", post(save))
        .route("/plan-previews/{id}", get(plan_read))
}
async fn run(
    app: &App,
    auth: &RequestAuth,
    audit: &Audit,
    permission: Permission,
    command: Command,
) -> std::result::Result<Json<wire::Response>, Error> {
    match &command {
        Command::Group { id, .. }
        | Command::GroupRead { id }
        | Command::GroupPreview { id, .. }
        | Command::Scope { id, .. }
        | Command::ScopeRead { id }
        | Command::PlanRead { id } => audit.target(&id.to_string()),
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
        Command::GroupRead { .. }
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
    auth.proof.manage(permission)?;
    wire::Response::decode(app.management.execute(&command, audit).await?).map(Json)
}
macro_rules! read {
    ($handler:ident,$id:ty,$permission:ident,$command:ident) => {
        async fn $handler(
            State(app): State<Arc<App>>,
            Extension(auth): Extension<RequestAuth>,
            Extension(audit): Extension<Audit>,
            Path(id): Path<$id>,
        ) -> std::result::Result<Json<wire::Response>, Error> {
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
    Json(change): Json<Operation<GroupChange>>,
) -> std::result::Result<Json<wire::Response>, Error> {
    let permission = if matches!(change.input, GroupChange::Recompute { .. }) {
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
    Json(change): Json<Operation<ScopeChange>>,
) -> std::result::Result<Json<wire::Response>, Error> {
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
    Json(change): Json<Operation<PolicyChange>>,
) -> std::result::Result<Json<wire::Response>, Error> {
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
    Json(request): Json<Operation<PreviewInput>>,
) -> std::result::Result<Json<wire::Response>, Error> {
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
    Json(request): Json<Operation<SavePlan>>,
) -> std::result::Result<Json<wire::Response>, Error> {
    run(
        &app,
        &auth,
        &audit,
        Permission::PlanSave,
        Command::Save { id, request },
    )
    .await
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Revision {
    expected_revision: u64,
}
async fn group_preview(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<Uuid>,
    Query(revision): Query<Revision>,
) -> std::result::Result<Json<wire::Response>, Error> {
    run(
        &app,
        &auth,
        &audit,
        Permission::GroupRead,
        Command::GroupPreview {
            id,
            expected_revision: revision.expected_revision,
        },
    )
    .await
}

async fn resource_write(
    State(app): State<Arc<App>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<Audit>,
    Path(id): Path<String>,
    Json(change): Json<Operation<resources::Change>>,
) -> std::result::Result<Json<wire::Response>, Error> {
    run(
        &app,
        &auth,
        &audit,
        Permission::ResourceWrite,
        Command::Resource { id, change },
    )
    .await
}
