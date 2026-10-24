//! ref: axum 0.8.9 axum/src/routing/mod.rs (protected tree composition).
use super::*;
use crate::authorization::{Permission, context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use rss_mdm_inventory_service::groups::{
    Command as GroupCommand, GroupChange, response as group_response,
};
use serde_json::Value;
type BodyInput<T> = std::result::Result<Json<T>, axum::extract::rejection::JsonRejection>;
fn body<T>(value: BodyInput<T>) -> std::result::Result<T, Error> {
    value.map(|v| v.0).map_err(Error::from)
}
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/groups",
            get(group_directory)
                .owned(&contracts::GROUPS, &[RouteOperation::List])
                .queried(rss_mdm_inventory_service::groups::directory::schema()),
        )
        .route(
            "/devices/{device}/groups",
            get(device_groups)
                .owned(&contracts::DEVICES, &[RouteOperation::Action])
                .windowed(&rss_mdm_inventory_service::groups::memberships::SCHEMA),
        )
        .route(
            "/scopes",
            get(scope_directory)
                .owned(&contracts::SCOPES, &[RouteOperation::List])
                .queried(&rss_mdm_flow_service::planning::directory::SCHEMA),
        )
        .route(
            "/groups/{id}",
            get(group_read)
                .owned(&contracts::GROUPS, &[RouteOperation::Get])
                .post(group_write)
                .owned(
                    &contracts::GROUPS,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Delete,
                    ],
                ),
        )
        .route(
            "/groups/{id}/references",
            get(group_references).owned(&contracts::GROUPS, &[RouteOperation::Action]),
        )
        .route(
            "/groups/{id}/previews",
            post(group_preview).owned(&contracts::GROUPS, &[RouteOperation::Action]),
        )
        .route(
            "/groups/{group}/results/{result}/{kind}",
            get(group_page).owned(&contracts::GROUPS, &[RouteOperation::Action]),
        )
        .route(
            "/scopes/{scope}/results/{result}/{kind}",
            get(scope_page).owned(&contracts::SCOPES, &[RouteOperation::Action]),
        )
        .route(
            "/scopes/{id}",
            get(scope_read)
                .owned(&contracts::SCOPES, &[RouteOperation::Get])
                .post(scope_write)
                .owned(
                    &contracts::SCOPES,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Delete,
                    ],
                ),
        )
        .route(
            "/groups/{group}/tasks/{task}",
            get(group_task).owned(&contracts::GROUPS, &[RouteOperation::Action]),
        )
        .route(
            "/scopes/{scope}/tasks/{task}",
            get(scope_task).owned(&contracts::SCOPES, &[RouteOperation::Action]),
        )
}
// Group receipts/read models include derived membership counts. Every result
// projection and task summary uses the full tenant input, so grant changes must
// be checked again even when reading an immutable result with an old cursor.

async fn run(
    app: &HttpState,
    auth: &RequestAuth,
    audit: &RequestAudit,
    permission: Permission,
    command: Command,
) -> std::result::Result<Response, Error> {
    match &command {
        Command::Scope { id, .. } | Command::ScopeRead { id } => audit.resource_target(
            rss_mdm_audit_integration::TargetKind::Scope,
            &id.to_string(),
        ),
        Command::TaskRead { target, .. } => {
            audit.resource_target(rss_mdm_audit_integration::TargetKind::Scope, target)
        }
        Command::ScopePage { scope, .. } => audit.resource_target(
            rss_mdm_audit_integration::TargetKind::Scope,
            &scope.to_string(),
        ),
    }
    audit.set_action(if matches!(command, Command::Scope { .. }) {
        "management_write"
    } else {
        "management_read"
    });
    let (operation, _) = storage::identity(&command, audit).map_err(|_| Error::Malformed)?;
    if let Some(id) = operation {
        audit.operation(id, audit.snapshot().action);
    }
    let authorize = || {
        auth.proof.manage(permission)?;
        if let Command::Scope { change, .. } = &command
            && matches!(&change.input, ScopeChange::Put { definition } if definition.references().iter().any(|r|matches!(r,Reference::Group(_))))
        {
            auth.proof.manage(Permission::GroupRead)?;
        }
        if matches!(
            command,
            Command::ScopePage { .. } | Command::TaskRead { .. }
        ) {
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
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> Result<Json<Value>, Error> {
    audit.set_action("management_read");
    let q = rss_mdm_inventory_service::groups::directory::parse(raw.as_deref().unwrap_or_default())
        .map_err(|_| Error::Malformed)?;
    Ok(Json(s.groups.directory(&auth.proof, &q, &audit).await?))
}
async fn scope_directory(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> Result<Json<Value>, Error> {
    audit.set_action("management_read");
    let q = rss_mdm_flow_service::planning::directory::parse(raw.as_deref().unwrap_or_default())
        .map_err(|_| Error::Malformed)?;
    Ok(Json(
        s.planning.scope_directory(&auth.proof, &q, &audit).await?,
    ))
}
async fn group_read(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Response, Error> {
    run_group(
        &app,
        &auth,
        &audit,
        Permission::GroupRead,
        GroupCommand::GroupRead { id },
    )
    .await
}
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
    run_group(
        &app,
        &auth,
        &audit,
        permission,
        GroupCommand::Group {
            id,
            change: Box::new(rss_mdm_inventory_service::operation::Operation {
                operation_id: change.operation_id,
                expected_revision: change.expected_revision,
                input: change.input,
            }),
            sensitive: assets::ReadScope::from_proof(&auth.proof)?.sensitive,
        },
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
    run_group(
        &app,
        &auth,
        &audit,
        Permission::GroupRead,
        GroupCommand::GroupPreview {
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
    run_group(
        &app,
        &auth,
        &audit,
        Permission::GroupRead,
        GroupCommand::TaskRead {
            id: task,
            target: group.to_string(),
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
    Path((group, result, kind)): Path<(
        Uuid,
        Uuid,
        rss_mdm_inventory_service::groups::pages::GroupPageKind,
    )>,
    Query(query): Query<rss_mdm_inventory_service::groups::pages::PageQuery>,
) -> std::result::Result<Response, Error> {
    run_group(
        &app,
        &auth,
        &audit,
        Permission::GroupRead,
        GroupCommand::GroupPage {
            group,
            result,
            projection: kind,
            query: rss_mdm_inventory_service::groups::pages::PageQuery {
                limit: query.limit,
                cursor: query.cursor,
            },
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
    pub groups: Arc<rss_mdm_inventory_service::groups::Groups>,
}

async fn run_group(
    app: &HttpState,
    auth: &RequestAuth,
    audit: &RequestAudit,
    permission: Permission,
    command: GroupCommand,
) -> Result<Response, Error> {
    match &command {
        GroupCommand::Group { id, change, .. } => {
            audit.resource_target(
                rss_mdm_audit_integration::TargetKind::Group,
                &id.to_string(),
            );
            audit.operation(change.operation_id, "management_write");
        }
        GroupCommand::GroupPreview { id, operation, .. } => {
            audit.resource_target(
                rss_mdm_audit_integration::TargetKind::Group,
                &id.to_string(),
            );
            audit.operation(*operation, "management_read");
        }
        GroupCommand::TaskRead { target, .. } => {
            audit.resource_target(rss_mdm_audit_integration::TargetKind::Group, target)
        }
        GroupCommand::GroupRead { id } => audit.resource_target(
            rss_mdm_audit_integration::TargetKind::Group,
            &id.to_string(),
        ),
        GroupCommand::GroupPage { group, .. } => audit.resource_target(
            rss_mdm_audit_integration::TargetKind::Group,
            &group.to_string(),
        ),
    }
    audit.set_action(if matches!(command, GroupCommand::Group { .. }) {
        "management_write"
    } else {
        "management_read"
    });
    let authorize = || {
        auth.proof.manage(permission)?;
        if let GroupCommand::Group { change, .. } = &command
            && matches!(&change.input,
                GroupChange::Create { criteria: Some(c), .. } | GroupChange::Rule { criteria: c }
                    if c.criteria.references_groups())
        {
            auth.proof.manage(Permission::GroupRead)?;
        }
        assets::ReadScope::from_proof(&auth.proof)?
            .full()
            .map_err(rss_mdm_inventory_service::Error::from)?;
        Ok(())
    };
    let response = group_response::Response::decode(
        app.groups
            .execute(&command, audit, &authorize, app.planning.as_ref())
            .await?,
    )?;
    let status = if matches!(response, group_response::Response::JobAccepted(_)) {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(response)).into_response())
}

async fn device_groups(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> Result<Json<Value>, Error> {
    let (query, _) = rss_mdm_inventory_service::groups::memberships::SCHEMA
        .parse(raw.as_deref().unwrap_or(""))
        .map_err(|_| Error::Malformed)?;
    Ok(Json(
        s.groups
            .memberships(&auth.proof, &device, &query, &audit)
            .await?,
    ))
}

async fn group_references(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    query: Result<
        Query<rss_mdm_inventory_service::groups::references::Query>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<Value>, Error> {
    audit.set_action("management_read");
    let Query(q) = query.map_err(|_| Error::Malformed)?;
    Ok(Json(
        s.groups
            .references(&auth.proof, id, &q, &audit, s.planning.as_ref())
            .await?,
    ))
}
