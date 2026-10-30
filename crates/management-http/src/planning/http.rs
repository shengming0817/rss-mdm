//! ref: axum 0.8.9 axum/src/routing/mod.rs (protected tree composition).
use super::*;
use crate::authorization::{Permission, context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use rss_mdm_inventory_service::groups::{
    Command as GroupCommand, GroupChange, response as group_response,
};
use rss_mdm_scope::Reference;
use rss_mdm_scope_service::ScopeChange;

#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct EmptyInput {}

type BodyInput<T> = std::result::Result<Json<T>, axum::extract::rejection::JsonRejection>;
fn body<T>(value: BodyInput<T>) -> std::result::Result<T, Error> {
    value.map(|v| v.0).map_err(Error::from)
}
pub fn routes() -> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Browser] { get_group_directory, get_device_groups, get_scope_directory, get_group_read, post_group_write, get_group_references, post_group_preview, get_group_page, get_scope_page, get_scope_read, post_scope_write, get_group_task, get_scope_task } }
        RoutesModule1 {
            get_group_directory: rss_mdm_http_contract::module::Route::new(
                "/groups",
                get(group_directory, &contracts::GROUPS, &[RouteOperation::List]),
            ),
            get_device_groups: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/groups",
                get(
                    device_groups,
                    &contracts::DEVICE_GROUPS,
                    &[RouteOperation::List],
                ),
            ),
            get_scope_directory: rss_mdm_http_contract::module::Route::new(
                "/scopes",
                get(scope_directory, &contracts::SCOPES, &[RouteOperation::List]),
            ),
            get_group_read: rss_mdm_http_contract::module::Route::new(
                "/groups/{id}",
                rss_mdm_http_contract::routing::get(
                    group_read,
                    &contracts::GROUPS,
                    &[RouteOperation::Get],
                ),
            ),
            post_group_write: rss_mdm_http_contract::module::Route::new(
                "/groups/{id}",
                rss_mdm_http_contract::routing::post(
                    group_write,
                    &contracts::GROUPS,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Delete,
                    ],
                ),
            ),
            get_group_references: rss_mdm_http_contract::module::Route::new(
                "/groups/{id}/references",
                get(
                    group_references,
                    &contracts::GROUP_REFERENCES,
                    &[RouteOperation::List],
                ),
            ),
            post_group_preview: rss_mdm_http_contract::module::Route::new(
                "/groups/{id}/previews",
                post(group_preview, &contracts::GROUPS, &[RouteOperation::Action]),
            ),
            get_group_page: rss_mdm_http_contract::module::Route::new(
                "/groups/{group}/results/{result}/{kind}",
                get(
                    group_page,
                    &contracts::GROUP_RESULTS,
                    &[RouteOperation::List],
                ),
            ),
            get_scope_page: rss_mdm_http_contract::module::Route::new(
                "/scopes/{scope}/results/{result}/{kind}",
                get(
                    scope_page,
                    &contracts::SCOPE_RESULTS,
                    &[RouteOperation::List],
                ),
            ),
            get_scope_read: rss_mdm_http_contract::module::Route::new(
                "/scopes/{id}",
                rss_mdm_http_contract::routing::get(
                    scope_read,
                    &contracts::SCOPES,
                    &[RouteOperation::Get],
                ),
            ),
            post_scope_write: rss_mdm_http_contract::module::Route::new(
                "/scopes/{id}",
                rss_mdm_http_contract::routing::post(
                    scope_write,
                    &contracts::SCOPES,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Delete,
                    ],
                ),
            ),
            get_group_task: rss_mdm_http_contract::module::Route::new(
                "/groups/{group}/tasks/{task}",
                get(group_task, &contracts::GROUPS, &[RouteOperation::Action]),
            ),
            get_scope_task: rss_mdm_http_contract::module::Route::new(
                "/scopes/{scope}/tasks/{task}",
                get(scope_task, &contracts::SCOPES, &[RouteOperation::Action]),
            ),
        }
        .assemble()
    }
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
) -> std::result::Result<PlanningResponse, Error> {
    match &command {
        Command::Scope { id, .. } | Command::ScopeRead { id } => audit.resource_target(
            rss_mdm_audit_integration::TargetKind::Scope,
            &id.to_string(),
        ),
        Command::TaskRead { target, .. } => {
            audit.resource_target(rss_mdm_audit_integration::TargetKind::Scope, target)
        }
    }
    audit.set_action(
        if matches!(command, Command::Scope { .. }) {
            "management_write"
        } else {
            "management_read"
        },
        if matches!(command, Command::Scope { .. }) {
            rss_mdm_audit_integration::AuditIntent::Management
        } else {
            rss_mdm_audit_integration::AuditIntent::Routine
        },
    );
    let operation = match &command {
        Command::Scope { change, .. } => Some(change.operation_id),
        _ => None,
    };
    if let Some(id) = operation {
        audit.operation(
            id,
            audit.snapshot().action,
            rss_mdm_audit_integration::AuditIntent::Management,
        );
    }
    let authorize = || {
        auth.proof.manage(permission)?;
        if let Command::Scope { change, .. } = &command
            && matches!(&change.input, ScopeChange::Put { definition } if definition.references().iter().any(|r|matches!(r,Reference::Group(_))))
        {
            auth.proof.manage(Permission::GroupRead)?;
        }
        if matches!(command, Command::TaskRead { .. }) {
            assets::ReadScope::from_proof(&auth.proof)?
                .full()
                .map_err(rss_mdm_inventory_service::Error::from)?;
        }
        Ok(())
    };
    authorize()?;
    let response = wire::Response::decode(app.scopes.execute(&command, audit, &authorize).await?)?;
    Ok(PlanningResponse(response))
}
macro_rules! read {
    ($handler:ident,$id:ty,$permission:ident,$command:ident) => {
        async fn $handler(
            State(app): State<Arc<HttpState>>,
            Extension(auth): Extension<RequestAuth>,
            Extension(audit): Extension<RequestAudit>,
            Path(id): Path<$id>,
        ) -> std::result::Result<PlanningResponse, Error> {
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
    query: rss_mdm_http_contract::query::OwnedQuery<GroupDirectoryQuery>,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<
                    rss_mdm_inventory_service::groups::directory::Row,
                >,
            >,
        >,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "management_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let q = query.parse().map_err(|_| Error::Malformed)?;
        Ok(Json(s.groups.directory(&auth.proof, &q, &audit).await?))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn scope_directory(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<ScopeDirectoryQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<rss_mdm_scope_service::directory::Row>,
            >,
        >,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "management_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let q = query.parse().map_err(|_| Error::Malformed)?;
        Ok(Json(
            s.scopes.scope_directory(&auth.proof, &q, &audit).await?,
        ))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn group_read(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<GroupResponse, Error> {
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
    payload: BodyInput<rss_mdm_inventory_service::operation::Operation<GroupChange>>,
) -> std::result::Result<GroupResponse, Error> {
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
            change: Box::new(change),
        },
    )
    .await
}
async fn scope_write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    payload: BodyInput<rss_mdm_scope_service::operation::Operation<ScopeChange>>,
) -> std::result::Result<PlanningResponse, Error> {
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
    payload: BodyInput<PreviewRequest>,
) -> std::result::Result<GroupResponse, Error> {
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
) -> std::result::Result<GroupResponse, Error> {
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
) -> std::result::Result<PlanningResponse, Error> {
    run(
        &app,
        &auth,
        &audit,
        Permission::ScopeRead,
        Command::TaskRead {
            id: task,
            target: scope.to_string(),
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
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<GroupPageQuery>,
    >,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<GroupResponse>, Error> {
    (async {
        let (query, _) = query.parse().map_err(|_| Error::Malformed)?;
        run_group(
            &app,
            &auth,
            &audit,
            Permission::GroupRead,
            GroupCommand::GroupPage {
                group,
                result,
                projection: kind,
                query,
            },
        )
        .await
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

async fn scope_page(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((scope, result, projection)): Path<(Uuid, Uuid, pages::ScopePageKind)>,
    params: rss_mdm_http_contract::query::OwnedQuery<ScopeResultQuery>,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<PlanningResponse>, Error> {
    (async {
        let query = params.parse().map_err(|_| Error::Malformed)?;
        let value = app
            .scopes
            .page(
                &auth.proof,
                &pages::PageRequest {
                    scope,
                    result,
                    projection,
                    query,
                },
                &audit,
            )
            .await?;
        Ok(PlanningResponse(wire::Response::decode(value)?))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

pub struct HttpState {
    pub scopes: std::sync::Arc<rss_mdm_scope_service::Scopes>,
    pub groups: Arc<rss_mdm_inventory_service::groups::Groups>,
}

async fn run_group(
    app: &HttpState,
    auth: &RequestAuth,
    audit: &RequestAudit,
    permission: Permission,
    command: GroupCommand,
) -> Result<GroupResponse, Error> {
    match &command {
        GroupCommand::Group { id, change, .. } => {
            audit.resource_target(
                rss_mdm_audit_integration::TargetKind::Group,
                &id.to_string(),
            );
            audit.operation(
                change.operation_id,
                "management_write",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
        }
        GroupCommand::GroupPreview { id, operation, .. } => {
            audit.resource_target(
                rss_mdm_audit_integration::TargetKind::Group,
                &id.to_string(),
            );
            audit.operation(
                *operation,
                "management_read",
                rss_mdm_audit_integration::AuditIntent::Routine,
            );
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
    audit.set_action(
        if matches!(command, GroupCommand::Group { .. }) {
            "management_write"
        } else {
            "management_read"
        },
        if matches!(command, GroupCommand::Group { .. }) {
            rss_mdm_audit_integration::AuditIntent::Management
        } else {
            rss_mdm_audit_integration::AuditIntent::Routine
        },
    );
    auth.proof.manage(permission)?;
    let response =
        group_response::Response::decode(app.groups.execute(&command, audit, &auth.proof).await?)?;
    Ok(GroupResponse(response))
}

async fn device_groups(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<DeviceGroupsQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_inventory_service::groups::memberships::Memberships>,
    >,
    Error,
> {
    (async {
        let (query, _) = query.parse().map_err(|_| Error::Malformed)?;
        Ok(Json(
            s.groups
                .memberships(&auth.proof, &device, &query, &audit)
                .await?,
        ))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

async fn group_references(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    params: rss_mdm_http_contract::query::OwnedQuery<GroupReferencesQuery>,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_inventory_service::groups::references::References>,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "management_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let q = params.parse()?;
        Ok(Json(
            s.groups.references(&auth.proof, id, &q, &audit).await?,
        ))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

struct GroupPageQuery;
impl rss_mdm_http_contract::query::WindowOwner for GroupPageQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_inventory_service::groups::pages::SCHEMA
    }
}

struct DeviceGroupsQuery;
impl rss_mdm_http_contract::query::WindowOwner for DeviceGroupsQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_inventory_service::groups::memberships::SCHEMA
    }
}

macro_rules! typed_response {
    ($name:ident, $owner:ident) => {
        struct $name($owner::Response);
        impl IntoResponse for $name {
            fn into_response(self) -> axum::response::Response {
                let status = if matches!(&self.0, $owner::Response::JobAccepted(_)) {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::OK
                };
                (status, Json(self.0)).into_response()
            }
        }
        impl rss_mdm_http_contract::signature::Output for $name {
            fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
                planning_responses::<$owner::Response>()
            }
        }
    };
}
typed_response!(PlanningResponse, wire);
typed_response!(GroupResponse, group_response);
fn planning_responses<T: schemars::JsonSchema>() -> Vec<rss_mdm_http_contract::signature::Response>
{
    use schemars::JsonSchema;
    let accepted = format!(
        "#/$defs/{}",
        rss_mdm_inventory_service::tasks::JobAccepted::schema_name()
    );
    [StatusCode::OK, StatusCode::ACCEPTED]
        .into_iter()
        .map(|status| {
            let mut response =
                rss_mdm_http_contract::signature::Response::json::<T>(status.as_u16());
            let schema = &mut response.body.as_mut().expect("planning JSON").schema.value;
            let variants = schema["anyOf"]
                .as_array_mut()
                .expect("actual untagged planning response");
            assert!(
                variants.iter().any(|v| v["$ref"] == accepted),
                "missing accepted response variant"
            );
            variants.retain(|v| (v["$ref"] == accepted) == (status == StatusCode::ACCEPTED));
            response
        })
        .collect()
}

struct GroupDirectoryQuery;
impl rss_mdm_http_contract::query::QueryOwner for GroupDirectoryQuery {
    type Parsed = rss_mdm_inventory_service::groups::directory::DirectoryQuery;
    type Error = rss_mdm_query::Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Directory(
            rss_mdm_inventory_service::groups::directory::schema(),
        ))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let owner = rss_mdm_inventory_service::groups::directory::schema();
        let mut schema = rss_mdm_http_contract::query::directory_parameters(
            owner.default_limit,
            owner.max_limit,
        );
        schema.value["properties"]["referenceableFor"] = serde_json::json!({"type":"string","format":"uuid","not":{"const":"00000000-0000-0000-0000-000000000000"}});
        schema
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        rss_mdm_inventory_service::groups::directory::parse(raw)
    }
}

struct ScopeDirectoryQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for ScopeDirectoryQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_scope_service::directory::SCHEMA
    }
    fn parse(raw: &str) -> rss_mdm_query::Result<rss_mdm_query::directory::Query> {
        rss_mdm_scope_service::directory::parse(raw)
    }
}

struct ScopeResultQuery;
impl rss_mdm_http_contract::query::QueryOwner for ScopeResultQuery {
    type Parsed = pages::ResultQuery;
    type Error = crate::Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Window(
            &pages::SCHEMA,
        ))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let mut schema = rss_mdm_http_contract::query::window_parameters(&pages::SCHEMA);
        schema.value["properties"]["channel"] =
            rss_mdm_http_contract::signature::Schema::request::<rss_mdm_inventory::Channel>().value;
        schema.value["required"] = serde_json::json!(["channel"]);
        schema
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        pages::ResultQuery::parse(raw).map_err(|_| Error::Malformed)
    }
}

struct GroupReferencesQuery;
impl rss_mdm_http_contract::query::QueryOwner for GroupReferencesQuery {
    type Parsed = rss_mdm_inventory_service::groups::references::Query;
    type Error = rss_mdm_inventory_service::Error;
    fn declaration() -> Option<rss_mdm_http_contract::QueryDeclaration> {
        Some(rss_mdm_http_contract::QueryDeclaration::Window(
            &rss_mdm_inventory_service::groups::references::SCHEMA,
        ))
    }
    fn parameters() -> rss_mdm_http_contract::signature::Schema {
        let mut schema = rss_mdm_http_contract::query::window_parameters(
            &rss_mdm_inventory_service::groups::references::SCHEMA,
        );
        schema.value["properties"]["kind"] = rss_mdm_http_contract::signature::Schema::request::<
            rss_mdm_inventory_service::groups::references::Kind,
        >()
        .value;
        schema.value["properties"]["relation"] =
            serde_json::json!({"type":"string","enum":["all","direct","indirect"],"default":"all"});
        schema
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        rss_mdm_inventory_service::groups::references::Query::parse(raw)
    }
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreviewRequest {
    operation_id: Uuid,
    expected_revision: u64,
    #[serde(rename = "input")]
    _input: EmptyInput,
}
