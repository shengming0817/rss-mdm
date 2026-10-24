use super::*;
use crate::authorization::Permission;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json,
    extract::{Path, Query as Params, State},
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response as HttpResponse},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post, put},
};
use serde::Deserialize;
type BodyInput<T> = std::result::Result<Json<T>, axum::extract::rejection::JsonRejection>;
type ParamInput<T> = std::result::Result<Params<T>, axum::extract::rejection::QueryRejection>;
fn body<T>(v: BodyInput<T>) -> std::result::Result<T, Error> {
    v.map(|v| v.0).map_err(Error::from)
}
fn params<T>(v: ParamInput<T>) -> std::result::Result<T, Error> {
    v.map(|v| v.0).map_err(|_| Error::Malformed)
}

pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/asset-fields",
            get(fields).owned(&contracts::ASSET_FIELDS, &[RouteOperation::List]),
        )
        .route(
            "/asset-field-layout",
            get(field_layout)
                .owned(&contracts::ASSET_LAYOUT, &[RouteOperation::Get])
                .put(field_layout_write)
                .owned(&contracts::ASSET_LAYOUT, &[RouteOperation::Update]),
        )
        .route(
            "/devices/{id}/collections/{run}/fields/{field}/items",
            get(collection_items).owned(&contracts::DEVICES, &[RouteOperation::Action]),
        )
        .route(
            "/asset-fields/{field}",
            put(field_write).owned(
                &contracts::ASSET_FIELDS,
                &[
                    RouteOperation::Create,
                    RouteOperation::Update,
                    RouteOperation::Delete,
                ],
            ),
        )
        .route(
            "/asset-retention-policies",
            post(retention_write).owned(&contracts::ASSET_RETENTION, &[RouteOperation::Create]),
        )
        .route(
            "/asset-retention-policies/{key}/{revision}",
            get(retention_read).owned(&contracts::ASSET_RETENTION, &[RouteOperation::Get]),
        )
        .route(
            "/asset-fields/{field}/references",
            get(field_references).owned(&contracts::ASSET_FIELDS, &[RouteOperation::Action]),
        )
        .route(
            "/device-queries",
            post(search).owned(&contracts::ASSET_QUERIES, &[RouteOperation::Create]),
        )
        .route(
            "/device-queries/{id}",
            get(query_status).owned(&contracts::ASSET_QUERIES, &[RouteOperation::Get]),
        )
        .route(
            "/device-queries/{id}/items",
            get(query_items).owned(&contracts::ASSET_RESULTS, &[RouteOperation::List]),
        )
        .route(
            "/device-queries/{id}/facets/{facet}",
            get(query_facets).owned(&contracts::ASSET_QUERIES, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{id}/inventory",
            get(detail).owned(&contracts::DEVICES, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{id}/inventory-scopes",
            get(inventory_scopes).owned(&contracts::DEVICES, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{id}/collections/{run}",
            get(collection_run).owned(&contracts::DEVICES, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{id}/inventory-lists/{field}",
            get(list_items).owned(&contracts::DEVICES, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{id}/manual-fields/{field}",
            put(manual).owned(&contracts::DEVICES, &[RouteOperation::Action]),
        )
        .route(
            "/saved-queries",
            get(saved_list)
                .owned(&contracts::SAVED_QUERIES, &[RouteOperation::List])
                .queried(&rss_mdm_inventory_service::assets::saved_directory::SCHEMA),
        )
        .route(
            "/saved-queries/{id}",
            get(saved_read)
                .owned(&contracts::SAVED_QUERIES, &[RouteOperation::Get])
                .put(saved_write)
                .owned(
                    &contracts::SAVED_QUERIES,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Delete,
                    ],
                ),
        )
        .route(
            "/saved-queries/{id}/execute",
            post(saved_execute).owned(&contracts::SAVED_QUERIES, &[RouteOperation::Action]),
        )
}
fn owner(auth: &RequestAuth) -> Owner {
    Owner {
        instance: auth.proof.instance_id().into(),
        principal: auth.proof.principal_id().into(),
    }
}
fn authorize(
    auth: &RequestAuth,
    command: &Command,
) -> std::result::Result<(), rss_mdm_inventory_service::Error> {
    match command {
        Command::Fields => field_access(auth).map(|_| ()),
        Command::FieldLayoutRead { access } => {
            if &field_access(auth)? == access {
                Ok(())
            } else {
                Err(rss_mdm_inventory_service::Error::Forbidden)
            }
        }
        Command::FieldLayoutWrite { .. }
        | Command::FieldWrite { .. }
        | Command::FieldReferences { .. }
        | Command::RetentionWrite { .. }
        | Command::RetentionRead { .. } => auth
            .proof
            .manage(Permission::InventoryFieldsWrite)
            .map_err(rss_mdm_inventory_service::Error::from),
        Command::Manual { device, .. } => auth
            .proof
            .require(Permission::InventoryAssign, Some(device))
            .map_err(rss_mdm_inventory_service::Error::from),
        Command::Detail { device, .. }
        | Command::InventoryScopes { device, .. }
        | Command::CollectionRun { device, .. }
        | Command::CollectionItems { device, .. }
        | Command::ListItems { device, .. } => auth
            .proof
            .require(Permission::InventoryRead, Some(device))
            .map_err(rss_mdm_inventory_service::Error::from),
        Command::QueryStatus { scope, .. }
        | Command::QueryItems { scope, .. }
        | Command::QueryFacets { scope, .. }
        | Command::Search { scope, .. }
        | Command::SavedExecute { scope, .. } => {
            if &ReadScope::from_proof(&auth.proof)? == scope {
                Ok(())
            } else {
                Err(rss_mdm_inventory_service::Error::Forbidden)
            }
        }
        _ => ReadScope::from_proof(&auth.proof).map(|_| ()),
    }
}
async fn run(
    app: &HttpState,
    auth: &RequestAuth,
    audit: &RequestAudit,
    command: Command,
) -> std::result::Result<HttpResponse, Error> {
    audit.set_action(if command.operation().is_some() {
        "management_write"
    } else {
        "inventory_read"
    });
    match &command {
        Command::FieldLayoutRead { .. } | Command::FieldLayoutWrite { .. } => {
            audit.target("asset-field-layout")
        }
        Command::RetentionWrite { change } => audit.target(&change.input.key),
        Command::RetentionRead { key, .. } => audit.target(key),
        Command::Manual { device, .. } => audit.target_device(device),
        Command::Detail { device, .. }
        | Command::InventoryScopes { device, .. }
        | Command::CollectionRun { device, .. }
        | Command::CollectionItems { device, .. }
        | Command::ListItems { device, .. } => audit.target_device(device),
        Command::FieldWrite { field, .. } | Command::FieldReferences { field } => {
            audit.target(field.as_str())
        }
        Command::QueryStatus { task, .. }
        | Command::QueryItems { task, .. }
        | Command::QueryFacets { task, .. } => audit.target(&task.to_string()),
        Command::SavedRead { id, .. }
        | Command::SavedWrite { id, .. }
        | Command::SavedExecute { id, .. } => audit.target(&id.to_string()),
        _ => {}
    }
    if let Some(id) = command.operation() {
        audit.operation(id, audit.snapshot().action);
    }
    authorize(auth, &command)?;
    let value = app
        .assets
        .execute(&command, audit, &|| authorize(auth, &command))
        .await?;
    let envelope: AssetEnvelope =
        serde_json::from_value(value).map_err(|_| Error::Unavailable(Failure::AssetsStorage))?;
    let status = if matches!(&envelope.asset, Response::Accepted { .. }) {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(envelope)).into_response())
}
fn field_access(
    auth: &RequestAuth,
) -> std::result::Result<FieldLayoutAccess, rss_mdm_inventory_service::Error> {
    use rss_mdm_authorization_service::error::AuthorizationError;
    match auth
        .proof
        .authorization()?
        .require(&auth.proof, Permission::InventoryFieldsWrite, None)
    {
        Ok(()) => Ok(FieldLayoutAccess::Edit),
        Err(AuthorizationError::Forbidden) => Ok(FieldLayoutAccess::Read {
            scope: ReadScope::from_proof(&auth.proof)?,
        }),
        Err(error) => Err(error.into()),
    }
}
async fn field_layout(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> std::result::Result<HttpResponse, Error> {
    let access = field_access(&auth)?;
    run(&app, &auth, &audit, Command::FieldLayoutRead { access }).await
}
async fn field_layout_write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    payload: BodyInput<Operation<FieldLayout>>,
) -> std::result::Result<HttpResponse, Error> {
    run(
        &app,
        &auth,
        &audit,
        Command::FieldLayoutWrite {
            change: body(payload)?,
        },
    )
    .await
}
async fn fields(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> std::result::Result<HttpResponse, Error> {
    run(&app, &auth, &audit, Command::Fields).await
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Page {
    cursor: Option<String>,
    limit: Option<usize>,
}
async fn search(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    payload: BodyInput<Operation<Query>>,
) -> std::result::Result<HttpResponse, Error> {
    let request = body(payload)?;
    let scope = ReadScope::from_proof(&auth.proof)?;
    run(
        &app,
        &auth,
        &audit,
        Command::Search {
            request: Box::new(request),
            scope,
        },
    )
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
async fn detail(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    parameters: ParamInput<CollectionSelector>,
) -> std::result::Result<HttpResponse, Error> {
    let selector = params(parameters)?;
    let scope = read_scope(&auth, selector.scope)?;
    run(&app, &auth, &audit, Command::Detail { device, scope }).await
}
async fn manual(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, key)): Path<(String, String)>,
    payload: BodyInput<Operation<ManualChange>>,
) -> std::result::Result<HttpResponse, Error> {
    let change = body(payload)?;
    let field = FieldKey::parse(&key).map_err(|_| Error::Malformed)?;
    run(
        &app,
        &auth,
        &audit,
        Command::Manual {
            device,
            field,
            change,
            owner: owner(&auth),
        },
    )
    .await
}
async fn saved_list(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> std::result::Result<HttpResponse, Error> {
    let q = saved_directory::SCHEMA
        .parse(raw.as_deref().unwrap_or_default())
        .map_err(|_| Error::Malformed)?;
    Ok(Json(app.assets.saved_directory(&auth.proof, &q, &audit).await?).into_response())
}
async fn saved_read(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> std::result::Result<HttpResponse, Error> {
    run(
        &app,
        &auth,
        &audit,
        Command::SavedRead {
            owner: owner(&auth),
            id,
        },
    )
    .await
}
async fn saved_write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    payload: BodyInput<Operation<SavedChange>>,
) -> std::result::Result<HttpResponse, Error> {
    let change = body(payload)?;
    run(
        &app,
        &auth,
        &audit,
        Command::SavedWrite {
            owner: owner(&auth),
            id,
            change,
        },
    )
    .await
}
async fn saved_execute(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    payload: BodyInput<Operation<Empty>>,
) -> std::result::Result<HttpResponse, Error> {
    let request = body(payload)?;
    run(
        &app,
        &auth,
        &audit,
        Command::SavedExecute {
            operation: request.operation_id,
            expected_revision: request.expected_revision,
            owner: owner(&auth),
            id,
            scope: ReadScope::from_proof(&auth.proof)?,
        },
    )
    .await
}

async fn query_status(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(task): Path<Uuid>,
) -> std::result::Result<HttpResponse, Error> {
    run(
        &app,
        &auth,
        &audit,
        Command::QueryStatus {
            task,
            scope: ReadScope::from_proof(&auth.proof)?,
        },
    )
    .await
}
async fn query_items(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(task): Path<Uuid>,
    parameters: ParamInput<Page>,
) -> std::result::Result<HttpResponse, Error> {
    let page = params(parameters)?;
    run(
        &app,
        &auth,
        &audit,
        Command::QueryItems {
            task,
            scope: ReadScope::from_proof(&auth.proof)?,
            limit: page.limit.unwrap_or(1000),
            cursor: page.cursor,
        },
    )
    .await
}
async fn query_facets(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((task, facet)): Path<(Uuid, Facet)>,
    parameters: ParamInput<Page>,
) -> std::result::Result<HttpResponse, Error> {
    let page = params(parameters)?;
    run(
        &app,
        &auth,
        &audit,
        Command::QueryFacets {
            task,
            facet,
            scope: ReadScope::from_proof(&auth.proof)?,
            limit: page.limit.unwrap_or(1000),
            cursor: page.cursor,
        },
    )
    .await
}

pub struct HttpState {
    pub assets: std::sync::Arc<super::AssetService>,
}

async fn field_write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(key): Path<String>,
    payload: BodyInput<Operation<FieldChange>>,
) -> std::result::Result<HttpResponse, Error> {
    let field = FieldKey::parse(&key).map_err(|_| Error::Malformed)?;
    run(
        &app,
        &auth,
        &audit,
        Command::FieldWrite {
            field,
            change: body(payload)?,
        },
    )
    .await
}
async fn field_references(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(key): Path<String>,
) -> std::result::Result<HttpResponse, Error> {
    let field = FieldKey::parse(&key).map_err(|_| Error::Malformed)?;
    run(&app, &auth, &audit, Command::FieldReferences { field }).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CollectionSelector {
    scope: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopePage {
    cursor: Option<String>,
    limit: Option<usize>,
}
async fn inventory_scopes(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    parameters: ParamInput<ScopePage>,
) -> std::result::Result<HttpResponse, Error> {
    let page = params(parameters)?;
    run(
        &app,
        &auth,
        &audit,
        Command::InventoryScopes {
            device,
            scope: ReadScope::from_proof(&auth.proof)?,
            limit: page.limit.unwrap_or(50),
            cursor: page.cursor,
        },
    )
    .await
}
fn read_scope(auth: &RequestAuth, scope: Option<String>) -> std::result::Result<ReadScope, Error> {
    let mut read = ReadScope::from_proof(&auth.proof)?;
    if let Some(scope) = scope {
        read.collection_scope = serde_json::from_str(&scope).map_err(|_| Error::Malformed)?;
        read.collection_scope
            .validate_executable()
            .map_err(|_| Error::Malformed)?;
    }
    Ok(read)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListPage {
    scope: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}
async fn collection_run(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
    parameters: ParamInput<CollectionSelector>,
) -> std::result::Result<HttpResponse, Error> {
    let selector = params(parameters)?;
    let scope = read_scope(&auth, selector.scope)?;
    run(
        &app,
        &auth,
        &audit,
        Command::CollectionRun {
            device,
            run: id,
            scope,
        },
    )
    .await
}

async fn list_items(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, key)): Path<(String, String)>,
    parameters: ParamInput<ListPage>,
) -> std::result::Result<HttpResponse, Error> {
    let page = params(parameters)?;
    let field = FieldKey::parse(&key).map_err(|_| Error::Malformed)?;
    let scope = read_scope(&auth, page.scope)?;
    run(
        &app,
        &auth,
        &audit,
        Command::ListItems {
            device,
            field,
            scope,
            limit: page.limit.unwrap_or(50),
            cursor: page.cursor,
        },
    )
    .await
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ItemPage {
    scope: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
}
async fn collection_items(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id, key)): Path<(String, Uuid, String)>,
    parameters: ParamInput<ItemPage>,
) -> std::result::Result<HttpResponse, Error> {
    let page = params(parameters)?;
    let field = FieldKey::parse(&key).map_err(|_| Error::Malformed)?;
    let scope = read_scope(&auth, page.scope)?;
    run(
        &app,
        &auth,
        &audit,
        Command::CollectionItems {
            device,
            run: id,
            field,
            scope,
            offset: page.offset.unwrap_or(0),
            limit: page.limit.unwrap_or(100),
        },
    )
    .await
}

async fn retention_write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    payload: BodyInput<Operation<rss_mdm_inventory::RetentionPolicy>>,
) -> std::result::Result<HttpResponse, Error> {
    run(
        &app,
        &auth,
        &audit,
        Command::RetentionWrite {
            change: body(payload)?,
        },
    )
    .await
}
async fn retention_read(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((key, revision)): Path<(String, u64)>,
) -> std::result::Result<HttpResponse, Error> {
    run(
        &app,
        &auth,
        &audit,
        Command::RetentionRead { key, revision },
    )
    .await
}
