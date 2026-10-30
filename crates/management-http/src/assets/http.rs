use super::*;
use crate::authorization::Permission;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json,
    extract::{Path, Query as Params, State},
};
use axum::{http::StatusCode, response::IntoResponse};
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

pub fn routes() -> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Browser] { get_fields, get_field_layout, put_field_layout_write, get_collection_items, get_field_read, put_field_write, post_retention_write, get_retention_read, get_field_references, post_search, get_query_status, get_query_items, get_query_facets, get_detail, post_inventory_scopes, get_collection_run, post_list_items, put_manual, get_saved_list, get_saved_read, put_saved_write, post_saved_execute } }
        RoutesModule1 {
            get_fields: rss_mdm_http_contract::module::Route::new(
                "/asset-fields",
                get(fields, &contracts::ASSET_FIELDS, &[RouteOperation::List]),
            ),
            get_field_layout: rss_mdm_http_contract::module::Route::new(
                "/asset-field-layout",
                rss_mdm_http_contract::routing::get(
                    field_layout,
                    &contracts::ASSET_LAYOUT,
                    &[RouteOperation::Get],
                ),
            ),
            put_field_layout_write: rss_mdm_http_contract::module::Route::new(
                "/asset-field-layout",
                rss_mdm_http_contract::routing::put(
                    field_layout_write,
                    &contracts::ASSET_LAYOUT,
                    &[RouteOperation::Update],
                ),
            ),
            get_collection_items: rss_mdm_http_contract::module::Route::new(
                "/devices/{id}/collections/{run}/fields/{field}/items",
                get(
                    collection_items,
                    &contracts::COLLECTION_ITEMS,
                    &[RouteOperation::List],
                ),
            ),
            get_field_read: rss_mdm_http_contract::module::Route::new(
                "/asset-fields/{field}",
                rss_mdm_http_contract::routing::get(
                    field_read,
                    &contracts::ASSET_FIELDS,
                    &[RouteOperation::Get],
                ),
            ),
            put_field_write: rss_mdm_http_contract::module::Route::new(
                "/asset-fields/{field}",
                rss_mdm_http_contract::routing::put(
                    field_write,
                    &contracts::ASSET_FIELDS,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Delete,
                    ],
                ),
            ),
            post_retention_write: rss_mdm_http_contract::module::Route::new(
                "/asset-retention-policies",
                post(
                    retention_write,
                    &contracts::ASSET_RETENTION,
                    &[RouteOperation::Create],
                ),
            ),
            get_retention_read: rss_mdm_http_contract::module::Route::new(
                "/asset-retention-policies/{key}/{revision}",
                get(
                    retention_read,
                    &contracts::ASSET_RETENTION,
                    &[RouteOperation::Get],
                ),
            ),
            get_field_references: rss_mdm_http_contract::module::Route::new(
                "/asset-fields/{field}/references",
                get(
                    field_references,
                    &contracts::FIELD_REFERENCES,
                    &[RouteOperation::List],
                ),
            ),
            post_search: rss_mdm_http_contract::module::Route::new(
                "/device-queries",
                post(search, &contracts::ASSET_QUERIES, &[RouteOperation::Create]),
            ),
            get_query_status: rss_mdm_http_contract::module::Route::new(
                "/device-queries/{id}",
                get(
                    query_status,
                    &contracts::ASSET_QUERIES,
                    &[RouteOperation::Get],
                ),
            ),
            get_query_items: rss_mdm_http_contract::module::Route::new(
                "/device-queries/{id}/items",
                get(
                    query_items,
                    &contracts::ASSET_RESULTS,
                    &[RouteOperation::List],
                ),
            ),
            get_query_facets: rss_mdm_http_contract::module::Route::new(
                "/device-queries/{id}/facets/{facet}",
                get(
                    query_facets,
                    &contracts::ASSET_FACETS,
                    &[RouteOperation::List],
                ),
            ),
            get_detail: rss_mdm_http_contract::module::Route::new(
                "/devices/{id}/inventory",
                get(detail, &contracts::DEVICES, &[RouteOperation::Action]),
            ),
            post_inventory_scopes: rss_mdm_http_contract::module::Route::new(
                "/devices/{id}/inventory-scopes",
                post(
                    inventory_scopes,
                    &contracts::INVENTORY_SCOPES,
                    &[RouteOperation::List],
                ),
            ),
            get_collection_run: rss_mdm_http_contract::module::Route::new(
                "/devices/{id}/collections/{run}",
                get(
                    collection_run,
                    &contracts::DEVICES,
                    &[RouteOperation::Action],
                ),
            ),
            post_list_items: rss_mdm_http_contract::module::Route::new(
                "/devices/{id}/inventory-lists/{field}",
                post(
                    list_items,
                    &contracts::INVENTORY_LIST_ITEMS,
                    &[RouteOperation::List],
                ),
            ),
            put_manual: rss_mdm_http_contract::module::Route::new(
                "/devices/{id}/manual-fields/{field}",
                put(
                    manual,
                    &contracts::DEVICES,
                    &[RouteOperation::Action, RouteOperation::Update],
                ),
            ),
            get_saved_list: rss_mdm_http_contract::module::Route::new(
                "/saved-queries",
                get(
                    saved_list,
                    &contracts::SAVED_QUERIES,
                    &[RouteOperation::List],
                ),
            ),
            get_saved_read: rss_mdm_http_contract::module::Route::new(
                "/saved-queries/{id}",
                rss_mdm_http_contract::routing::get(
                    saved_read,
                    &contracts::SAVED_QUERIES,
                    &[RouteOperation::Get],
                ),
            ),
            put_saved_write: rss_mdm_http_contract::module::Route::new(
                "/saved-queries/{id}",
                rss_mdm_http_contract::routing::put(
                    saved_write,
                    &contracts::SAVED_QUERIES,
                    &[
                        RouteOperation::Create,
                        RouteOperation::Update,
                        RouteOperation::Delete,
                    ],
                ),
            ),
            post_saved_execute: rss_mdm_http_contract::module::Route::new(
                "/saved-queries/{id}/execute",
                post(
                    saved_execute,
                    &contracts::SAVED_QUERIES,
                    &[RouteOperation::Action],
                ),
            ),
        }
        .assemble()
    }
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
        Command::FieldLayoutRead { access } => {
            if &field_access(auth)? == access {
                Ok(())
            } else {
                Err(rss_mdm_inventory_service::Error::Forbidden)
            }
        }
        Command::FieldReferences { .. } => {
            auth.proof.manage(Permission::InventoryFieldsWrite)?;
            auth.proof
                .manage(Permission::ResourceRead)
                .map_err(rss_mdm_inventory_service::Error::from)
        }
        Command::FieldLayoutWrite { .. }
        | Command::FieldWrite { .. }
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
    audit.set_action(
        if command.operation().is_some() {
            "management_write"
        } else {
            "inventory_read"
        },
        if command.operation().is_some() {
            rss_mdm_audit_integration::AuditIntent::Management
        } else {
            rss_mdm_audit_integration::AuditIntent::Routine
        },
    );
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
        Command::FieldWrite { field, .. } | Command::FieldReferences { field, .. } => {
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
        audit.operation(
            id,
            audit.snapshot().action,
            rss_mdm_audit_integration::AuditIntent::Management,
        );
    }
    authorize(auth, &command)?;
    let envelope = app
        .assets
        .execute_authorized(&command, audit, &auth.proof, &|| authorize(auth, &command))
        .await?;
    Ok(HttpResponse::new(envelope))
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
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<FieldsQuery>,
    >,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<HttpResponse>, Error> {
    (async {
        audit.set_action(
            "inventory_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let q = query.parse().map_err(|_| Error::Malformed)?;
        Ok(HttpResponse::new(
            app.assets.fields(&auth.proof, &q, &audit).await?,
        ))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn field_read(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(key): Path<String>,
) -> std::result::Result<HttpResponse, Error> {
    audit.set_action(
        "inventory_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.target(&key);
    let key = FieldKey::parse(&key).map_err(|_| Error::Malformed)?;
    Ok(HttpResponse::new(
        app.assets.field(&auth.proof, key, &audit).await?,
    ))
}
async fn search(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    payload: Result<SearchBody, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<HttpResponse, Error> {
    let request = payload.map_err(Error::from)?.0;
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
#[derive(schemars::JsonSchema, Deserialize)]
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
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<SavedDirectoryQuery>,
    >,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<HttpResponse>, Error> {
    (async {
        let q = query.parse().map_err(|_| Error::Malformed)?;
        Ok(HttpResponse::new(
            app.assets.saved_directory(&auth.proof, &q, &audit).await?,
        ))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
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
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<QueryItemsQuery>,
    >,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<HttpResponse>, Error> {
    (async {
        let (page, _context) = query.parse().map_err(|_| Error::Malformed)?;
        run(
            &app,
            &auth,
            &audit,
            Command::QueryItems {
                task,
                scope: ReadScope::from_proof(&auth.proof)?,
                limit: page.limit(),
                cursor: page.cursor().clone(),
            },
        )
        .await
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn query_facets(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((task, facet)): Path<(Uuid, Facet)>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<QueryFacetsQuery>,
    >,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<HttpResponse>, Error> {
    (async {
        let (page, _context) = query.parse().map_err(|_| Error::Malformed)?;
        run(
            &app,
            &auth,
            &audit,
            Command::QueryFacets {
                task,
                facet,
                scope: ReadScope::from_proof(&auth.proof)?,
                limit: page.limit(),
                cursor: page.cursor().clone(),
            },
        )
        .await
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
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
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<FieldReferencesQuery>,
    >,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<HttpResponse>, Error> {
    (async {
        let field = FieldKey::parse(&key).map_err(|_| Error::Malformed)?;
        let (page, _) = query.parse().map_err(|_| Error::Malformed)?;
        let query = FieldReferenceQuery {
            limit: page.limit() as u16,
            cursor: page.cursor().clone(),
            authority: auth.proof.authorization()?.query_binding(&auth.proof)?,
        };
        run(
            &app,
            &auth,
            &audit,
            Command::FieldReferences { field, query },
        )
        .await
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CollectionSelector {
    scope: Option<String>,
}
async fn inventory_scopes(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    payload: std::result::Result<PageBody<ScopePageRequest>, Error>,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<HttpResponse>, Error> {
    let request = payload?.0;
    let page = windows::SCOPES
        .page(request.limit, request.cursor, windows::MAX_CURSOR_BYTES)
        .map_err(|_| Error::Malformed)?;
    run(
        &app,
        &auth,
        &audit,
        Command::InventoryScopes {
            device,
            scope: ReadScope::from_proof(&auth.proof)?,
            limit: page.limit(),
            cursor: page.cursor().clone(),
        },
    )
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
fn read_scope(auth: &RequestAuth, scope: Option<String>) -> std::result::Result<ReadScope, Error> {
    let scope = scope
        .map(|s| serde_json::from_str(&s).map_err(|_| Error::Malformed))
        .transpose()?;
    read_scope_value(auth, scope)
}
fn read_scope_value(
    auth: &RequestAuth,
    scope: Option<rss_mdm_inventory::CollectionScope>,
) -> std::result::Result<ReadScope, Error> {
    let mut read = ReadScope::from_proof(&auth.proof)?;
    if let Some(scope) = scope {
        scope.validate_executable().map_err(|_| Error::Malformed)?;
        read.collection_scope = scope;
    }
    Ok(read)
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
    payload: std::result::Result<PageBody<ListPageRequest>, Error>,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<HttpResponse>, Error> {
    let request = payload?.0;
    let page = windows::LISTS
        .page(request.limit, request.cursor, windows::MAX_CURSOR_BYTES)
        .map_err(|_| Error::Malformed)?;
    let field = FieldKey::parse(&key).map_err(|_| Error::Malformed)?;
    let scope = read_scope_value(&auth, request.scope)?;
    run(
        &app,
        &auth,
        &audit,
        Command::ListItems {
            device,
            field,
            scope,
            limit: page.limit(),
            cursor: page.cursor().clone(),
        },
    )
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn collection_items(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id, key)): Path<(String, Uuid, String)>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<CollectionItemsQuery>,
    >,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<HttpResponse>, Error> {
    (async {
        let (page, context) = query.parse().map_err(|_| Error::Malformed)?;
        let field = FieldKey::parse(&key).map_err(|_| Error::Malformed)?;
        let scope = read_scope(&auth, context.get("scope").cloned())?;
        run(
            &app,
            &auth,
            &audit,
            Command::CollectionItems {
                device,
                run: id,
                field,
                scope,
                cursor: page.cursor().clone(),
                limit: page.limit(),
            },
        )
        .await
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
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

struct FieldsQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for FieldsQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_inventory_service::assets::field_directory::SCHEMA
    }
}

struct QueryItemsQuery;
impl rss_mdm_http_contract::query::WindowOwner for QueryItemsQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_inventory_service::assets::windows::RESULTS
    }
}

struct QueryFacetsQuery;
impl rss_mdm_http_contract::query::WindowOwner for QueryFacetsQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_inventory_service::assets::windows::FACETS
    }
}

struct FieldReferencesQuery;
impl rss_mdm_http_contract::query::WindowOwner for FieldReferencesQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_inventory_service::assets::windows::FIELD_REFERENCES
    }
}

#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopePageRequest {
    #[schemars(range(min = 1, max = 1000))]
    limit: Option<u16>,
    #[schemars(length(min = 1, max = windows::MAX_CURSOR_BYTES))]
    cursor: Option<String>,
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListPageRequest {
    #[schemars(range(min = 1, max = 1000))]
    limit: Option<u16>,
    #[schemars(length(min = 1, max = windows::MAX_CURSOR_BYTES))]
    cursor: Option<String>,
    scope: Option<rss_mdm_inventory::CollectionScope>,
}
trait PageBodyOwner {
    fn schema() -> &'static rss_mdm_query::window::Schema;
}
impl PageBodyOwner for ScopePageRequest {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &windows::SCOPES
    }
}
impl PageBodyOwner for ListPageRequest {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &windows::LISTS
    }
}
struct PageBody<T>(T);
impl<S: Send + Sync, T: serde::de::DeserializeOwned + Send> axum::extract::FromRequest<S>
    for PageBody<T>
{
    type Rejection = Error;
    async fn from_request(
        request: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        if request.uri().query().is_some() {
            return Err(Error::Malformed);
        }
        let Json(value) = Json::from_request(request, state)
            .await
            .map_err(Error::from)?;
        Ok(Self(value))
    }
}
impl<T: schemars::JsonSchema + PageBodyOwner> rss_mdm_http_contract::signature::Input
    for PageBody<T>
{
    fn request() -> rss_mdm_http_contract::signature::Request {
        let mut request = <Json<T> as rss_mdm_http_contract::signature::Input>::request();
        request.query_owner = Some(rss_mdm_http_contract::QueryDeclaration::BodyWindow(
            T::schema(),
        ));
        request
    }
}

struct CollectionItemsQuery;
impl rss_mdm_http_contract::query::WindowOwner for CollectionItemsQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_inventory_service::assets::windows::COLLECTION_ITEMS
    }
}

struct HttpResponse {
    status: StatusCode,
    envelope: AssetEnvelope,
}
impl HttpResponse {
    fn new(envelope: AssetEnvelope) -> Self {
        let status = Self::status(&envelope);
        Self { status, envelope }
    }
    fn status(envelope: &AssetEnvelope) -> StatusCode {
        if matches!(&envelope.asset, Response::Accepted { .. }) {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        }
    }
}
impl IntoResponse for HttpResponse {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(self.envelope)).into_response()
    }
}
impl rss_mdm_http_contract::signature::Output for HttpResponse {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        [StatusCode::OK, StatusCode::ACCEPTED].into_iter().map(|status| {
            let mut response = rss_mdm_http_contract::signature::Response::json::<AssetEnvelope>(status.as_u16());
            let schema = &mut response.body.as_mut().expect("asset JSON envelope").schema.value;
            let reference = schema["properties"]["asset"]["$ref"].as_str().expect("actual asset response schema").trim_start_matches('#').to_owned();
            let variants = schema.pointer_mut(&reference).expect("asset response definition")["oneOf"].as_array_mut().expect("closed asset variants");
            variants.retain(|variant| (variant["properties"]["kind"]["const"] == "accepted") == (status == StatusCode::ACCEPTED));
            response
        }).collect()
    }
}

struct SavedDirectoryQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for SavedDirectoryQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_inventory_service::assets::saved_directory::SCHEMA
    }
}

struct SearchBody(Operation<rss_mdm_inventory_service::assets::rsql::QueryInput>);
impl<S: Send + Sync> axum::extract::FromRequest<S> for SearchBody {
    type Rejection = axum::extract::rejection::JsonRejection;
    async fn from_request(
        request: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Json(input) = Json::from_request(request, state).await?;
        Ok(Self(input))
    }
}
impl rss_mdm_http_contract::signature::Input for SearchBody {
    fn request() -> rss_mdm_http_contract::signature::Request {
        let mut request = <Json<Operation<rss_mdm_inventory_service::assets::rsql::QueryInput>> as rss_mdm_http_contract::signature::Input>::request();
        request.query_owner = Some(rss_mdm_http_contract::QueryDeclaration::Catalog(
            &rss_mdm_inventory_service::assets::rsql::CONTRACT,
        ));
        request
    }
}
