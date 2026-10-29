use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_content_service::connections::{
    Receipt, Request,
    authority::{Authority, Directory},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use std::sync::Arc;

pub fn routes(
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router<Arc<Authority>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    register(Some(cursor))
}
pub(crate) fn register(
    cursor: Option<rss_mdm_query::cursor::CursorCodec>,
) -> Router<Arc<Authority>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    let router = {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_history, get_read, post_create, get_operation } }
        RegisterModule1 {
            get_history: rss_mdm_http_contract::module::Route::new(
                "/storage/connections/versions",
                get(
                    history,
                    &contracts::STORAGE_CONNECTION_VERSIONS,
                    &[RouteOperation::List],
                ),
            ),
            get_read: rss_mdm_http_contract::module::Route::new(
                "/storage/connections",
                rss_mdm_http_contract::routing::get(
                    read,
                    &contracts::STORAGE_CONNECTIONS,
                    &[RouteOperation::Get],
                ),
            ),
            post_create: rss_mdm_http_contract::module::Route::new(
                "/storage/connections",
                rss_mdm_http_contract::routing::post(
                    create,
                    &contracts::STORAGE_CONNECTIONS,
                    &[RouteOperation::Update],
                ),
            ),
            get_operation: rss_mdm_http_contract::module::Route::new(
                "/storage/connections/operations/{id}",
                get(
                    operation,
                    &contracts::STORAGE_CONNECTIONS,
                    &[RouteOperation::Get],
                ),
            ),
        }
        .assemble()
    };
    let router = {
        rss_mdm_http_contract::route_module! { struct RegisterModule101 for [Browser] { base, get_migrations, post_create_migration, get_migration_operation } }
        RegisterModule101 {
            base: router,
            get_migrations: rss_mdm_http_contract::module::Route::new(
                "/storage/migrations",
                rss_mdm_http_contract::routing::get(
                    migrations,
                    &contracts::STORAGE_MIGRATIONS,
                    &[RouteOperation::Get],
                ),
            ),
            post_create_migration: rss_mdm_http_contract::module::Route::new(
                "/storage/migrations",
                rss_mdm_http_contract::routing::post(
                    create_migration,
                    &contracts::STORAGE_MIGRATIONS,
                    &[RouteOperation::Update],
                ),
            ),
            get_migration_operation: rss_mdm_http_contract::module::Route::new(
                "/storage/migrations/operations/{id}",
                get(
                    migration_operation,
                    &contracts::STORAGE_MIGRATIONS,
                    &[RouteOperation::Get],
                ),
            ),
        }
        .assemble()
    };
    let router = {
        rss_mdm_http_contract::route_module! { struct RegisterModule102 for [Browser] { base, post_cancel_migration } }
        RegisterModule102 {
            base: router,
            post_cancel_migration: rss_mdm_http_contract::module::Route::new(
                "/storage/migrations/operations/{id}/cancel",
                rss_mdm_http_contract::routing::post(
                    cancel_migration,
                    &contracts::STORAGE_MIGRATIONS,
                    &[RouteOperation::Update],
                ),
            ),
        }
        .assemble()
    };
    match cursor {
        Some(cursor) => router.layer(axum::Extension(cursor)),
        None => router,
    }
}
async fn read(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<Directory>, Error> {
    audit.set_action(
        "storage_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    Ok(Json(service.read(&auth.proof, &audit).await?))
}
async fn create(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: crate::api::WriteHeaders,
    input: Result<Json<Request>, axum::extract::rejection::JsonRejection>,
) -> Result<rss_mdm_http_contract::signature::WithStatus<202, Json<Receipt>>, Error> {
    let operation = crate::api::write_key(&headers, &audit, "storage_provision")?;
    let input = input.map_err(Error::from)?.0;
    Ok(rss_mdm_http_contract::signature::WithStatus(Json(
        service
            .create(&auth.proof, &audit, operation, &input)
            .await?,
    )))
}

async fn operation(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<Receipt>, Error> {
    audit.set_action(
        "storage_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    Ok(Json(service.operation(&auth.proof, &audit, id).await?))
}

async fn history(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(cursor): Extension<rss_mdm_query::cursor::CursorCodec>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<HistoryQuery>,
    >,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<rss_mdm_query::Page<Receipt>>>, Error> {
    (async {
        let (q, _) = query.parse().map_err(|_| Error::Malformed)?;
        service
            .history(&auth.proof, &audit, &q, &cursor)
            .await
            .map(Json)
            .map_err(Error::from)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

struct HistoryQuery;
impl rss_mdm_http_contract::query::WindowOwner for HistoryQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_content_service::connections::authority::HISTORY
    }
}

async fn create_migration(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: crate::api::WriteHeaders,
    input: Result<
        Json<rss_mdm_content_service::migration::Request>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<
    rss_mdm_http_contract::signature::WithStatus<
        202,
        Json<rss_mdm_content_service::migration::Receipt>,
    >,
    Error,
> {
    let operation = crate::api::write_key(&headers, &audit, "storage_migration_request")?;
    let input = input.map_err(Error::from)?.0;
    Ok(rss_mdm_http_contract::signature::WithStatus(Json(
        service
            .create_migration(&auth.proof, &audit, operation, &input)
            .await?,
    )))
}
async fn migration_operation(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<rss_mdm_content_service::migration::Receipt>, Error> {
    audit.set_action(
        "storage_migration_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    Ok(Json(
        service.migration_operation(&auth.proof, &audit, id).await?,
    ))
}

async fn cancel_migration(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<rss_mdm_content_service::migration::Receipt>, Error> {
    Ok(Json(
        service.cancel_migration(&auth.proof, &audit, id).await?,
    ))
}

async fn migrations(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<rss_mdm_content_service::migration::Directory>, Error> {
    audit.set_action(
        "storage_migration_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    Ok(Json(service.migrations(&auth.proof, &audit).await?))
}
