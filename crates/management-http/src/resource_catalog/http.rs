use super::*;
use crate::authorization::{Permission, context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde_json::Value;
pub struct HttpState {
    pub catalog: Arc<ResourceCatalog>,
}
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/resources", get(directory))
        .route("/resources/{id}", get(read).post(write))
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
}

async fn directory(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: Result<
        Query<rss_mdm_flow_service::resource_catalog::directory::DirectoryQuery>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<Value>, Error> {
    audit.set_action("management_read");
    let Query(q) = query.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    Ok(Json(s.catalog.directory(&auth.proof, &q, &audit).await?))
}
async fn run(
    app: &HttpState,
    auth: &RequestAuth,
    audit: &RequestAudit,
    id: String,
    change: Option<Operation<Change>>,
) -> std::result::Result<Json<wire::Response>, Error> {
    let permission = if change.is_some() {
        Permission::ResourceWrite
    } else {
        Permission::ResourceRead
    };
    audit.target(&id);
    audit.set_action(if change.is_some() {
        "management_write"
    } else {
        "management_read"
    });
    if let Some(op) = &change {
        audit.operation(op.operation_id, "management_write");
    }
    let command = match change {
        Some(change) => Command::Resource { id, change },
        None => Command::ResourceRead { id },
    };
    Ok(Json(wire::Response::decode(
        app.catalog
            .execute(&command, audit, &|| {
                auth.proof
                    .manage(permission)
                    .map_err(rss_mdm_flow_service::Error::from)
            })
            .await?,
    )?))
}
async fn read(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
) -> std::result::Result<Json<wire::Response>, Error> {
    run(&app, &auth, &audit, id, None).await
}
async fn write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
    body: std::result::Result<Json<Operation<Change>>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<wire::Response>, Error> {
    run(
        &app,
        &auth,
        &audit,
        id,
        Some(
            body.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?
                .0,
        ),
    )
    .await
}
