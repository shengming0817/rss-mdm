use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::routing::get;
use rss_mdm_http_contract::{Operation as RouteOperation, Router, catalog as contracts};
use std::sync::Arc;
use uuid::Uuid;
pub(crate) fn register(
    cursor: Option<rss_mdm_query::cursor::CursorCodec>,
) -> Router<Arc<dyn super::Reads>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! {struct Routes for [Browser]{get_ddm,operations}}
    let router = Routes {
        get_ddm: rss_mdm_http_contract::module::Route::new(
            "/devices/{device}/ddm",
            get(
                ddm,
                &contracts::DEVICE_DECLARATIONS,
                &[RouteOperation::List],
            ),
        ),
        operations: read_routes(),
    }
    .assemble();
    match cursor {
        Some(codec) => router.layer(Extension(codec)),
        None => router,
    }
}
pub fn read_routes()
-> Router<Arc<dyn super::Reads>, impl rss_mdm_http_contract::module::Declaration> {
    rss_mdm_http_contract::route_module! { struct RegisterModule2 for [Browser] { get_directory, get_statistics, get_read } }
    RegisterModule2 {
        get_directory: rss_mdm_http_contract::module::Route::new(
            "/operations",
            get(directory, &contracts::EXECUTIONS, &[RouteOperation::List]),
        ),
        get_statistics: rss_mdm_http_contract::module::Route::new(
            "/operations/statistics",
            get(statistics, &contracts::EXECUTIONS, &[RouteOperation::Query]),
        ),
        get_read: rss_mdm_http_contract::module::Route::new(
            "/devices/{device}/operations/{id}",
            get(read, &contracts::DEVICES, &[RouteOperation::Action]),
        ),
    }
    .assemble()
}

async fn directory(
    axum::extract::Path(_tenant): axum::extract::Path<uuid::Uuid>,

    State(s): State<Arc<dyn super::Reads>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<DirectoryQuery>,
    >,
) -> std::result::Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<super::Page<rss_mdm_query::directory::Projection<super::Item>>>,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "command_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let q = query.parse().map_err(|_| Error::Malformed)?;
        let page = s.directory(&auth, &q, &codec, &audit).await?;
        Ok(Json(page))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

async fn statistics(
    axum::extract::Path(_tenant): axum::extract::Path<uuid::Uuid>,

    State(s): State<Arc<dyn super::Reads>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Statistics<DirectoryQuery>,
    >,
) -> std::result::Result<Json<rss_mdm_query::Statistics<super::Statistics>>, Error> {
    audit.set_action(
        "command_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let q = query.parse().map_err(|_| Error::Malformed)?;
    Ok(Json(s.statistics(&auth, &q, &audit).await?))
}

async fn read(
    State(app): State<Arc<dyn super::Reads>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((_tenant, device, id)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId, Uuid)>,
) -> std::result::Result<Json<super::Detail>, Error> {
    audit.operation(
        id,
        "command_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.target_device(&device);
    app.detail(&auth, &device, id, &audit).await.map(Json)
}

async fn ddm(
    State(s): State<Arc<dyn super::Reads>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((_tenant, device)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId)>,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
    query: rss_mdm_http_contract::query::OwnedQuery<rss_mdm_http_contract::query::Window<DdmQuery>>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<super::projection::Ddm>>, Error> {
    (async {
        let (query, _) = query.parse().map_err(|_| Error::Malformed)?;
        Ok(Json(crate::operation_reads::projection::ddm(
            s.declarations(&auth, &device, &query, &audit, &codec)
                .await?,
        )))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
struct DirectoryQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for DirectoryQuery {
    fn execution() -> &'static rss_mdm_query::directory::Execution {
        &crate::operation_reads::EXECUTION
    }
}

struct DdmQuery;
impl rss_mdm_http_contract::query::WindowOwner for DdmQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &super::declarations::SCHEMA
    }
}
