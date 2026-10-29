use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

pub fn previews(
    queries: Arc<rss_mdm_execution_service::queries::Queries>,
    telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register_previews(Some(cursor)).with_state(Arc::new(super::http_preview::StateServices {
        queries,
        telemetry,
    }))
}
pub(crate) fn register_previews(
    cursor: Option<rss_mdm_query::cursor::CursorCodec>,
) -> Router<
    Arc<super::http_preview::StateServices>,
    impl rss_mdm_http_contract::module::Declaration + use<>,
> {
    let router = {
        rss_mdm_http_contract::route_module! { struct RegisterPreviewsModule1 for [Browser] { post_preview } }
        RegisterPreviewsModule1 {
            post_preview: rss_mdm_http_contract::module::Route::new(
                "/policies/previews",
                post(
                    super::http_preview::preview,
                    &contracts::POLICY_PREVIEWS,
                    &[RouteOperation::List, RouteOperation::Query],
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

pub fn routes(
    queries: Arc<rss_mdm_execution_service::queries::Queries>,
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router<Arc<Policies>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    register(Some(queries), Some(cursor))
}
pub(crate) fn register(
    queries: Option<Arc<rss_mdm_execution_service::queries::Queries>>,
    cursor: Option<rss_mdm_query::cursor::CursorCodec>,
) -> Router<Arc<Policies>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    let router = {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { post_resolve, router_new, get_capabilities, get_list, get_read, post_change, delete_delete, post_rerun } }
        RegisterModule1 { post_resolve: rss_mdm_http_contract::module::Route::new("/policies/resolve", post(resolve, &contracts::POLICIES, &[RouteOperation::Action])),
router_new: {
 rss_mdm_http_contract::route_module! { struct RegisterModule2 for [Browser] { get_assignments } }
 RegisterModule2 { get_assignments: rss_mdm_http_contract::module::Route::new("/policies/{id}/assignments", get(assignments, &contracts::POLICY_ASSIGNMENTS, &[RouteOperation::List])) }.assemble()
}
                .bind_with(queries.as_ref(), Clone::clone),
get_capabilities: rss_mdm_http_contract::module::Route::new("/policies/capabilities", get(capabilities, &contracts::POLICIES, &[RouteOperation::Action])),
get_list: rss_mdm_http_contract::module::Route::new("/policies", get(list, &contracts::POLICIES, &[RouteOperation::List])),
get_read: rss_mdm_http_contract::module::Route::new("/policies/{id}", rss_mdm_http_contract::routing::get(read, &contracts::POLICIES, &[RouteOperation::Get])),
post_change: rss_mdm_http_contract::module::Route::new("/policies/{id}", rss_mdm_http_contract::routing::post(change, &contracts::POLICIES,
                    &[RouteOperation::Create, RouteOperation::Update])),
delete_delete: rss_mdm_http_contract::module::Route::new("/policies/{id}", rss_mdm_http_contract::routing::delete(delete, &contracts::POLICIES, &[RouteOperation::Delete])),
post_rerun: rss_mdm_http_contract::module::Route::new("/policies/{id}/reruns", post(rerun, &contracts::POLICIES,
                &[RouteOperation::Action, RouteOperation::Create])) }.assemble()
    };
    match cursor {
        Some(cursor) => router.layer(axum::Extension(cursor)),
        None => router,
    }
}
async fn change(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: std::result::Result<
        Json<rss_mdm_policy_service::operation::Operation<Change>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> std::result::Result<Json<rss_mdm_policy::View>, Error> {
    let Json(input) = input.map_err(Error::from)?;
    audit.operation(
        input.operation_id,
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.resource_target(
        rss_mdm_audit_integration::TargetKind::Policy,
        &id.to_string(),
    );
    service
        .change(&auth.proof, id, &input, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn read(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<rss_mdm_policy::View>, Error> {
    super::read::read(&service, &auth.proof, &audit, id)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn list(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<PolicyDirectoryQuery>,
    >,
) -> std::result::Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_query::Page<rss_mdm_query::directory::Projection<super::read::Row>>>,
    >,
    Error,
> {
    (async {
        let page = query.parse().map_err(|_| Error::Malformed)?;
        super::read::list(&service, &auth.proof, &audit, &page)
            .await
            .map(Json)
            .map_err(Error::from)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

async fn rerun(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    input: std::result::Result<
        Json<rss_mdm_policy_service::operation::Operation<super::rerun::Rerun>>,
        axum::extract::rejection::JsonRejection,
    >,
) -> std::result::Result<Json<super::rerun::Receipt>, Error> {
    let Json(input) = input.map_err(Error::from)?;
    audit.operation(
        input.operation_id,
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.resource_target(
        rss_mdm_audit_integration::TargetKind::Policy,
        &id.to_string(),
    );
    service
        .rerun(&auth.proof, id, &input, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn assignments(
    State(service): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<AssignmentsQuery>,
    >,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
) -> std::result::Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_execution_service::queries::records::AssignmentPage>,
    >,
    Error,
> {
    (async {
        let (page, _) = query.parse().map_err(|_| Error::Malformed)?;
        rss_mdm_execution_service::queries::assignments::assignments(
            &service,
            &auth.proof,
            &audit,
            id,
            &page,
            &codec,
        )
        .await
        .map(Json)
        .map_err(Error::from)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

#[derive(schemars::JsonSchema, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Delete {
    operation_id: Uuid,
    expected_revision: u64,
}
async fn delete(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Delete>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<rss_mdm_policy::View>, Error> {
    let Json(body) = body.map_err(Error::from)?;
    audit.operation(
        body.operation_id,
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.resource_target(
        rss_mdm_audit_integration::TargetKind::Policy,
        &id.to_string(),
    );
    service
        .change(
            &auth.proof,
            id,
            &rss_mdm_policy_service::operation::Operation {
                operation_id: body.operation_id,
                expected_revision: body.expected_revision,
                input: Change::Archive,
            },
            &audit,
        )
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn capabilities(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<rss_mdm_policy_service::management::Capabilities>, Error> {
    service
        .capabilities(&auth.proof, &audit)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn resolve(
    State(service): State<Arc<Policies>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Json(selector): Json<rss_mdm_agent_wire::runtime::CapabilitySelector>,
) -> std::result::Result<Json<super::read::Resolved>, Error> {
    super::read::resolve(&service, &auth.proof, &audit, &selector)
        .await
        .map(Json)
        .map_err(Error::from)
}

struct AssignmentsQuery;
impl rss_mdm_http_contract::query::WindowOwner for AssignmentsQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_execution_service::queries::assignments::SCHEMA
    }
}

struct PolicyDirectoryQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for PolicyDirectoryQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_policy_service::management::read::SCHEMA
    }
}
