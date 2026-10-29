//! Direct device-scoped credential access; authentication is the normal management middleware.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use rss_mdm_recovery_credentials::{Credentials, Material};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct Services {
    pub(crate) credentials: Arc<Credentials>,
    pub(crate) cursor: rss_mdm_query::cursor::CursorCodec,
}
pub fn routes(
    service: Option<Arc<Credentials>>,
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    let enabled = service.is_some();
    mount(
        service.map(|service| {
            Arc::new(Services {
                credentials: service,
                cursor,
            })
        }),
        enabled,
    )
}
pub(crate) fn mount(
    runtime: Option<Arc<Services>>,
    enabled: bool,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register()
        .bind_with(runtime.as_ref(), Clone::clone)
        .when("recovery_credentials", enabled)
}
fn register() -> Router<Arc<Services>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_list, get_disclose, post_revoke } }
        RegisterModule1 {
            get_list: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/recovery-credentials",
                get(
                    list,
                    &contracts::RECOVERY_CREDENTIALS,
                    &[RouteOperation::List],
                ),
            ),
            get_disclose: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/recovery-credentials/{id}/versions/{version}/secret",
                get(
                    disclose,
                    &contracts::RECOVERY_CREDENTIALS,
                    &[RouteOperation::Action],
                ),
            ),
            post_revoke: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/recovery-credentials/{id}/versions/{version}/revoke",
                post(
                    revoke,
                    &contracts::RECOVERY_CREDENTIALS,
                    &[RouteOperation::Lifecycle],
                ),
            ),
        }
        .assemble()
    }
}
async fn list(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<ListQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<rss_mdm_recovery_credentials::Material>,
            >,
        >,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "recovery_credential_list",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        audit.target_device(&device);
        let q = query.parse().map_err(|_| Error::Malformed)?;
        s.credentials
            .list(&auth.proof, &device, &q, &s.cursor)
            .await
            .map(Json)
            .map_err(Into::into)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn disclose(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id, version)): Path<(String, Uuid, i64)>,
) -> Result<DisclosureResponse, Error> {
    let value = s
        .credentials
        .disclose(&auth.proof, &device, id, version, &audit)
        .await?;
    Ok(DisclosureResponse(value))
}
async fn revoke(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id, version)): Path<(String, Uuid, i64)>,
) -> Result<Json<Material>, Error> {
    s.credentials
        .revoke(&auth.proof, &device, id, version, &audit)
        .await
        .map(Json)
        .map_err(Into::into)
}

/// Explicit authorization changes only custody collection; it never installs a profile or rotates a key.
pub fn filevault_routes(
    service: Option<Arc<rss_mdm_recovery_credentials::FilevaultService>>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    let enabled = service.is_some();
    mount_filevault(service, enabled)
}
pub(crate) fn mount_filevault(
    runtime: Option<Arc<rss_mdm_recovery_credentials::FilevaultService>>,
    enabled: bool,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
 rss_mdm_http_contract::route_module! { struct MountFilevaultModule1 for [Browser] { get_read_filevault_configuration, post_configure_filevault, post_link_filevault } }
 MountFilevaultModule1 { get_read_filevault_configuration: rss_mdm_http_contract::module::Route::new("/devices/{device}/recovery-credentials/filevault/configuration", rss_mdm_http_contract::routing::get(read_filevault_configuration, &contracts::RECOVERY_CREDENTIALS, &[RouteOperation::Action])),
post_configure_filevault: rss_mdm_http_contract::module::Route::new("/devices/{device}/recovery-credentials/filevault/configuration", rss_mdm_http_contract::routing::post(configure_filevault, &contracts::RECOVERY_CREDENTIALS,
                    &[RouteOperation::Action, RouteOperation::Update])),
post_link_filevault: rss_mdm_http_contract::module::Route::new("/devices/{device}/recovery-credentials/filevault/link", post(link_filevault, &contracts::RECOVERY_CREDENTIALS,
                &[RouteOperation::Action, RouteOperation::Update])) }.assemble()
}
        .bind_with(runtime.as_ref(), Clone::clone).when("filevault", enabled)
}
async fn configure_filevault(
    State(s): State<Arc<rss_mdm_recovery_credentials::FilevaultService>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    input: Result<
        Json<rss_mdm_recovery_credentials::filevault::Configure>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<rss_mdm_agent_wire::filevault::Configuration>, Error> {
    let Json(input) = input.map_err(|_| Error::Malformed)?;
    audit.operation(
        input.operation_id,
        "filevault_collection_configure",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target_device(&device);
    s.configure(&auth.proof, &device, &input, &audit)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn link_filevault(
    State(s): State<Arc<rss_mdm_recovery_credentials::FilevaultService>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    input: Result<
        Json<rss_mdm_recovery_credentials::FilevaultLink>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<rss_mdm_agent_wire::filevault::Configuration>, Error> {
    let Json(input) = input.map_err(|_| Error::Malformed)?;
    audit.operation(
        input.operation_id,
        "filevault_custody_link",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target_device(&device);
    s.link(&auth.proof, &device, &input, &audit)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn read_filevault_configuration(
    State(s): State<Arc<rss_mdm_recovery_credentials::FilevaultService>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    selection: Result<
        Query<rss_mdm_recovery_credentials::FilevaultSelection>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<rss_mdm_agent_wire::filevault::Configuration>, Error> {
    let Query(selection) = selection.map_err(|_| Error::Malformed)?;
    audit.set_action(
        "filevault_configuration_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.target_device(&device);
    s.management_configuration(&auth.proof, &device, &selection)
        .await
        .map(Json)
        .map_err(Into::into)
}

struct ListQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for ListQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_recovery_credentials::directory::SCHEMA
    }
}

struct DisclosureResponse(rss_mdm_recovery_credentials::Disclosure);
impl IntoResponse for DisclosureResponse {
    fn into_response(self) -> Response {
        let mut response = rss_mdm_http_contract::signature::NoStore(Json(self.0)).into_response();
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        response
    }
}
impl rss_mdm_http_contract::signature::Output for DisclosureResponse {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        use rss_mdm_http_contract::signature::{NoStore, Schema};
        <NoStore<Json<rss_mdm_recovery_credentials::Disclosure>> as rss_mdm_http_contract::signature::Output>::responses().into_iter().map(|mut response| {
            let mut pragma = Schema::response::<String>(); pragma.value["const"] = "no-cache".into();
            response.headers.insert("pragma".into(), pragma); response
        }).collect()
    }
}
