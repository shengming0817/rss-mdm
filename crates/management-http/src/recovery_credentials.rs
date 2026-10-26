//! Direct device-scoped credential access; authentication is the normal management middleware.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, Query, RawQuery, State},
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

struct Services {
    credentials: Arc<Credentials>,
    cursor: rss_mdm_query::cursor::CursorCodec,
}
pub fn routes(
    service: Option<Arc<Credentials>>,
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router {
    let Some(service) = service else {
        return Router::new();
    };
    Router::new()
        .route(
            "/devices/{device}/recovery-credentials",
            get(list)
                .owned(&contracts::RECOVERY_CREDENTIALS, &[RouteOperation::List])
                .queried(&rss_mdm_recovery_credentials::directory::SCHEMA),
        )
        .route(
            "/devices/{device}/recovery-credentials/{id}/versions/{version}/secret",
            get(disclose).owned(&contracts::RECOVERY_CREDENTIALS, &[RouteOperation::Action]),
        )
        .route(
            "/devices/{device}/recovery-credentials/{id}/versions/{version}/revoke",
            post(revoke).owned(
                &contracts::RECOVERY_CREDENTIALS,
                &[RouteOperation::Lifecycle],
            ),
        )
        .with_state(Arc::new(Services {
            credentials: service,
            cursor,
        }))
}
async fn list(
    State(s): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<Json<rss_mdm_query::Page<serde_json::Value>>>,
    Error,
> {
    (async {
        audit.set_action(
            "recovery_credential_list",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        audit.target_device(&device);
        let q = rss_mdm_recovery_credentials::directory::SCHEMA
            .parse(raw.as_deref().unwrap_or(""))
            .map_err(|_| Error::Malformed)?;
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
) -> Result<Response, Error> {
    let value = s
        .credentials
        .disclose(&auth.proof, &device, id, version, &audit)
        .await?;
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    Ok(response)
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
) -> Router {
    let Some(service) = service else {
        return Router::new();
    };
    Router::new()
        .route(
            "/devices/{device}/recovery-credentials/filevault/configuration",
            get(read_filevault_configuration)
                .owned(&contracts::RECOVERY_CREDENTIALS, &[RouteOperation::Action])
                .post(configure_filevault)
                .owned(
                    &contracts::RECOVERY_CREDENTIALS,
                    &[RouteOperation::Action, RouteOperation::Update],
                ),
        )
        .route(
            "/devices/{device}/recovery-credentials/filevault/link",
            post(link_filevault).owned(
                &contracts::RECOVERY_CREDENTIALS,
                &[RouteOperation::Action, RouteOperation::Update],
            ),
        )
        .with_state(service)
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
