//! Direct device-scoped credential access; authentication is the normal management middleware.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, RawQuery, State},
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
) -> Result<Json<rss_mdm_query::Page<serde_json::Value>>, Error> {
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
