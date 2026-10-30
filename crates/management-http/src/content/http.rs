//! Resource-authorized streaming upload. Long I/O never holds a PG transaction.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    body::Body,
    extract::{Path, Query, State},
};
use futures::TryStreamExt;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_content_service::Upload;
type HttpState = Option<Arc<rss_mdm_content_service::service::Access>>;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::post};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
pub fn routes() -> Router<HttpState, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Browser] { get_script, get_receipt, post_cleanup, post_upload, post_mirror, post_begin, get_status, patch_append, post_complete } }
        RoutesModule1 {
            get_script: rss_mdm_http_contract::module::Route::new(
                "/resources/{id}/versions/{version}/script",
                rss_mdm_http_contract::routing::get(
                    script,
                    &contracts::DOWNLOAD_MANAGEMENT_HTTP,
                    &[RouteOperation::Action],
                ),
            ),
            get_receipt: rss_mdm_http_contract::module::Route::new(
                "/resources/{id}/content/operations/{operation}",
                rss_mdm_http_contract::routing::get(
                    receipt,
                    &contracts::RESOURCE,
                    &[RouteOperation::Action],
                ),
            ),
            post_cleanup: rss_mdm_http_contract::module::Route::new(
                "/software/content/cleanup",
                post(
                    cleanup,
                    &contracts::CONTENT_MAINTENANCE,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
            post_upload: rss_mdm_http_contract::module::Route::new(
                "/resources/{id}/content",
                post(
                    upload,
                    &contracts::RESOURCE,
                    &[RouteOperation::Action, RouteOperation::Create],
                ),
            ),
            post_mirror: rss_mdm_http_contract::module::Route::new(
                "/resources/{id}/content/mirror",
                post(
                    mirror,
                    &contracts::RESOURCE,
                    &[RouteOperation::Action, RouteOperation::Create],
                ),
            ),
            post_begin: rss_mdm_http_contract::module::Route::new(
                "/resources/{id}/uploads/{upload}",
                rss_mdm_http_contract::routing::post(
                    begin,
                    &contracts::RESOURCE,
                    &[RouteOperation::Action, RouteOperation::Create],
                ),
            ),
            get_status: rss_mdm_http_contract::module::Route::new(
                "/resources/{id}/uploads/{upload}",
                rss_mdm_http_contract::routing::get(
                    status,
                    &contracts::RESOURCE,
                    &[RouteOperation::Action],
                ),
            ),
            patch_append: rss_mdm_http_contract::module::Route::new(
                "/resources/{id}/uploads/{upload}",
                rss_mdm_http_contract::routing::patch(
                    append,
                    &contracts::RESOURCE,
                    &[RouteOperation::Action, RouteOperation::Update],
                ),
            ),
            post_complete: rss_mdm_http_contract::module::Route::new(
                "/resources/{id}/uploads/{upload}/complete",
                post(
                    complete,
                    &contracts::RESOURCE,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
        }
        .assemble()
    }
}
use rss_mdm_content_service::service::{Selection, current};
async fn begin(
    State(app): State<HttpState>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, upload)): Path<(String, Uuid)>,
    Query(input): Query<Selection>,
) -> Result<Json<Upload>, Error> {
    let app = app.as_deref().ok_or(Error::Unsupported)?;
    rss_mdm_content_service::service::begin_upload(
        app,
        &auth.proof,
        &audit,
        &id,
        upload,
        &input,
        rss_mdm_content_service::service::store(app)?.upload_budget()?,
    )
    .await
    .map(Json)
    .map_err(Into::into)
}
async fn status(
    State(app): State<HttpState>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, upload)): Path<(String, Uuid)>,
) -> Result<Json<Upload>, Error> {
    let app = app.as_deref().ok_or(Error::Unsupported)?;
    Ok(Json(
        current(
            app,
            &auth.proof,
            &audit,
            &id,
            upload,
            rss_mdm_content_service::service::store(app)?.upload_budget()?,
        )
        .await?,
    ))
}
#[derive(schemars::JsonSchema, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offset {
    offset: u64,
}
async fn append(
    State(app): State<HttpState>,
    Extension(auth): Extension<RequestAuth>,
    Extension(continuation): Extension<crate::http_operation::RequestContinuation>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, upload)): Path<(String, Uuid)>,
    Query(offset): Query<Offset>,
    rss_mdm_http_contract::signature::BinaryBody(body): rss_mdm_http_contract::signature::BinaryBody,
) -> Result<AppendResponse, Error> {
    let app = app.as_deref().ok_or(Error::Unsupported)?;
    let reader =
        tokio_util::io::StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
    Ok(AppendResponse(
        rss_mdm_content_service::service::append_upload(
            app,
            rss_mdm_content_service::service::UploadAuthority::new(
                &auth.proof,
                continuation.secret(),
            ),
            &audit,
            &id,
            upload,
            offset.offset,
            reader,
        )
        .await?,
    ))
}
async fn complete(
    State(app): State<HttpState>,
    Extension(auth): Extension<RequestAuth>,
    Extension(continuation): Extension<crate::http_operation::RequestContinuation>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, upload)): Path<(String, Uuid)>,
) -> Result<rss_mdm_http_contract::signature::WithStatus<201, ()>, Error> {
    let app = app.as_deref().ok_or(Error::Unsupported)?;
    rss_mdm_content_service::service::complete_upload(
        app,
        rss_mdm_content_service::service::UploadAuthority::new(&auth.proof, continuation.secret()),
        &audit,
        &id,
        upload,
    )
    .await?;
    Ok(rss_mdm_http_contract::signature::WithStatus(()))
}
async fn upload(
    State(app): State<HttpState>,
    Extension(auth): Extension<RequestAuth>,
    Extension(continuation): Extension<crate::http_operation::RequestContinuation>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
    Query(input): Query<Selection>,
    rss_mdm_http_contract::signature::BinaryBody(body): rss_mdm_http_contract::signature::BinaryBody,
) -> Result<rss_mdm_http_contract::signature::WithStatus<201, ()>, Error> {
    let app = app.as_deref().ok_or(Error::Unsupported)?;
    let reader =
        tokio_util::io::StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
    rss_mdm_content_service::service::upload(
        app,
        rss_mdm_content_service::service::UploadAuthority::new(&auth.proof, continuation.secret()),
        &audit,
        &id,
        &input,
        reader,
    )
    .await?;
    Ok(rss_mdm_http_contract::signature::WithStatus(()))
}
/// Explicit bounded maintenance; every candidate is pinned against new upload/download readers.
async fn cleanup(
    State(app): State<HttpState>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<rss_mdm_content_service::service::Cleanup>, Error> {
    let app = app.as_deref().ok_or(Error::Unsupported)?;
    rss_mdm_content_service::service::cleanup(app, &auth.proof, &audit)
        .await
        .map(Json)
        .map_err(Into::into)
}

/// Mirror only the selected frozen artifact; source credentials never reach the artifact origin.
async fn mirror(
    State(app): State<HttpState>,
    Extension(auth): Extension<RequestAuth>,
    Extension(continuation): Extension<crate::http_operation::RequestContinuation>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
    Query(input): Query<Selection>,
) -> Result<rss_mdm_http_contract::signature::WithStatus<201, ()>, Error> {
    let app = app.as_deref().ok_or(Error::Unsupported)?;
    rss_mdm_content_service::service::mirror(
        app,
        rss_mdm_content_service::service::UploadAuthority::new(&auth.proof, continuation.secret()),
        &audit,
        &id,
        &input,
    )
    .await
    .map(|()| rss_mdm_http_contract::signature::WithStatus(()))
    .map_err(Into::into)
}

/// Shared response framing for catalog and execution-authorized content.
pub async fn response(
    content: super::Verified,
    headers: &axum::http::HeaderMap,
) -> Result<rss_mdm_http_contract::download::Download, Error> {
    use axum::http::header;
    let etag = content.etag();
    let length = content.artifact.length();
    if headers.get_all(header::RANGE).iter().count() > 1 {
        return Err(Error::Malformed);
    }
    let requested = headers
        .get(header::RANGE)
        .map(|h| h.to_str().map_err(|_| Error::Malformed))
        .transpose()?;
    let requested = if headers
        .get(header::IF_RANGE)
        .is_some_and(|value| value.as_bytes() != etag.as_bytes())
    {
        None
    } else {
        requested
    };
    let (start, end) = match rss_mdm_content_service::range(requested, length) {
        Ok(range) => range,
        Err(_) => {
            return Ok(rss_mdm_http_contract::download::Download::unsatisfied(
                length,
            ));
        }
    };
    let body = Body::from_stream(content.stream(start, end).await?);
    rss_mdm_http_contract::download::Download::stream(
        body,
        &etag,
        start,
        end,
        length,
        requested.is_some(),
    )
    .map_err(|_| Error::Malformed)
}
/// Durable operation lookup survives expiration of the temporary upload session.
async fn receipt(
    State(app): State<HttpState>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, operation)): Path<(String, Uuid)>,
) -> Result<Json<rss_mdm_content_service::bindings::Receipt>, Error> {
    let app = app.as_deref().ok_or(Error::Unsupported)?;
    rss_mdm_content_service::service::receipt(app, &auth.proof, &audit, &id, operation)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn script(
    State(app): State<HttpState>,
    Extension(auth): Extension<RequestAuth>,
    Extension(continuation): Extension<crate::http_operation::RequestContinuation>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, version)): Path<(String, String)>,
    DownloadHeaders(headers): DownloadHeaders,
    query: Result<
        Query<rss_mdm_content_service::service::script::ScriptSelection>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<
    rss_mdm_http_contract::download::Attachment<rss_mdm_http_contract::download::Download>,
    Error,
> {
    let app = app.as_deref().ok_or(Error::Unsupported)?;
    let Query(selection) = query.map_err(|_| Error::Malformed)?;
    let content = rss_mdm_content_service::service::script::download(
        app,
        &auth.proof,
        &audit,
        &id,
        &version,
        &selection,
        continuation.secret(),
    )
    .await?;
    let body = response(content, &headers).await?;
    Ok(rss_mdm_http_contract::download::Attachment {
        body,
        disposition: axum::http::HeaderValue::from_static("attachment; filename=\"script.txt\""),
    })
}

pub(crate) struct DownloadHeaders(pub(crate) axum::http::HeaderMap);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for DownloadHeaders {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl rss_mdm_http_contract::signature::Input for DownloadHeaders {
    fn request() -> rss_mdm_http_contract::signature::Request {
        use rss_mdm_http_contract::signature::{Direction, Request, Schema};
        Request {
            headers: [
                (
                    "range".into(),
                    Schema {
                        direction: Direction::Request,
                        value: serde_json::json!({"type":"string"}),
                    },
                ),
                (
                    "if-range".into(),
                    Schema {
                        direction: Direction::Request,
                        value: serde_json::json!({"type":"string"}),
                    },
                ),
            ]
            .into(),
            required_headers: vec![],
            ..Request::default()
        }
    }
}

struct AppendResponse(rss_mdm_content_service::service::Append);
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OffsetCode {
    UploadOffsetConflict,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct OffsetConflict {
    code: OffsetCode,
    offset: u64,
}
impl axum::response::IntoResponse for AppendResponse {
    fn into_response(self) -> axum::response::Response {
        match self.0 {
            rss_mdm_content_service::service::Append::Written(result) => {
                Json(result).into_response()
            }
            rss_mdm_content_service::service::Append::OffsetConflict(offset) => {
                rss_mdm_http_contract::signature::WithStatus::<409, _>(Json(OffsetConflict {
                    code: OffsetCode::UploadOffsetConflict,
                    offset,
                }))
                .into_response()
            }
        }
    }
}
impl rss_mdm_http_contract::signature::Output for AppendResponse {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        use rss_mdm_http_contract::signature::{Output, WithStatus};
        let mut responses = <Json<Upload> as Output>::responses();
        responses.extend(<WithStatus<409, Json<OffsetConflict>> as Output>::responses());
        responses
    }
}
