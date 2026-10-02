//! Resource-authorized streaming upload. Long I/O never holds a PG transaction.
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    routing::post,
};
use futures::TryStreamExt;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_content_service::Upload;
pub(crate) use rss_mdm_content_service::service::Access as HttpState;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/resources/{id}/content/operations/{operation}",
            axum::routing::get(receipt),
        )
        .route("/software/content/cleanup", post(cleanup))
        .route("/resources/{id}/content", post(upload))
        .route("/resources/{id}/content/mirror", post(mirror))
        .route(
            "/resources/{id}/uploads/{upload}",
            post(begin).get(status).patch(append),
        )
        .route("/resources/{id}/uploads/{upload}/complete", post(complete))
        .layer(DefaultBodyLimit::disable())
}
use rss_mdm_content_service::service::{Selection, current};
async fn begin(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, upload)): Path<(String, Uuid)>,
    Query(input): Query<Selection>,
) -> Result<Json<Upload>, Error> {
    rss_mdm_content_service::service::begin_upload(&app, &auth.proof, &audit, &id, upload, &input)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn status(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, upload)): Path<(String, Uuid)>,
) -> Result<Json<Upload>, Error> {
    Ok(Json(current(&app, &auth.proof, &audit, &id, upload).await?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Offset {
    offset: u64,
}
async fn append(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, upload)): Path<(String, Uuid)>,
    Query(offset): Query<Offset>,
    body: Body,
) -> Result<axum::response::Response, Error> {
    use axum::response::IntoResponse;
    let reader =
        tokio_util::io::StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
    match rss_mdm_content_service::service::append_upload(
        &app,
        &auth.proof,
        &audit,
        &id,
        upload,
        offset.offset,
        reader,
    )
    .await?
    {
        rss_mdm_content_service::service::Append::Written(result) => {
            Ok(Json(result).into_response())
        }
        rss_mdm_content_service::service::Append::OffsetConflict(offset) => Ok((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"code":"upload_offset_conflict","offset":offset})),
        )
            .into_response()),
    }
}
async fn complete(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, upload)): Path<(String, Uuid)>,
) -> Result<StatusCode, Error> {
    rss_mdm_content_service::service::complete_upload(&app, &auth.proof, &audit, &id, upload)
        .await?;
    Ok(StatusCode::CREATED)
}
async fn upload(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
    Query(input): Query<Selection>,
    body: Body,
) -> Result<StatusCode, Error> {
    let reader =
        tokio_util::io::StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
    rss_mdm_content_service::service::upload(&app, &auth.proof, &audit, &id, &input, reader)
        .await?;
    Ok(StatusCode::CREATED)
}
/// Explicit bounded maintenance; every candidate is pinned against new upload/download readers.
async fn cleanup(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<serde_json::Value>, Error> {
    rss_mdm_content_service::service::cleanup(&app, &auth.proof, &audit)
        .await
        .map(Json)
        .map_err(Into::into)
}

/// Mirror only the selected frozen artifact; source credentials never reach the artifact origin.
async fn mirror(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<String>,
    Query(input): Query<Selection>,
) -> Result<StatusCode, Error> {
    rss_mdm_content_service::service::mirror(&app, &auth.proof, &audit, &id, &input)
        .await
        .map(|()| StatusCode::CREATED)
        .map_err(Into::into)
}

/// Shared response framing for catalog and execution-authorized content.
pub async fn response(
    content: super::Verified,
    headers: &axum::http::HeaderMap,
) -> Result<axum::response::Response, Error> {
    use axum::{http::header, response::IntoResponse};
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
    let (start, end) = match super::range(requested, length) {
        Ok(range) => range,
        Err(_) => {
            let mut response = (
                StatusCode::RANGE_NOT_SATISFIABLE,
                Json(serde_json::json!({"code":"range_not_satisfiable"})),
            )
                .into_response();
            response.headers_mut().insert(
                header::CONTENT_RANGE,
                format!("bytes */{}", length)
                    .parse()
                    .map_err(|_| Error::Malformed)?,
            );
            return Ok(response);
        }
    };
    let mut response = (
        if requested.is_some() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        },
        Body::from_stream(content.stream(start, end).await?),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        (end - start)
            .to_string()
            .parse()
            .map_err(|_| Error::Malformed)?,
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().expect("constant"),
    );
    response
        .headers_mut()
        .insert(header::ETAG, etag.parse().map_err(|_| Error::Malformed)?);
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, "bytes".parse().expect("constant"));
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "private, no-store".parse().expect("constant"),
    );
    if requested.is_some() {
        response.headers_mut().insert(
            header::CONTENT_RANGE,
            format!("bytes {start}-{}/{}", end - 1, length)
                .parse()
                .map_err(|_| Error::Malformed)?,
        );
    }
    Ok(response)
}
/// Durable operation lookup survives expiration of the temporary upload session.
async fn receipt(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((id, operation)): Path<(String, Uuid)>,
) -> Result<Json<serde_json::Value>, Error> {
    rss_mdm_content_service::service::receipt(&app, &auth.proof, &audit, &id, operation)
        .await
        .map(Json)
        .map_err(Into::into)
}
