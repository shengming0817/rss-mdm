use crate::Error;
use axum::{Json, body::Body, http::StatusCode};
pub(crate) async fn response(
    content: rss_mdm_content_service::Verified,
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
    let (start, end) = match rss_mdm_content_service::range(requested, length) {
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
