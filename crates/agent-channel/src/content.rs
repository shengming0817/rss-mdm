use crate::Error;
use axum::body::Body;
pub(crate) async fn response(
    content: rss_mdm_content_service::Verified,
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

pub(crate) struct DownloadHeaders(pub axum::http::HeaderMap);
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
        use rss_mdm_http_contract::signature::{Request, Schema};
        Request {
            headers: [
                ("range".into(), Schema::request::<String>()),
                ("if-range".into(), Schema::request::<String>()),
            ]
            .into(),
            ..Request::default()
        }
    }
}
