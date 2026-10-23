//! Management ingress budgets, shared by buffering and Axum JSON extraction.
//! ref: axum axum-core/src/extract/default_body_limit.rs@axum-v0.8.9
use crate::Error;
use axum::http::Method;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyPolicy {
    Buffered(usize),
    Streaming,
}

/// Completion and package publication verify stored streams under the content lifecycle budget.
pub(crate) fn content_owned(route: &str, method: &Method) -> bool {
    matches!(for_route(route, method), BodyPolicy::Streaming)
        || (method == Method::POST
            && matches!(
                route,
                "/api/v1/resources/{id}/uploads/{upload}/complete"
                    | "/api/v1/resources/{id}/content/mirror"
                    | "/api/v1/agent-packages"
            ))
}

pub(crate) fn for_route(route: &str, method: &Method) -> BodyPolicy {
    use BodyPolicy::{Buffered, Streaming};
    match (method.as_str(), route) {
        ("POST", "/api/v1/resources/{id}/content")
        | ("PATCH", "/api/v1/resources/{id}/uploads/{upload}") => Streaming,
        (
            "POST",
            "/api/v1/policies/{id}" | "/api/v1/policies/previews" | "/api/v1/resources/{id}",
        ) => Buffered(8 * 1024 * 1024),
        ("POST", "/api/v1/devices/{device}/operations") => Buffered(16 * 1024 * 1024),
        ("POST", "/api/v1/pki/rotations" | "/api/v1/pki/crls") => Buffered(64 * 1024 * 1024),
        ("POST", "/api/v1/pki/signing/recover" | "/api/v1/agent-issuances/{id}/recover") => {
            Buffered(256 * 1024)
        }
        ("PUT", "/api/v1/windows/entra-policy") => Buffered(128 * 1024),
        ("POST", "/api/v1/certificate-archive/import")
        | (
            "PUT",
            "/api/v1/authorization/rules/{id}"
            | "/api/v1/authorization/user-groups/{id}"
            | "/api/v1/tenant-administration/authorization/rules/{id}",
        ) => Buffered(2 * 1024 * 1024),
        (
            "POST",
            "/api/v1/agent-packages"
            | "/api/v1/agent-packages/{id}/withdraw"
            | "/api/v1/software/imports"
            | "/api/v1/software/sources/{id}/revisions/{revision}"
            | "/api/v1/software/resources/{id}/versions/{version}",
        ) => Buffered(1024 * 1024),
        (_, path) if path.starts_with("/api/v1/apple/materials/") => Buffered(256 * 1024),
        (_, path) if path.starts_with("/api/v1/apple/organizations") => Buffered(256 * 1024),
        _ => Buffered(16 * 1024),
    }
}

pub(crate) fn read_error(error: &axum::Error) -> Error {
    use std::error::Error as _;
    let mut cause = error.source();
    while let Some(error) = cause {
        if error.is::<http_body_util::LengthLimitError>() {
            return Error::RequestTooLarge;
        }
        cause = error.source();
    }
    Error::Malformed
}

/// Bound the actual stream, then configure the extractor with exactly the same budget.
pub(crate) async fn buffer(
    request: axum::extract::Request,
    limit: usize,
) -> Result<axum::extract::Request, Error> {
    let (parts, body) = request.into_parts();
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        axum::body::to_bytes(body, limit),
    )
    .await
    .map_err(|_| Error::Unavailable(crate::Failure::RequestDeadline))?
    .map_err(|error| read_error(&error))?;
    let mut request = axum::extract::Request::from_parts(parts, axum::body::Body::from(bytes));
    axum::extract::DefaultBodyLimit::max(limit).apply(&mut request);
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json,
        body::Body,
        extract::{FromRequest, Request},
        response::IntoResponse,
    };

    #[tokio::test]
    async fn buffering_and_json_share_the_actual_stream_limit() {
        for length in [7, 8, 9] {
            // Valid JSON whose wire size is exactly the chosen length, with no Content-Length.
            let raw = format!("\"{}\"", "a".repeat(length - 2));
            let chunks = futures::stream::iter(
                raw.into_bytes()
                    .into_iter()
                    .map(|b| Ok::<_, std::io::Error>(vec![b])),
            );
            let request = Request::new(Body::from_stream(chunks));
            let result = buffer(request, 8).await;
            if length > 8 {
                assert!(matches!(result, Err(Error::RequestTooLarge)));
                continue;
            }
            let mut request = result.unwrap();
            request
                .headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
            assert!(Json::<String>::from_request(request, &()).await.is_ok());
        }
        // An outer default must not reintroduce a second, smaller extraction limit.
        let mut request = Request::new(Body::from("\"abcd\""));
        axum::extract::DefaultBodyLimit::max(4).apply(&mut request);
        let mut request = buffer(request, 6).await.unwrap();
        request
            .headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        assert!(Json::<String>::from_request(request, &()).await.is_ok());
    }

    #[tokio::test]
    async fn rejection_projection_distinguishes_length_syntax_and_io() {
        for (body, limit, status) in [("\"abcd\"", 4, 413), ("{", 4, 400)] {
            let mut request = Request::new(Body::from(body));
            request
                .headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
            axum::extract::DefaultBodyLimit::max(limit).apply(&mut request);
            let error = Json::<serde_json::Value>::from_request(request, &())
                .await
                .unwrap_err();
            assert_eq!(Error::from(error).into_response().status().as_u16(), status);
        }
        let stream = futures::stream::once(async {
            Err::<Vec<u8>, _>(std::io::Error::other("read failed"))
        });
        assert!(matches!(
            buffer(Request::new(Body::from_stream(stream)), 8).await,
            Err(Error::Malformed)
        ));
    }

    #[test]
    fn budgets_match_methods_and_matched_paths() {
        assert!(content_owned("/api/v1/agent-packages", &Method::POST));
        assert!(!content_owned("/api/v1/agent-packages", &Method::GET));
        assert_eq!(
            for_route("/api/v1/agent-packages", &Method::POST),
            BodyPolicy::Buffered(1024 * 1024)
        );
        assert_eq!(
            for_route("/api/v1/policies/{id}", &Method::POST),
            BodyPolicy::Buffered(8 * 1024 * 1024)
        );
        assert_eq!(
            for_route("/api/v1/policies/{id}", &Method::PUT),
            BodyPolicy::Buffered(16 * 1024)
        );
        assert_eq!(
            for_route("/api/v1/pki/crls", &Method::POST),
            BodyPolicy::Buffered(64 * 1024 * 1024)
        );
        assert_eq!(
            for_route("/api/v1/resources/{id}/content", &Method::POST),
            BodyPolicy::Streaming
        );
        assert_eq!(
            for_route("/api/v1/resources/{id}/content", &Method::PATCH),
            BodyPolicy::Buffered(16 * 1024)
        );
        assert_eq!(
            for_route("/api/v1/resources/{id}/uploads/{upload}", &Method::PATCH),
            BodyPolicy::Streaming
        );
    }
}
