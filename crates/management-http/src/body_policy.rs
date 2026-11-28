//! Management ingress budgets, shared by buffering and Axum JSON extraction.
//! ref: axum axum-core/src/extract/default_body_limit.rs@axum-v0.8.9
use crate::Error;
use axum::http::Method;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyPolicy {
    Buffered(usize),
    Streaming,
    Handler(usize),
}

/// Completion and package publication verify stored streams under the content lifecycle budget.
pub(crate) fn content_owned(route: &str, method: &Method) -> bool {
    matches!(for_route(route, method), BodyPolicy::Streaming)
        || (method == Method::POST
            && matches!(
                route,
                "/api/v1/tenants/{tenant}/resources/{id}/uploads/{upload}/complete"
                    | "/api/v1/tenants/{tenant}/resources/{id}/content/mirror"
                    | "/api/v1/tenants/{tenant}/agent-packages"
                    | "/api/v1/tenants/{tenant}/agent-packages/uploads/{id}"
            ))
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BodyLimits {
    default_bytes: usize,
    routes: Vec<RouteLimit>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteLimit {
    method: String,
    path: String,
    bytes: usize,
    mode: Mode,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Buffered,
    Streaming,
    Handler,
}

/// Product request limits exported unchanged with each host's gateway facts.
pub fn body_limits() -> &'static BodyLimits {
    static LIMITS: std::sync::LazyLock<BodyLimits> = std::sync::LazyLock::new(|| {
        serde_json::from_str(include_str!("body_limits.json"))
            .expect("compiled management body limits")
    });
    &LIMITS
}
impl BodyLimits {
    pub(crate) fn default_bytes(&self) -> usize {
        self.default_bytes
    }
    /// A large body starts only when there is also room for a same-sized decode.
    pub(crate) fn reservation(wire_bytes: usize) -> usize {
        wire_bytes
            .checked_mul(2)
            .expect("compiled management body capacity")
    }
    pub fn largest_buffer(&self) -> usize {
        self.routes
            .iter()
            .filter(|r| !matches!(r.mode, Mode::Streaming))
            .map(|r| Self::reservation(r.bytes))
            .max()
            .unwrap_or(self.default_bytes)
    }
}
pub(crate) fn for_route(route: &str, method: &Method) -> BodyPolicy {
    let limits = body_limits();
    let Some(rule) = limits
        .routes
        .iter()
        .find(|r| r.method == method.as_str() && r.path == route)
    else {
        return BodyPolicy::Buffered(limits.default_bytes);
    };
    match rule.mode {
        Mode::Buffered => BodyPolicy::Buffered(rule.bytes),
        Mode::Streaming => BodyPolicy::Streaming,
        Mode::Handler => BodyPolicy::Handler(rule.bytes),
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
    use axum::body::{Bytes, HttpBody};
    use futures::StreamExt;
    let exact = body
        .size_hint()
        .exact()
        .and_then(|n| usize::try_from(n).ok());
    if exact.is_some_and(|n| n > limit) {
        return Err(Error::RequestTooLarge);
    }
    let capacity = exact.unwrap_or(limit);
    let read = async move {
        let mut stream = body.into_data_stream();
        let mut bytes = Vec::with_capacity(capacity);
        while let Some(frame) = stream.next().await {
            let chunk = frame.map_err(|e| read_error(&e))?;
            if chunk.len() > capacity - bytes.len() {
                return Err(Error::RequestTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok::<_, Error>(Bytes::from(bytes))
    };
    let bytes = if let Some(control) = parts.extensions.get::<rss_axum::RequestControl>() {
        use rss_request_context::CancellationObserver;
        tokio::select! {
            biased;
            () = control.cancelled() => return Err(Error::RequestDeadline),
            result = tokio::time::timeout_at(control.deadline().instant().into(), read) =>
                result.map_err(|_| Error::RequestDeadline)?,
        }
    } else if let Some(deadline) = parts.extensions.get::<rss_request_context::Deadline>() {
        tokio::time::timeout_at(deadline.instant().into(), read)
            .await
            .map_err(|_| Error::RequestDeadline)?
    } else {
        read.await
    }?;
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

    #[test]
    fn gateway_uses_domain_envelope_sizes() {
        for (path, expected) in [
            (
                "/api/v1/tenants/{tenant}/software/source-snapshots/{source}",
                rss_mdm_software_service::source_snapshots::MAX_REQUEST_BYTES,
            ),
            (
                "/api/v1/tenants/{tenant}/devices/{id}/inventory-scopes",
                rss_mdm_inventory_service::assets::windows::MAX_PAGE_BODY_BYTES,
            ),
        ] {
            assert_eq!(
                for_route(path, &Method::POST),
                BodyPolicy::Buffered(expected)
            );
        }
    }

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

    #[tokio::test]
    async fn mounted_policy_inputs_accept_complete_scope_definitions() {
        use crate::planning::policies::http;
        use rss_mdm_http_contract::Operation;
        let routes = http::register(None, None)
            .into_endpoints()
            .into_iter()
            .chain(http::register_previews(None).into_endpoints());
        let definition = serde_json::json!({"targets":(1..=300).map(|i|serde_json::json!({"kind":"group","id":uuid::Uuid::from_u128(i)})).collect::<Vec<_>>(),"limitations":null,"exclusions":[]});
        let raw = serde_json::to_vec(&definition).unwrap();
        assert!(raw.len() > 16 * 1024);
        let mut tested = 0;
        for endpoint in routes.filter(|e| {
            e.method == "POST"
                && (e.operations.contains(&Operation::Update) || e.path.ends_with("/previews"))
        }) {
            let path = format!("/api/v1/tenants/{{tenant}}{}", endpoint.path);
            let BodyPolicy::Buffered(limit) = for_route(&path, &Method::POST) else {
                panic!("buffered Policy input")
            };
            let mut request = buffer(Request::new(Body::from(raw.clone())), limit)
                .await
                .unwrap();
            request
                .headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
            assert_eq!(
                Json::<serde_json::Value>::from_request(request, &())
                    .await
                    .unwrap()
                    .0,
                definition
            );
            tested += 1;
        }
        assert_eq!(
            tested, 4,
            "Policy write, Action preview and both Scope previews"
        );
    }

    #[test]
    fn budgets_match_methods_and_matched_paths() {
        assert!(content_owned(
            "/api/v1/tenants/{tenant}/agent-packages",
            &Method::POST
        ));
        assert!(!content_owned(
            "/api/v1/tenants/{tenant}/agent-packages",
            &Method::GET
        ));
        assert!(content_owned(
            "/api/v1/tenants/{tenant}/agent-packages/uploads/{id}",
            &Method::POST
        ));
        assert!(!content_owned(
            "/api/v1/tenants/{tenant}/agent-packages/uploads/{id}",
            &Method::GET
        ));
        assert_eq!(
            for_route("/api/v1/tenants/{tenant}/agent-packages", &Method::POST),
            BodyPolicy::Buffered(1024 * 1024)
        );
        assert_eq!(
            for_route("/api/v1/tenants/{tenant}/policies/{policy}", &Method::POST),
            BodyPolicy::Buffered(8 * 1024 * 1024)
        );
        assert_eq!(
            for_route("/api/v1/tenants/{tenant}/policies/{policy}", &Method::PUT),
            BodyPolicy::Buffered(16 * 1024)
        );
        assert_eq!(
            for_route("/api/v1/tenants/{tenant}/pki/crls", &Method::POST),
            BodyPolicy::Buffered(64 * 1024 * 1024)
        );
        assert_eq!(
            for_route(
                "/api/v1/tenants/{tenant}/resources/{id}/content",
                &Method::POST
            ),
            BodyPolicy::Streaming
        );
        assert_eq!(
            for_route(
                "/api/v1/tenants/{tenant}/resources/{id}/content",
                &Method::PATCH
            ),
            BodyPolicy::Buffered(16 * 1024)
        );
        assert_eq!(
            for_route(
                "/api/v1/tenants/{tenant}/resources/{id}/uploads/{upload}",
                &Method::PATCH
            ),
            BodyPolicy::Streaming
        );
    }
}
