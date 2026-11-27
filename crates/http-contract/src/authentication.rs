//! Transport declarations supplied by the middleware owner, never authentication execution.
use crate::signature::Schema;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
pub struct Description {
    pub owner: &'static str,
    /// Responses emitted before the declared handler is entered.
    pub rejections: Vec<crate::signature::Response>,
    /// Exactly one credential presentation is accepted; mixing presentations is rejected.
    pub alternatives: Vec<Credential>,
    pub conditional_response_headers: Vec<ConditionalHeader>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Credential {
    pub kind: &'static str,
    pub owner: &'static str,
    pub headers: BTreeMap<String, Schema>,
    pub required_headers: Vec<&'static str>,
    pub constraints: Vec<&'static str>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ConditionalHeader {
    pub status: u16,
    pub name: &'static str,
    pub value: &'static str,
    pub request_header_present: &'static str,
    pub request_headers_absent: Vec<&'static str>,
}

/// Identity credential presentations described by the executing browser middleware.
pub fn identity_credentials(method: &str, bearer: bool, api_key: bool) -> Vec<Credential> {
    use crate::signature::{Direction, Schema};
    fn header(value: serde_json::Value) -> Schema {
        Schema {
            direction: Direction::Request,
            value,
        }
    }
    let mut cookie = Credential {
        kind: "cookie", owner: "rss-identity-web-credentials::authenticate_request",
        headers: [("cookie".into(), header(serde_json::json!({"type":"string", "description":"Contains exactly one __Host-identity-session cookie"})))].into(),
        required_headers: vec!["cookie"], constraints: vec!["authorization and x-api-key must be absent"],
    };
    if method != "GET" && method != "HEAD" {
        cookie.headers.extend([
            ("origin".into(), header(serde_json::json!({"type":"string", "format":"uri", "description":"Must equal the configured Identity HTTPS origin"}))),
            ("x-identity-request".into(), header(serde_json::json!({"type":"string", "const":"1"}))),
            ("x-csrf-token".into(), header(serde_json::json!({"type":"string", "description":"CSRF proof bound to the presented session credential"}))),
        ]);
        cookie
            .required_headers
            .extend(["origin", "x-identity-request", "x-csrf-token"]);
    }
    let mut credentials = vec![cookie];
    if bearer || api_key {
        for (kind, name, owner, description) in [
            (
                "bearer",
                "authorization",
                "rss-identity-web-credentials::authenticate_bearer_request",
                "Bearer session credential",
            ),
            (
                "api_key",
                "x-api-key",
                "authorization-service::Store::authenticate_key",
                "Product API key secret",
            ),
        ] {
            if kind == "api_key" && !api_key || kind == "bearer" && !bearer {
                continue;
            }
            credentials.push(Credential {
                kind, owner,
                headers: [(name.into(), header(serde_json::json!({"type":"string", "description":description})))].into(),
                required_headers: vec![name],
                constraints: vec!["exactly one credential header; no other credential header or __Host-identity-session/__Host-identity-csrf cookie", "trusted client address must satisfy the current API source network policy"],
            });
        }
    }
    credentials
}

/// Fixed Cookie/Bearer authentication boundary of the pinned Identity SDK.
/// ref: rss-identity 1d3ebac9 identity-http-axum/src/{lib,bearer,boundary}.rs
pub fn identity_rejections() -> Vec<crate::signature::Response> {
    use crate::signature::{Direction, Representation, Response, Schema};
    use serde_json::json;
    [
        (400, "malformed_request"),
        (401, "invalid_credential"),
        (403, "csrf_rejected"),
        (429, "rate_limited"),
        (503, "identity_unavailable"),
    ]
    .into_iter()
    .map(|(status, code)| {
        let mut response = Response::empty(status);
        response.body = Some(Representation::json(Schema {
            direction: Direction::Response,
            value: json!({"type":"object","properties":{"code":{"type":"string","const":code}},"required":["code"],"additionalProperties":false}),
        }));
        response.headers.insert("referrer-policy".into(), Schema {direction: Direction::Response, value: json!({"const":"no-referrer"})});
        if status == 429 {
            response.headers.insert(
                "retry-after".into(),
                Schema {
                    direction: Direction::Response,
                    value: json!({"type":"string","pattern":"^[1-9][0-9]{0,9}$"}),
                },
            );
        }
        response
    })
    .collect()
}
