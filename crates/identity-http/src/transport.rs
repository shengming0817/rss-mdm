//! Deferred body extraction preserves credential checks before body decoding.
use axum::{
    extract::{FromRequest, FromRequestParts, Request},
    http::{HeaderMap, HeaderValue, request::Parts},
    response::{IntoResponse, Response},
};
use rss_mdm_http_contract::signature::{
    Input, Output, Representation, Request as Signature, Response as Reply, Schema,
};
use schemars::JsonSchema;
use serde::Serialize;
use std::{convert::Infallible, marker::PhantomData};

pub(crate) const PASSIVE: u8 = 0;
pub(crate) const WRITE: u8 = 1;
pub(crate) const LOGIN: u8 = 2;
pub(crate) const ROTATE: u8 = 3;
pub(crate) const PROGRAM_LOGIN: u8 = 4;
pub(crate) const PROGRAM_LOGOUT: u8 = 5;
pub(crate) const CALLBACK: u8 = 6;

pub(crate) struct Headers<const MODE: u8>(pub HeaderMap);
impl<S: Send + Sync, const MODE: u8> FromRequestParts<S> for Headers<MODE> {
    type Rejection = Infallible;
    async fn from_request_parts(p: &mut Parts, _: &S) -> Result<Self, Infallible> {
        Ok(Self(p.headers.clone()))
    }
}
impl<const MODE: u8> Input for Headers<MODE> {
    fn request() -> Signature {
        let mut request = Signature::default();
        let mut add = |key: &'static str, required, constraint: serde_json::Value| {
            let mut schema = Schema::request::<String>();
            schema.value = constraint;
            request.headers.insert(key.to_owned(), schema);
            if required {
                request.required_headers.push(key)
            }
        };
        let string = || serde_json::json!({"type":"string"});
        if MODE == PROGRAM_LOGOUT {
            add("authorization", true, string());
        }
        if !matches!(MODE, PROGRAM_LOGIN | PROGRAM_LOGOUT) {
            add(
                "cookie",
                MODE != LOGIN,
                if MODE == CALLBACK {
                    serde_json::json!({"type":"string","description":"Browser-bound OIDC cookie and original session when present"})
                } else {
                    string()
                },
            );
        }
        if matches!(MODE, WRITE | LOGIN | ROTATE) {
            add(
                "origin",
                true,
                serde_json::json!({"type":"string","format":"uri"}),
            );
            add("x-csrf-token", MODE != LOGIN, string());
            if MODE != ROTATE {
                add("x-identity-request", true, serde_json::json!({"const":"1"}));
            }
        }
        request
    }
}
pub(crate) struct Deferred<T, const MODE: u8>(pub Request, pub PhantomData<fn() -> T>);
impl<T, const MODE: u8, S: Send + Sync> FromRequest<S> for Deferred<T, MODE> {
    type Rejection = Infallible;
    async fn from_request(request: Request, _: &S) -> Result<Self, Infallible> {
        Ok(Self(request, PhantomData))
    }
}
impl<T: JsonSchema, const MODE: u8> Input for Deferred<T, MODE> {
    fn request() -> Signature {
        Signature {
            body: Some(Representation::json(Schema::request::<T>())),
            ..Headers::<MODE>::request()
        }
    }
}

pub struct CookieJson<T> {
    pub body: T,
    pub cookie: Option<HeaderValue>,
}
impl<T: Serialize> IntoResponse for CookieJson<T> {
    fn into_response(self) -> Response {
        let mut response = axum::Json(self.body).into_response();
        if let Some(cookie) = self.cookie {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, cookie);
        }
        response
    }
}
impl<T: JsonSchema> Output for CookieJson<T> {
    fn responses() -> Vec<Reply> {
        let mut r = Reply::json::<T>(200);
        r.headers
            .insert("set-cookie".into(), Schema::response::<String>());
        vec![r]
    }
}
pub(crate) struct SignedOut(pub HeaderValue);
impl IntoResponse for SignedOut {
    fn into_response(self) -> Response {
        (
            axum::http::StatusCode::NO_CONTENT,
            [(axum::http::header::SET_COOKIE, self.0)],
        )
            .into_response()
    }
}
impl Output for SignedOut {
    fn responses() -> Vec<Reply> {
        let mut r = Reply::empty(204);
        r.headers
            .insert("set-cookie".into(), Schema::response::<String>());
        vec![r]
    }
}
