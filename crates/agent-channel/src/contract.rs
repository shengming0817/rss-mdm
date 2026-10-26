//! Descriptions share the runtime error projection and authentication owner.
use crate::{AgentError, wire};
use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, request::Parts},
};
use rss_mdm_http_contract::signature::{Direction, Input, Output, Request, Response, Schema};
use std::convert::Infallible;

/// The original headers passed to runtime device authentication, never a bearer identity.
pub(crate) struct RuntimeHeaders(pub HeaderMap);
impl<S: Send + Sync> FromRequestParts<S> for RuntimeHeaders {
    type Rejection = Infallible;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl Input for RuntimeHeaders {
    fn request() -> Request {
        // authenticate() rejects any Authorization header; the peer certificate is transport-owned.
        Request {
            headers: [(
                "authorization".into(),
                Schema {
                    direction: Direction::Request,
                    value: false.into(),
                },
            )]
            .into(),
            ..Request::default()
        }
    }
}

impl Output for AgentError {
    fn responses() -> Vec<Response> {
        let codes = Schema::response::<wire::ErrorCode>();
        codes
            .string_values()
            .iter()
            .map(|value| {
                let code: wire::ErrorCode =
                    serde_json::from_value(value.clone()).expect("actual runtime error code");
                let mut response =
                    Response::json::<wire::ErrorBody>(crate::status_for(code).as_u16());
                response
                    .body
                    .as_mut()
                    .expect("JSON error body")
                    .schema
                    .value["properties"]["code"]["const"] = value.clone();
                response
            })
            .collect()
    }
}
impl Output for crate::Error {
    fn responses() -> Vec<Response> {
        AgentError::responses()
    }
}

pub(crate) trait BodyDecoder {
    type Value: schemars::JsonSchema;
    fn decode(
        bytes: axum::body::Bytes,
        headers: &HeaderMap,
        limit: usize,
    ) -> Result<Decoded<Self::Value>, AgentError>;
    fn request() -> Request {
        use rss_mdm_http_contract::signature::Representation;
        Request {
            body: Some(Representation::json(Schema::request::<Self::Value>())),
            ..Request::default()
        }
    }
}
pub(crate) struct Decoded<T> {
    pub value: T,
    pub bytes: usize,
}
pub(crate) struct Buffered<D> {
    bytes: axum::body::Bytes,
    decoder: std::marker::PhantomData<fn() -> D>,
}
impl<D: BodyDecoder> Buffered<D> {
    pub fn decode(
        self,
        headers: &HeaderMap,
        limit: usize,
    ) -> Result<Decoded<D::Value>, AgentError> {
        D::decode(self.bytes, headers, limit)
    }
}
impl<D: BodyDecoder, S: Send + Sync> axum::extract::FromRequest<S> for Buffered<D> {
    type Rejection = axum::extract::rejection::BytesRejection;
    async fn from_request(
        request: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self {
            bytes: axum::body::Bytes::from_request(request, state).await?,
            decoder: std::marker::PhantomData,
        })
    }
}
impl<D: BodyDecoder> Input for Buffered<D> {
    fn request() -> Request {
        let mut request = D::request();
        request
            .rejections
            .extend([Response::text(400), Response::text(413)]);
        request
    }
}
