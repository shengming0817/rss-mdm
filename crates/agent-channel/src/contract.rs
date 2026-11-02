//! Descriptions share the runtime error projection and authentication owner.
use crate::AgentError;
use axum::http::HeaderMap;
use rss_mdm_http_contract::signature::{Input, Output, Request, Response, Schema};

pub use rss_mdm_http_contract::agent::RuntimeHeaders;
impl Output for AgentError {
    fn responses() -> Vec<Response> {
        rss_mdm_http_contract::agent::responses()
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
