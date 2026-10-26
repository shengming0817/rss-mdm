//! HTTP descriptions inferred from the function registered with Axum.
//!
//! This module never invokes a handler or implements request dispatch.
//! ref: axum axum/src/handler/mod.rs@c59208c86fded335cd85e388030ad59347b0e5ae
//! ref: schemars schemars/src/generate.rs@ed6186319d5ebf1959a03f558df375d2bb5c44a6
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use schemars::{JsonSchema, generate::SchemaSettings};
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, future::Future};

/// Direction is part of schema identity: an omitted input need not be an omitted output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Request,
    Response,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Schema {
    pub direction: Direction,
    pub value: Value,
}
impl Schema {
    pub fn request<T: JsonSchema>() -> Self {
        Self::of::<T>(Direction::Request)
    }
    pub fn response<T: JsonSchema>() -> Self {
        Self::of::<T>(Direction::Response)
    }
    /// Schemars uses either enum or oneOf/const when variants carry documentation.
    /// Both describe a closed vocabulary; anything else is a contract error.
    pub fn string_values(&self) -> Vec<Value> {
        fn values(value: &Value) -> Vec<Value> {
            if let Some(items) = value.get("enum").and_then(Value::as_array) {
                assert!(
                    !items.is_empty() && items.iter().all(Value::is_string),
                    "expected a closed string vocabulary"
                );
                return items.clone();
            }
            if let Some(value) = value.get("const").filter(|v| v.is_string()) {
                return vec![value.clone()];
            }
            if let Some(items) = value.get("oneOf").and_then(Value::as_array) {
                assert!(!items.is_empty(), "empty string vocabulary");
                return items.iter().flat_map(values).collect();
            }
            panic!("expected a derived closed string vocabulary")
        }
        let mut result = values(&self.value);
        result.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        result.dedup();
        result
    }
    fn of<T: JsonSchema>(direction: Direction) -> Self {
        let settings = SchemaSettings::draft2020_12();
        let settings = match direction {
            Direction::Request => settings.for_deserialize(),
            Direction::Response => settings.for_serialize(),
        };
        Self {
            direction,
            value: settings
                .into_generator()
                .into_root_schema_for::<T>()
                .to_value(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Representation {
    pub content_type: &'static str,
    pub schema: Schema,
}
impl Representation {
    pub fn json(schema: Schema) -> Self {
        Self {
            content_type: "application/json",
            schema,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Response {
    pub status: u16,
    pub body: Option<Representation>,
    pub headers: BTreeMap<String, Schema>,
}
impl Response {
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            body: None,
            headers: BTreeMap::new(),
        }
    }
    pub fn json<T: JsonSchema>(status: u16) -> Self {
        Self {
            body: Some(Representation::json(Schema::response::<T>())),
            ..Self::empty(status)
        }
    }
    pub fn text(status: u16) -> Self {
        Self {
            body: Some(Representation {
                content_type: "text/plain; charset=utf-8",
                schema: Schema::response::<String>(),
            }),
            ..Self::empty(status)
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Request {
    pub path: Option<Schema>,
    pub query: Option<Schema>,
    pub query_owner: Option<crate::QueryDeclaration>,
    pub body: Option<Representation>,
    pub headers: BTreeMap<String, Schema>,
    pub required_headers: Vec<&'static str>,
    pub rejections: Vec<Response>,
}
impl Request {
    fn merge(&mut self, other: Self) {
        fn slot<T>(target: &mut Option<T>, value: Option<T>, name: &str) {
            if let Some(value) = value {
                assert!(
                    target.replace(value).is_none(),
                    "duplicate HTTP {name} extractor"
                );
            }
        }
        slot(&mut self.path, other.path, "path");
        slot(&mut self.query, other.query, "query");
        slot(&mut self.query_owner, other.query_owner, "query owner");
        slot(&mut self.body, other.body, "body");
        for (name, schema) in other.headers {
            assert!(
                self.headers.insert(name, schema).is_none(),
                "duplicate HTTP header"
            );
        }
        self.rejections.extend(other.rejections);
        self.required_headers.extend(other.required_headers);
        self.required_headers.sort_unstable();
        self.required_headers.dedup();
    }
}

/// Implemented by the *actual* handler argument, not by a separate endpoint DTO list.
pub trait Input {
    fn request() -> Request;
}
/// Implemented alongside the actual IntoResponse projection of a product error/response.
pub trait Output {
    fn responses() -> Vec<Response>;
    fn collection() -> bool {
        false
    }
}

/// An uninterpreted streaming body. Resource ownership, authorization and limits stay at ingress.
pub struct BinaryBody(pub axum::body::Body);
impl<S: Send + Sync> axum::extract::FromRequest<S> for BinaryBody {
    type Rejection = std::convert::Infallible;
    async fn from_request(request: axum::extract::Request, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(request.into_body()))
    }
}
impl Input for BinaryBody {
    fn request() -> Request {
        Request {
            body: Some(Representation {
                content_type: "application/octet-stream",
                schema: Schema {
                    direction: Direction::Request,
                    value: serde_json::json!({"type":"string", "format":"binary"}),
                },
            }),
            ..Request::default()
        }
    }
}

impl<T> Input for State<T> {
    fn request() -> Request {
        Request::default()
    }
}
impl<T> Input for Extension<T> {
    fn request() -> Request {
        Request {
            rejections: vec![Response::text(500)],
            ..Request::default()
        }
    }
}
impl<T> Input for Option<Extension<T>> {
    fn request() -> Request {
        Request::default()
    }
}
impl<T: JsonSchema> Input for Path<T> {
    fn request() -> Request {
        Request {
            path: Some(Schema::request::<T>()),
            rejections: vec![Response::text(400), Response::text(500)],
            ..Request::default()
        }
    }
}
impl<T: JsonSchema> Input for Query<T> {
    fn request() -> Request {
        Request {
            query: Some(Schema::request::<T>()),
            rejections: vec![Response::text(400)],
            ..Request::default()
        }
    }
}
impl<T: JsonSchema> Input for Json<T> {
    fn request() -> Request {
        Request {
            body: Some(Representation::json(Schema::request::<T>())),
            rejections: vec![
                Response::text(400),
                Response::text(413),
                Response::text(415),
                Response::text(422),
            ],
            ..Request::default()
        }
    }
}
// Result<Extractor, Rejection> transfers rejection handling to the handler's actual output.
impl<T: Input, E> Input for Result<T, E> {
    fn request() -> Request {
        let mut request = T::request();
        request.rejections.clear();
        request
    }
}
macro_rules! input_tuples {
    ($head:ident $(, $tail:ident)*) => {
        impl<$head: Input, $($tail: Input),*> Input for ($head, $($tail,)*) {
            fn request() -> Request {
                let mut request = Request::default();
                request.merge($head::request());
                $(request.merge($tail::request());)*
                request
            }
        }
        input_tuples!($($tail),*);
    };
    () => {};
}
input_tuples!(
    A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16
);
impl<T: JsonSchema> Output for Json<T> {
    fn responses() -> Vec<Response> {
        vec![Response::json::<T>(200)]
    }
}
impl<T: Output, E: Output> Output for Result<T, E> {
    fn responses() -> Vec<Response> {
        let mut responses = T::responses();
        responses.extend(E::responses());
        responses
    }
    fn collection() -> bool {
        T::collection()
    }
}
impl<T: Output> Output for crate::CollectionResponse<T> {
    fn responses() -> Vec<Response> {
        T::responses()
    }
    fn collection() -> bool {
        true
    }
}
impl Output for () {
    fn responses() -> Vec<Response> {
        vec![Response::empty(200)]
    }
}
impl Output for std::convert::Infallible {
    fn responses() -> Vec<Response> {
        Vec::new()
    }
}
impl Output for String {
    fn responses() -> Vec<Response> {
        vec![Response::text(200)]
    }
}
impl Output for &'static str {
    fn responses() -> Vec<Response> {
        String::responses()
    }
}

/// A status that participates in both response rendering and its contract.
/// Dynamic statuses must be represented by a product-owned closed response enum.
pub struct WithStatus<const STATUS: u16, T>(pub T);
impl<const STATUS: u16, T: axum::response::IntoResponse> axum::response::IntoResponse
    for WithStatus<STATUS, T>
{
    fn into_response(self) -> axum::response::Response {
        (
            http::StatusCode::from_u16(STATUS).expect("HTTP status constant"),
            self.0,
        )
            .into_response()
    }
}
impl<const STATUS: u16, T: Output> Output for WithStatus<STATUS, T> {
    fn collection() -> bool {
        T::collection()
    }
    fn responses() -> Vec<Response> {
        assert!(
            (200..=599).contains(&STATUS),
            "invalid HTTP response status"
        );
        T::responses()
            .into_iter()
            .map(|mut response| {
                response.status = STATUS;
                response
            })
            .collect()
    }
}

/// A response whose private material must not be stored by HTTP caches.
pub struct NoStore<T>(pub T);
impl<T: axum::response::IntoResponse> axum::response::IntoResponse for NoStore<T> {
    fn into_response(self) -> axum::response::Response {
        let mut response = self.0.into_response();
        response.headers_mut().insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        );
        response
    }
}
impl<T: Output> Output for NoStore<T> {
    fn collection() -> bool {
        T::collection()
    }
    fn responses() -> Vec<Response> {
        T::responses()
            .into_iter()
            .map(|mut response| {
                let mut schema = Schema::response::<String>();
                schema.value["const"] = "no-store".into();
                response.headers.insert("cache-control".into(), schema);
                response
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Signature {
    pub collection: bool,
    pub request: Request,
    pub responses: Vec<Response>,
}
impl Signature {
    fn new<R: Output>(request: Request) -> Self {
        let mut responses = R::responses();
        responses.extend(request.rejections.iter().cloned());
        responses.sort_by(|a, b| {
            (a.status, a.body.as_ref().map(|b| b.content_type))
                .cmp(&(b.status, b.body.as_ref().map(|b| b.content_type)))
        });
        responses.dedup();
        Self {
            collection: R::collection(),
            request,
            responses,
        }
    }
}

/// A structural companion to Axum's Handler. It does not call or wrap the handler.
pub trait ContractHandler<T, S> {
    fn signature() -> Signature;
}
impl<F, Fut, R, S> ContractHandler<((),), S> for F
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = R>,
    R: Output,
{
    fn signature() -> Signature {
        Signature::new::<R>(Request::default())
    }
}
macro_rules! handlers {
    ($head:ident $(, $tail:ident)*) => {
        impl<F, Fut, R, S, M, $head, $($tail),*> ContractHandler<(M, $head, $($tail,)*), S> for F
        where F: FnOnce($head, $($tail),*) -> Fut, Fut: Future<Output = R>, R: Output,
              $head: Input, $($tail: Input,)* {
            fn signature() -> Signature {
                let mut request = Request::default();
                request.merge($head::request());
                $(request.merge($tail::request());)*
                Signature::new::<R>(request)
            }
        }
        handlers!($($tail),*);
    };
    () => {};
}
handlers!(
    A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16
);

/// Description and execution must accept the same Axum handler, arguments and result.
pub fn describe<H, T, S>(_: &H) -> Signature
where
    H: axum::handler::Handler<T, S> + ContractHandler<T, S>,
    T: 'static,
{
    H::signature()
}

impl<T: JsonSchema> Input for axum::Form<T> {
    fn request() -> Request {
        Request {
            body: Some(Representation {
                content_type: "application/x-www-form-urlencoded",
                schema: Schema::request::<T>(),
            }),
            rejections: vec![
                Response::text(400),
                Response::text(413),
                Response::text(415),
                Response::text(422),
            ],
            ..Request::default()
        }
    }
}
