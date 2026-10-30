//! Deferred query decoding preserves the ingress owner's authorization/error ordering.
use crate::{
    QueryDeclaration,
    signature::{Input, Request, Schema},
};
use serde_json::json;
use std::{convert::Infallible, marker::PhantomData};

/// Implemented at ingress, delegating parsing and the description to the same business owner.
/// Domain crates do not depend on HTTP to expose their existing parser.
pub trait QueryOwner {
    type Parsed;
    type Error;
    fn declaration() -> Option<QueryDeclaration>;
    fn parameters() -> Schema;
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error>;
}

pub trait DirectoryOwner {
    fn schema() -> &'static rss_mdm_query::directory::Schema;
    fn parse(raw: &str) -> rss_mdm_query::Result<rss_mdm_query::directory::Query> {
        Self::schema().parse(raw)
    }
}
pub trait WindowOwner {
    fn schema() -> &'static rss_mdm_query::window::Schema;
    fn max_cursor_bytes() -> usize {
        4096
    }
    fn max_raw_query_bytes() -> usize {
        rss_mdm_query::MAX_RAW_QUERY_BYTES
    }
}
pub struct Directory<Q>(PhantomData<fn() -> Q>);
pub struct Statistics<Q>(PhantomData<fn() -> Q>);
pub struct Window<Q>(PhantomData<fn() -> Q>);

fn page_parameters(default_limit: u16, max_limit: u16) -> serde_json::Value {
    json!({"$schema":"https://json-schema.org/draft/2020-12/schema", "type":"object",
        "properties": {
            "limit":{"type":"integer", "minimum":1, "maximum":max_limit, "default":default_limit},
            "cursor":{"type":"string", "minLength":1}
        }, "additionalProperties":false})
}
impl<Q: DirectoryOwner> QueryOwner for Directory<Q> {
    type Parsed = rss_mdm_query::directory::Query;
    type Error = rss_mdm_query::Error;
    fn declaration() -> Option<QueryDeclaration> {
        Some(QueryDeclaration::Directory(Q::schema()))
    }
    fn parameters() -> Schema {
        let owner = Q::schema();
        directory_parameters(owner.default_limit, owner.max_limit)
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        let query = Q::parse(raw)?;
        query.require_schema(Q::schema())?;
        Ok(query)
    }
}
impl<Q: WindowOwner> QueryOwner for Window<Q> {
    type Parsed = (
        rss_mdm_query::window::Query,
        std::collections::BTreeMap<String, String>,
    );
    type Error = rss_mdm_query::Error;
    fn declaration() -> Option<QueryDeclaration> {
        Some(QueryDeclaration::Window(Q::schema()))
    }
    fn parameters() -> Schema {
        let owner = Q::schema();
        let mut value = page_parameters(owner.default_limit, owner.max_limit);
        value["properties"]["cursor"]["maxLength"] = json!(Q::max_cursor_bytes());
        // Context is returned as decoded strings by the window owner, without coercion.
        for parameter in owner.context {
            value["properties"][parameter] = json!({"type":"string"});
        }
        Schema {
            direction: crate::signature::Direction::Request,
            value,
        }
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        Q::schema().parse_with_budgets(raw, Q::max_raw_query_bytes(), Q::max_cursor_bytes())
    }
}

/// Extraction only captures the original query. The handler chooses when to parse it.
/// The raw input is private so callers cannot accidentally parse it with a different catalog.
pub struct OwnedQuery<Q> {
    raw: String,
    owner: PhantomData<fn() -> Q>,
}
impl<Q: QueryOwner> OwnedQuery<Q> {
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
    pub fn parse(self) -> Result<Q::Parsed, Q::Error> {
        Q::parse(&self.raw)
    }
}
impl<S: Send + Sync, Q> axum::extract::FromRequestParts<S> for OwnedQuery<Q> {
    type Rejection = Infallible;
    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self {
            raw: parts.uri.query().unwrap_or_default().to_owned(),
            owner: PhantomData,
        })
    }
}
impl<Q: QueryOwner> Input for OwnedQuery<Q> {
    fn request() -> Request {
        Request {
            query: Some(Q::parameters()),
            query_owner: Q::declaration(),
            ..Request::default()
        }
    }
}

impl<Q: DirectoryOwner> QueryOwner for Statistics<Q> {
    type Parsed = rss_mdm_query::directory::Query;
    type Error = rss_mdm_query::Error;
    fn declaration() -> Option<QueryDeclaration> {
        Some(QueryDeclaration::Directory(Q::schema()))
    }
    fn parameters() -> Schema {
        Schema {
            direction: crate::signature::Direction::Request,
            value: json!({
                "$schema":"https://json-schema.org/draft/2020-12/schema", "type":"object",
                "properties":{"filter":{"type":"string"}}, "additionalProperties":false
            }),
        }
    }
    fn parse(raw: &str) -> Result<Self::Parsed, Self::Error> {
        Q::schema().statistics(raw)
    }
}

/// Shared URL encoding of directory parameters; the owner still binds the field catalog.
pub fn directory_parameters(default_limit: u16, max_limit: u16) -> Schema {
    let mut value = page_parameters(default_limit, max_limit);
    for name in ["filter", "sort", "fields"] {
        value["properties"][name] = json!({"type":"string"});
    }
    Schema {
        direction: crate::signature::Direction::Request,
        value,
    }
}
/// Common page coordinates for custom window owners.
pub fn window_parameters(owner: &'static rss_mdm_query::window::Schema) -> Schema {
    Schema {
        direction: crate::signature::Direction::Request,
        value: page_parameters(owner.default_limit, owner.max_limit),
    }
}
