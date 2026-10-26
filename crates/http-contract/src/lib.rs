//! Product route ownership. Axum remains the only dispatcher and middleware implementation.
pub mod artifact;
pub mod catalog;
pub mod collections;
pub mod download;
pub mod query;
mod router;
pub mod routing;
pub mod signature;
pub mod validation;
pub use router::Router;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Operation {
    List,
    Get,
    Create,
    Update,
    Delete,
    Lifecycle,
    Action,
    Query,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Category {
    Mutable,
    Versioned,
    Signed,
    Projection,
    Facts,
    ReadModel,
    Singleton,
    Command,
    Protocol,
    Download,
    Health,
}
impl Category {
    pub fn required(self) -> &'static [Operation] {
        use Operation::*;
        match self {
            Self::Mutable => &[List, Get, Create, Update, Delete],
            Self::Versioned => &[List, Get, Create, Update, Lifecycle],
            Self::Signed => &[List, Get, Create, Lifecycle],
            Self::Projection => &[List, Get],
            Self::Facts => &[List],
            Self::ReadModel => &[Get],
            Self::Singleton => &[Get, Update],
            Self::Command | Self::Protocol | Self::Download | Self::Health => &[Action],
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Resource {
    pub id: &'static str,
    pub category: Category,
    pub owner: &'static str,
    pub proof: &'static str,
    pub query: QueryPolicy,
    pub collection: Option<&'static collections::Description>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum QueryPolicy {
    Unified,
    ResourceV1,
    SourceCatalog,
    Protocol,
    NotCollection,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "kind", content = "schema", rename_all = "snake_case")]
pub enum QueryDeclaration {
    Directory(&'static rss_mdm_query::directory::Schema),
    Window(&'static rss_mdm_query::window::Schema),
    Catalog(&'static rss_mdm_query::CatalogQuery),
}
impl QueryDeclaration {
    pub fn id(self) -> &'static str {
        match self {
            Self::Directory(s) => s.id,
            Self::Window(s) => s.id,
            Self::Catalog(s) => s.id,
        }
    }
    fn valid(self) -> bool {
        match self {
            Self::Directory(s) => s.parse("").is_ok(),
            Self::Window(s) => s.parse("").is_ok(),
            Self::Catalog(s) => {
                !s.catalog_resource.is_empty() && s.max_fields > 0 && s.max_sort > 0
            }
        }
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", content = "description", rename_all = "snake_case")]
pub enum EndpointContract {
    Product(signature::Signature),
    External(ExternalProtocol),
}
/// Existing native protocol owners. This is not an exemption for their self-owned JSON APIs.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalProtocol {
    AppleMdm,
    WindowsMdm,
    SoftwareRepository,
}
impl ExternalProtocol {
    fn accepts(self, resource: &Resource) -> bool {
        let owner = match self {
            Self::AppleMdm => "apple-channel",
            Self::WindowsMdm => "windows-channel",
            Self::SoftwareRepository => "management-http",
        };
        resource.owner == owner
            && matches!(resource.category, Category::Protocol | Category::Download)
    }
}

/// A deployment UUID inserted into a static route, not a handler Path extractor.
#[derive(Clone, Debug, Serialize)]
pub struct ConfiguredSegment {
    pub name: &'static str,
    pub source: &'static str,
}
impl ConfiguredSegment {
    pub fn schema(&self) -> signature::Schema {
        signature::Schema::request::<uuid::Uuid>()
    }
    pub(crate) fn capture(&self) -> String {
        format!("{{{}}}", self.name)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Endpoint {
    pub path: String,
    pub method: &'static str,
    pub resource: &'static Resource,
    pub operations: &'static [Operation],
    pub query: Option<QueryDeclaration>,
    pub contract: EndpointContract,
    pub operation_id: String,
    pub conditions: Vec<&'static str>,
    pub configured_path: Option<ConfiguredSegment>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    Missing(String, Operation),
    Duplicate(String, String),
    DuplicateResource(String),
    Orphan(String),
    Unknown(String),
    MissingQuery(String),
    InvalidQueryDescription(String),
    MisclassifiedCollection(String),
}
/// The expected resource set is independent from the endpoints; deleting both a list and
/// its descriptor cannot erase its resource's required operation.
pub fn validate(endpoints: &[Endpoint], expected: &[&Resource]) -> Vec<Violation> {
    let mut violations = validate_ownership(endpoints, expected);
    for endpoint in endpoints {
        if let EndpointContract::Product(signature) = &endpoint.contract
            && signature.collection != endpoint.operations.contains(&Operation::List)
        {
            violations.push(Violation::MisclassifiedCollection(endpoint.path.clone()));
        }
        if endpoint.resource.query == QueryPolicy::Unified
            && (endpoint.operations.contains(&Operation::List)
                || (endpoint.resource.collection.is_none()
                    && endpoint.operations.contains(&Operation::Create)))
            && !endpoint
                .query
                .is_some_and(|s| s.id() == endpoint.resource.id && s.valid())
        {
            violations.push(Violation::MissingQuery(endpoint.resource.id.into()));
        }
    }
    violations
}
/// Static registration proves ownership; mounted descriptors additionally prove field binding.
pub fn validate_ownership(endpoints: &[Endpoint], expected: &[&Resource]) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut resources = BTreeSet::new();
    for resource in expected {
        if !resources.insert(resource.id) {
            violations.push(Violation::DuplicateResource(resource.id.into()));
        }
    }
    let mut paths = BTreeSet::new();
    let mut observed: BTreeMap<&str, BTreeSet<Operation>> = BTreeMap::new();
    for endpoint in endpoints {
        if !paths.insert((&endpoint.path, endpoint.method)) {
            violations.push(Violation::Duplicate(
                endpoint.path.clone(),
                endpoint.method.into(),
            ));
        }
        if !expected.iter().any(|r| r.id == endpoint.resource.id) {
            violations.push(Violation::Unknown(endpoint.resource.id.into()));
        }
        observed
            .entry(endpoint.resource.id)
            .or_default()
            .extend(endpoint.operations);
    }
    for resource in expected {
        if !collections::valid(resource) {
            violations.push(Violation::InvalidQueryDescription(resource.id.into()));
        }
        if resource.category.required().contains(&Operation::List)
            && resource.query == QueryPolicy::NotCollection
        {
            violations.push(Violation::MissingQuery(resource.id.into()));
        }
        let operations = observed.get(resource.id);
        if operations.is_none() {
            violations.push(Violation::Orphan(resource.id.into()));
        }
        for operation in resource.category.required() {
            let present = operations.is_some_and(|ops| ops.contains(operation));
            if !present {
                violations.push(Violation::Missing(resource.id.into(), *operation));
            }
        }
    }
    violations
}

/// An HTTP collection, including domain-owned page metadata. Serialization is unchanged.
/// Inventory associates this explicit handler result with its resource and query contract.
pub struct CollectionResponse<T>(pub T);
impl<T: axum::response::IntoResponse> axum::response::IntoResponse for CollectionResponse<T> {
    fn into_response(self) -> axum::response::Response {
        self.0.into_response()
    }
}
