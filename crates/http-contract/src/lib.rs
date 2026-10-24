//! Product route ownership. Axum remains the only dispatcher and middleware implementation.
pub mod catalog;
pub mod collections;
mod router;
pub mod routing;
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
    Pending(u32),
    FixedWindow,
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
pub struct Endpoint {
    pub path: String,
    pub method: &'static str,
    pub resource: &'static Resource,
    pub operations: &'static [Operation],
    pub query: Option<QueryDeclaration>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    Missing(String, Operation),
    Duplicate(String, String),
    DuplicateResource(String),
    Orphan(String),
    Unknown(String),
    StaleGap(String, Operation),
    MissingQuery(String),
    InvalidQueryDescription(String),
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Gap {
    pub resource: &'static str,
    pub operation: Operation,
    pub issue: u32,
    pub reason: &'static str,
}
/// The expected resource set is independent from the endpoints; deleting both a list and
/// its descriptor cannot erase its resource's required operation.
pub fn validate(endpoints: &[Endpoint], expected: &[&Resource], gaps: &[Gap]) -> Vec<Violation> {
    let mut violations = validate_ownership(endpoints, expected, gaps);
    for endpoint in endpoints {
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
pub fn validate_ownership(
    endpoints: &[Endpoint],
    expected: &[&Resource],
    gaps: &[Gap],
) -> Vec<Violation> {
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
        if !collections::valid(resource, gaps) {
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
            let gap = gaps
                .iter()
                .any(|g| g.resource == resource.id && &g.operation == operation);
            if !present && !gap {
                violations.push(Violation::Missing(resource.id.into(), *operation));
            }
            if present && gap {
                violations.push(Violation::StaleGap(resource.id.into(), *operation));
            }
        }
    }
    violations
}
