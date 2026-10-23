//! Product route ownership. Axum remains the only dispatcher and middleware implementation.
pub mod catalog;
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
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum QueryPolicy {
    ResourceV1,
    Pending(u32),
    FixedWindow,
    Protocol,
    NotCollection,
}
#[derive(Clone, Debug, Serialize)]
pub struct Endpoint {
    pub path: String,
    pub method: &'static str,
    pub resource: &'static Resource,
    pub operations: &'static [Operation],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    Missing(String, Operation),
    Duplicate(String, String),
    Orphan(String),
    Unknown(String),
    StaleGap(String, Operation),
    MissingQuery(String),
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
    let mut violations = Vec::new();
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
