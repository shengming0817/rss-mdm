//! Deterministic product compliance decisions; time and device execution are not inputs.
use serde::{Deserialize, Serialize};
mod model;
pub use model::*;
/// Completed assessment, never a worker state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Compliant,
    NonCompliant,
    Unknown,
    NotApplicable,
}
/// Host-mapped three-valued predicate or target decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Match,
    NoMatch,
    Unknown,
}
/// Combine applicability and the existing predicate engine's decision.
pub fn assess(applicable: Decision, condition: Decision) -> Status {
    match applicable {
        Decision::NoMatch => Status::NotApplicable,
        Decision::Unknown => Status::Unknown,
        Decision::Match => match condition {
            Decision::Match => Status::Compliant,
            Decision::NoMatch => Status::NonCompliant,
            Decision::Unknown => Status::Unknown,
        },
    }
}
/// Current response state; Pending is not a persisted assessment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Current {
    Compliant,
    NonCompliant,
    Unknown,
    NotApplicable,
    Pending,
}
impl From<Status> for Current {
    fn from(s: Status) -> Self {
        match s {
            Status::Compliant => Self::Compliant,
            Status::NonCompliant => Self::NonCompliant,
            Status::Unknown => Self::Unknown,
            Status::NotApplicable => Self::NotApplicable,
        }
    }
}
/// Aggregate only enabled rules. Empty input means no rules, never compliance.
pub fn aggregate(items: impl IntoIterator<Item = Current>) -> Current {
    let mut best = None;
    for item in items {
        let rank = |s| match s {
            Current::NotApplicable => 0,
            Current::Compliant => 1,
            Current::Pending => 2,
            Current::Unknown => 3,
            Current::NonCompliant => 4,
        };
        if best.is_none_or(|old| rank(item) > rank(old)) {
            best = Some(item);
        }
    }
    best.unwrap_or(Current::Unknown)
}
