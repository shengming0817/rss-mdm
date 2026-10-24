//! Product query syntax and bounded continuation tokens; no HTTP, SQL or authority owner.
pub mod cursor;
pub mod directory;
mod parameters;
mod parser;
pub use parameters::Parameters;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid query")]
    Invalid,
    #[error("query budget exceeded")]
    Budget,
    #[error("continuation no longer matches the query context")]
    CursorInvalidated,
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operator {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    Out,
    Icontains,
}
impl Operator {
    pub fn range(self) -> bool {
        matches!(self, Self::Lt | Self::Le | Self::Gt | Self::Ge)
    }
    pub fn set(self) -> bool {
        matches!(self, Self::In | Self::Out)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expression<F, V> {
    Compare {
        field: F,
        operator: Operator,
        values: Vec<V>,
    },
    And(Vec<Self>),
    Or(Vec<Self>),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sort<F> {
    pub field: F,
    pub descending: bool,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}
/// Parse before any field-specific interpretation. No unbounded intermediate AST is created.
pub fn parse_filter(input: &str) -> Result<Expression<String, String>> {
    parser::parse(input)
}

/// Raw query byte ceiling, checked before URL decoding.
pub const MAX_RAW_QUERY_BYTES: usize = 16 * 1024;
/// Decoded RSQL byte ceiling.
pub const MAX_FILTER_BYTES: usize = 8 * 1024;
