//! Fixed-order continuations share strict decoding without pretending to support re-sorting.
use crate::{Error, Parameters, Result};
use serde::Serialize;
use std::collections::BTreeMap;
#[derive(Debug, Serialize)]
pub struct Schema {
    pub id: &'static str,
    pub default_limit: u16,
    pub max_limit: u16,
    /// The source owns this order and the meaning of the frozen continuation.
    pub order: &'static str,
    pub context: &'static [&'static str],
}
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    #[serde(skip)]
    schema: &'static Schema,
    limit: usize,
    cursor: Option<String>,
}
impl Schema {
    pub fn parse(&'static self, raw: &str) -> Result<(Query, BTreeMap<String, String>)> {
        self.parse_with_budgets(raw, crate::MAX_RAW_QUERY_BYTES, 4096)
    }
    /// The product owns larger fixed inputs and must provision their full transport path.
    pub fn parse_with_budgets(
        &'static self,
        raw: &str,
        max_raw_bytes: usize,
        max_cursor_bytes: usize,
    ) -> Result<(Query, BTreeMap<String, String>)> {
        let (p, context) = Parameters::parse_with_cursor(raw, self.context, max_raw_bytes, |s| {
            crate::cursor::validate_token(&s, max_cursor_bytes)?;
            Ok(s)
        })?;
        if p.filter.is_some()
            || !p.sort.is_empty()
            || p.fields.is_some()
            || self.order.is_empty()
            || self.default_limit == 0
            || self.default_limit > self.max_limit
        {
            return Err(Error::Invalid);
        }
        let limit = p.limit.unwrap_or(self.default_limit);
        if !(1..=self.max_limit).contains(&limit) {
            return Err(Error::Invalid);
        }
        Ok((
            Query {
                schema: self,
                limit: usize::from(limit),
                cursor: p.cursor,
            },
            context,
        ))
    }
}

impl Query {
    pub fn require_schema(&self, schema: &Schema) -> Result<()> {
        if std::ptr::eq(self.schema, schema) {
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }
    pub fn limit(&self) -> usize {
        self.limit
    }
    pub fn cursor(&self) -> &Option<String> {
        &self.cursor
    }
}
