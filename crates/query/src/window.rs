//! Fixed-order continuations share strict decoding without pretending to support re-sorting.
use crate::{Error, Parameters, Result};
use serde::{Deserialize, Serialize};
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub limit: usize,
    pub cursor: Option<String>,
}
impl Schema {
    pub fn parse(&self, raw: &str) -> Result<(Query, BTreeMap<String, String>)> {
        let (p, context) = Parameters::parse_with_context(raw, self.context)?;
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
                limit: usize::from(limit),
                cursor: p.cursor.map(|v| v.as_str().to_owned()),
            },
            context,
        ))
    }
}
