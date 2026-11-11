//! Storage-independent completeness check. The storage owner retains the actual executor.
use super::Schema;
use crate::{Error, Result};
use serde::Serialize;
use std::{collections::BTreeSet, ops::Deref};

#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct Execution {
    schema: &'static Schema,
}
impl Execution {
    /// Verify the selectors supplied by the actual execution dispatch, never a second catalog.
    pub fn bind<'a>(
        schema: &'static Schema,
        fields: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self> {
        let mut bound = BTreeSet::new();
        for field in fields {
            if !bound.insert(field) {
                return Err(Error::Invalid);
            }
        }
        let required = schema
            .fields()
            .iter()
            .filter(|f| f.filter || f.sort)
            .map(|f| f.name.as_str())
            .collect::<BTreeSet<_>>();
        if required != bound {
            return Err(Error::Invalid);
        }
        Ok(Self { schema })
    }
    pub fn schema(&self) -> &'static Schema {
        self.schema
    }
    pub fn require(&self, schema: &Schema) -> Result<()> {
        if std::ptr::eq(self.schema, schema) {
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }
}
impl Deref for Execution {
    type Target = Schema;
    fn deref(&self) -> &Schema {
        self.schema
    }
}
