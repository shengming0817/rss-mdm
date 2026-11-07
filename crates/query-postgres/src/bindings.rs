//! Bind the complete model before it can be advertised or executed. Requests never supply SQL paths.
use rss_mdm_query::{
    Error, Result,
    directory::{Kind, Schema},
};
use std::collections::{BTreeMap, BTreeSet};

/// A trusted expression selected by the domain storage owner.
pub enum Source {
    Column {
        field: &'static str,
        sql: &'static str,
    },
    Json {
        field: &'static str,
        sql: &'static str,
    },
}
impl Source {
    pub const fn column(field: &'static str, sql: &'static str) -> Self {
        Self::Column { field, sql }
    }
    /// Empty field binds a complete JSON row; a named field binds its typed subtree.
    pub const fn json(field: &'static str, sql: &'static str) -> Self {
        Self::Json { field, sql }
    }
    fn name(&self) -> &str {
        match self {
            Self::Column { field, .. } | Self::Json { field, .. } => field,
        }
    }
}
pub struct Bindings {
    schema: &'static Schema,
    columns: BTreeMap<String, String>,
}
impl Bindings {
    pub fn new(schema: &'static Schema, sources: &[Source]) -> Result<Self> {
        let mut names = BTreeSet::new();
        if sources.iter().any(|s| !names.insert(s.name())) {
            return Err(Error::Invalid);
        }
        let mut used = BTreeSet::new();
        let mut columns = BTreeMap::new();
        for field in schema.fields.iter().filter(|f| f.filter || f.sort) {
            let source = sources
                .iter()
                .filter(|source| match source {
                    Source::Column { field: name, .. } => field.name == *name,
                    Source::Json { field: name, .. } => {
                        name.is_empty()
                            || field.name == *name
                            || field
                                .name
                                .strip_prefix(name)
                                .is_some_and(|rest| rest.starts_with('.'))
                    }
                })
                .max_by_key(|s| s.name().len())
                .ok_or(Error::Invalid)?;
            used.insert(source.name());
            let sql = match source {
                Source::Column { sql, .. } => (*sql).to_owned(),
                Source::Json { field: root, sql } => {
                    let path = if root.is_empty() {
                        field.name.as_str()
                    } else {
                        field
                            .name
                            .strip_prefix(root)
                            .ok_or(Error::Invalid)?
                            .trim_start_matches('.')
                    };
                    json_column(sql, path, &field.kind)?
                }
            };
            if columns.insert(field.name.clone(), sql).is_some() {
                return Err(Error::Invalid);
            }
        }
        if sources.iter().any(|s| !used.contains(s.name())) {
            return Err(Error::Invalid);
        }
        Ok(Self { schema, columns })
    }
    /// Ingress exports this same checked schema, forcing storage completeness at composition time.
    pub fn schema(&self) -> &'static Schema {
        self.schema
    }
}
pub trait Columns: Copy {
    fn column(&self, name: &str) -> Result<&str>;
    fn require(&self, _schema: &Schema) -> Result<()> {
        Ok(())
    }
}
impl<F: Fn(&str) -> &'static str + Copy> Columns for F {
    fn column(&self, name: &str) -> Result<&str> {
        Ok(self(name))
    }
}
impl Columns for &Bindings {
    fn column(&self, name: &str) -> Result<&str> {
        self.columns
            .get(name)
            .map(String::as_str)
            .ok_or(Error::Invalid)
    }
    fn require(&self, schema: &Schema) -> Result<()> {
        if std::ptr::eq(self.schema, schema) {
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }
}
fn json_column(root: &str, path: &str, kind: &Kind) -> Result<String> {
    let segments = if path.is_empty() {
        Vec::new()
    } else {
        path.split('.').collect::<Vec<_>>()
    };
    if segments
        .iter()
        .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    {
        return Err(Error::Invalid);
    }
    let path = format!(
        "ARRAY[{}]::text[]",
        segments
            .iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let ty = match kind.scalar() {
        Kind::Integer => "bigint",
        Kind::Number => "double precision",
        Kind::Boolean => "boolean",
        Kind::Text | Kind::Uuid | Kind::Enum(_) => "text",
        _ => return Err(Error::Invalid),
    };
    if kind.collection() {
        let array = format!("(({root}) #> {path})");
        Ok(format!(
            "(CASE WHEN jsonb_typeof({array})='array' THEN ARRAY(SELECT value::{ty} FROM jsonb_array_elements_text({array}) AS item(value)) ELSE NULL::{ty}[] END)"
        ))
    } else {
        let value = format!("((({root}) #>> {path})::{ty})");
        Ok(if ty == "text" {
            format!("{value} COLLATE \"C\"")
        } else {
            value
        })
    }
}
