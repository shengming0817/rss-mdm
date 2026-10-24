//! Checked directory values. Resource owners supply the sole field catalog; no SQL or authority.
use crate::{Error, Expression, Operator, Page, Parameters, Result, Sort, cursor::CursorCodec};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, Serialize)]
pub enum Kind {
    Text,
    Uuid,
    Integer,
    Boolean,
    Enum(&'static [&'static str]),
    EnumSet(&'static [&'static str]),
    UuidSet,
    Object,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Field {
    pub name: &'static str,
    pub kind: Kind,
    pub filter: bool,
    pub sort: bool,
    pub output: bool,
}
impl Field {
    pub const fn scalar(name: &'static str, kind: Kind) -> Self {
        Self {
            name,
            kind,
            filter: true,
            sort: true,
            output: true,
        }
    }
    pub const fn output(name: &'static str) -> Self {
        Self {
            name,
            kind: Kind::Object,
            filter: false,
            sort: false,
            output: true,
        }
    }
    pub const fn filter_only(name: &'static str, kind: Kind) -> Self {
        Self {
            name,
            kind,
            filter: true,
            sort: false,
            output: false,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Schema {
    pub id: &'static str,
    pub fields: &'static [Field],
    /// Unique identity, appended when absent from the caller's ordering.
    pub keys: &'static [&'static str],
    pub default_limit: u16,
    pub max_limit: u16,
}
impl Schema {
    pub fn field(&self, name: &str) -> Result<&Field> {
        self.fields
            .iter()
            .find(|f| f.name == name)
            .ok_or(Error::Invalid)
    }
    pub fn statistics(&'static self, raw: &str) -> Result<Query> {
        let p = Parameters::parse(raw)?;
        if p.cursor.is_some() || p.limit.is_some() || p.fields.is_some() || !p.sort.is_empty() {
            return Err(Error::Invalid);
        }
        Query::new(self, p)
    }
    pub fn parse(&'static self, raw: &str) -> Result<Query> {
        Query::new(self, Parameters::parse(raw)?)
    }
}
#[derive(Clone, Debug)]
pub struct Query {
    schema: &'static Schema,
    filter: Option<Expression<String, Value>>,
    sort: Vec<Sort<String>>,
    fields: Vec<String>,
    limit: u16,
    cursor: Option<rss_contract::PageCursor>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Position(pub Vec<Value>);
impl Query {
    pub fn new(schema: &'static Schema, p: Parameters) -> Result<Self> {
        if schema.keys.is_empty()
            || schema.default_limit == 0
            || schema.default_limit > schema.max_limit
        {
            return Err(Error::Invalid);
        }
        let filter = p
            .filter
            .map(|s| crate::parse_filter(&s).and_then(|e| bind(schema, e)))
            .transpose()?;
        let mut sort = p.sort;
        for (i, s) in sort.iter().enumerate() {
            if !schema.field(&s.field)?.sort || sort[..i].iter().any(|v| v.field == s.field) {
                return Err(Error::Invalid);
            }
        }
        for key in schema.keys {
            if !schema.field(key)?.sort {
                return Err(Error::Invalid);
            }
            if !sort.iter().any(|s| s.field == *key) {
                sort.push(Sort {
                    field: (*key).into(),
                    descending: false,
                });
            }
        }
        let mut fields = p.fields.unwrap_or_else(|| {
            schema
                .fields
                .iter()
                .filter(|f| f.output)
                .map(|f| f.name.to_owned())
                .collect()
        });
        for name in &fields {
            if !schema.field(name)?.output {
                return Err(Error::Invalid);
            }
        }
        fields.sort();
        let limit = p.limit.unwrap_or(schema.default_limit);
        if !(1..=schema.max_limit).contains(&limit) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            schema,
            filter,
            sort,
            fields,
            limit,
            cursor: p.cursor,
        })
    }
    pub fn require_schema(&self, schema: &Schema) -> Result<()> {
        if std::ptr::eq(self.schema, schema) {
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }
    pub fn cursor(&self) -> Option<&rss_contract::PageCursor> {
        self.cursor.as_ref()
    }
    pub fn schema(&self) -> &'static Schema {
        self.schema
    }
    pub fn filter(&self) -> Option<&Expression<String, Value>> {
        self.filter.as_ref()
    }
    pub fn sort(&self) -> &[Sort<String>] {
        &self.sort
    }
    pub fn selects(&self, field: &str) -> bool {
        self.fields.iter().any(|f| f == field)
    }
    pub fn limit(&self) -> usize {
        usize::from(self.limit)
    }
    pub fn mentions(&self, name: &str) -> bool {
        fn walk(e: &Expression<String, Value>, name: &str) -> bool {
            match e {
                Expression::Compare { field, .. } => field == name,
                Expression::And(v) | Expression::Or(v) => v.iter().any(|e| walk(e, name)),
            }
        }
        self.filter.as_ref().is_some_and(|e| walk(e, name))
    }
    /// Defaults become part of the effective query and continuation binding.
    pub fn default_filter(&mut self, name: &str, value: &str) -> Result<()> {
        if !self.mentions(name) {
            let expr = bind(
                self.schema,
                Expression::Compare {
                    field: name.into(),
                    operator: Operator::Eq,
                    values: vec![value.into()],
                },
            )?;
            self.filter = Some(match self.filter.take() {
                Some(e) => Expression::And(vec![e, expr]),
                None => expr,
            });
        }
        Ok(())
    }
    pub fn binding<T: Serialize>(&self, authority: &T) -> Result<String> {
        crate::cursor::fingerprint(&(
            self.schema.id,
            authority,
            &self.filter,
            &self.sort,
            &self.fields,
        ))
    }
    pub fn after(&self, codec: &CursorCodec, binding: &str) -> Result<Option<Position>> {
        self.cursor
            .as_ref()
            .map(|c| {
                let position = codec.decode(c, binding)?;
                self.validate_position(&position)?;
                Ok(position)
            })
            .transpose()
    }
    pub fn validate_position(&self, position: &Position) -> Result<()> {
        if position.0.len() != self.sort.len() {
            return Err(Error::CursorInvalidated);
        }
        for (s, v) in self.sort.iter().zip(&position.0) {
            if !v.is_null() && !valid(self.schema.field(&s.field)?.kind, v) {
                return Err(Error::CursorInvalidated);
            }
        }
        Ok(())
    }
    pub fn position(&self, row: &Value) -> Result<Position> {
        let position = Position(
            self.sort
                .iter()
                .map(|s| row.get(&s.field).cloned().ok_or(Error::Invalid))
                .collect::<Result<_>>()?,
        );
        self.validate_position(&position)?;
        Ok(position)
    }
    pub fn project(&self, row: Value) -> Result<Value> {
        let mut result = Map::new();
        for name in &self.fields {
            result.insert(name.clone(), row.get(name).cloned().ok_or(Error::Invalid)?);
        }
        Ok(Value::Object(result))
    }
    pub fn page(
        &self,
        rows: Vec<Value>,
        codec: &CursorCodec,
        binding: &str,
    ) -> Result<Page<Value>> {
        let page = self.unprojected_page(rows, codec, binding)?;
        Ok(Page {
            items: page
                .items
                .into_iter()
                .map(|r| self.project(r))
                .collect::<Result<_>>()?,
            next_cursor: page.next_cursor,
        })
    }
    /// Preserve private identity/order fields until the HTTP owner has hydrated computed outputs.
    pub fn unprojected_page(
        &self,
        mut rows: Vec<Value>,
        codec: &CursorCodec,
        binding: &str,
    ) -> Result<Page<Value>> {
        let more = rows.len() > self.limit();
        rows.truncate(self.limit());
        let next_cursor = if more {
            rows.last()
                .map(|r| {
                    codec
                        .encode(binding, &self.position(r)?)
                        .map(|c| c.as_str().to_owned())
                })
                .transpose()?
        } else {
            None
        };
        Ok(Page {
            items: rows,
            next_cursor,
        })
    }
}
fn valid(kind: Kind, value: &Value) -> bool {
    match kind {
        Kind::Text => value
            .as_str()
            .is_some_and(|s| s.len() <= 4096 && !s.chars().any(char::is_control)),
        Kind::Uuid | Kind::UuidSet => value.as_str().is_some_and(|s| {
            uuid::Uuid::parse_str(s).is_ok_and(|v| !v.is_nil() && v.to_string() == s)
        }),
        Kind::Integer => value.as_i64().is_some(),
        Kind::Boolean => value.is_boolean(),
        Kind::Enum(values) | Kind::EnumSet(values) => {
            value.as_str().is_some_and(|s| values.contains(&s))
        }
        Kind::Object => false,
    }
}
fn scalar(kind: Kind, input: String) -> Result<Value> {
    let value = match kind {
        Kind::Integer => Value::from(input.parse::<i64>().map_err(|_| Error::Invalid)?),
        Kind::Boolean => match input.as_str() {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => return Err(Error::Invalid),
        },
        Kind::Uuid | Kind::UuidSet => Value::from(
            uuid::Uuid::parse_str(&input)
                .map_err(|_| Error::Invalid)?
                .to_string(),
        ),
        _ => Value::from(input),
    };
    if valid(kind, &value) {
        Ok(value)
    } else {
        Err(Error::Invalid)
    }
}
fn bind(schema: &Schema, e: Expression<String, String>) -> Result<Expression<String, Value>> {
    Ok(match e {
        Expression::Compare {
            field,
            operator,
            values,
        } => {
            let spec = schema.field(&field)?;
            if !matches!(
                operator,
                Operator::Eq
                    | Operator::Ne
                    | Operator::Lt
                    | Operator::Le
                    | Operator::Gt
                    | Operator::Ge
                    | Operator::In
                    | Operator::Out
                    | Operator::Icontains
            ) || !spec.filter
                || matches!(spec.kind, Kind::Object)
                || (operator.range()
                    && matches!(
                        spec.kind,
                        Kind::Boolean | Kind::Enum(_) | Kind::EnumSet(_) | Kind::UuidSet
                    ))
                || (operator == Operator::Icontains && !matches!(spec.kind, Kind::Text))
            {
                return Err(Error::Invalid);
            }
            Expression::Compare {
                field,
                operator,
                values: values
                    .into_iter()
                    .map(|s| scalar(spec.kind, s))
                    .collect::<Result<_>>()?,
            }
        }
        Expression::And(v) => Expression::And(
            v.into_iter()
                .map(|e| bind(schema, e))
                .collect::<Result<_>>()?,
        ),
        Expression::Or(v) => Expression::Or(
            v.into_iter()
                .map(|e| bind(schema, e))
                .collect::<Result<_>>()?,
        ),
    })
}
