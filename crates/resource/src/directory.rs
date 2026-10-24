//! Resource directory field authority. SQL and authorization remain with their adapters.
use crate::{Id, Kind};
use rss_mdm_query::{Error, Expression, Parameters, Result, Sort};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
/// Default bounded directory page.
pub const DEFAULT_LIMIT: u16 = 64;
/// Maximum bounded directory page.
pub const MAX_LIMIT: u16 = 1000;
/// Public field identities; arbitrary presentation keys are not selectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Field {
    /// Canonical resource ID.
    Id,
    /// Current aggregate revision.
    Revision,
    /// Resource declaration kind.
    Kind,
    /// Whether an active version exists; filter only.
    Active,
    /// Nullable active version identity; output only.
    ActiveVersion,
    /// Opaque bounded presentation document; output only.
    Presentation,
}
/// Field capabilities used by query binding and capability documentation.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct FieldSpec {
    /// Closed identity.
    pub field: Field,
    /// Public selector.
    pub name: &'static str,
    /// Public value type.
    pub value_type: &'static str,
    /// Accepted in filters.
    pub filter: bool,
    /// Accepted in ORDER BY.
    pub sort: bool,
    /// Accepted in projection.
    pub output: bool,
}
/// Sole Resource query field catalog.
pub const FIELDS: &[FieldSpec] = &[
    FieldSpec {
        field: Field::Id,
        name: "id",
        value_type: "resource_id",
        filter: true,
        sort: true,
        output: true,
    },
    FieldSpec {
        field: Field::Revision,
        name: "revision",
        value_type: "nonnegative_i64",
        filter: true,
        sort: true,
        output: true,
    },
    FieldSpec {
        field: Field::Kind,
        name: "kind",
        value_type: "resource_kind",
        filter: true,
        sort: true,
        output: true,
    },
    FieldSpec {
        field: Field::Active,
        name: "active",
        value_type: "boolean",
        filter: true,
        sort: false,
        output: false,
    },
    FieldSpec {
        field: Field::ActiveVersion,
        name: "activeVersion",
        value_type: "nullable_resource_id",
        filter: false,
        sort: false,
        output: true,
    },
    FieldSpec {
        field: Field::Presentation,
        name: "presentation",
        value_type: "bounded_object",
        filter: false,
        sort: false,
        output: true,
    },
];
fn field(name: &str) -> Result<&'static FieldSpec> {
    FIELDS.iter().find(|f| f.name == name).ok_or(Error::Invalid)
}
/// Validated comparison value. Construction of Query remains private.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scalar {
    /// Validated ID or kind's public spelling.
    Text(String),
    /// Nonnegative aggregate revision.
    Integer(i64),
    /// Active state.
    Boolean(bool),
}
/// Validated query: only parse can construct this, including for non-HTTP callers.
#[derive(Debug)]
pub struct Query {
    filter: Option<Expression<Field, Scalar>>,
    sort: Vec<Sort<Field>>,
    fields: Vec<Field>,
    limit: u16,
    cursor: Option<rss_contract::PageCursor>,
}
impl Query {
    /// Decode raw URL parameters, then bind all selectors and values to Resource semantics.
    pub fn parse(raw: &str) -> Result<Self> {
        let p = Parameters::parse(raw)?;
        let filter = p
            .filter
            .map(|s| rss_mdm_query::parse_filter(&s).and_then(bind))
            .transpose()?;
        let mut sort = Vec::new();
        for s in p.sort {
            let f = field(&s.field)?;
            if !f.sort || sort.iter().any(|s: &Sort<Field>| s.field == f.field) {
                return Err(Error::Invalid);
            }
            sort.push(Sort {
                field: f.field,
                descending: s.descending,
            });
        }
        if !sort.iter().any(|s| s.field == Field::Id) {
            sort.push(Sort {
                field: Field::Id,
                descending: false,
            });
        }
        let mut fields = match p.fields {
            None => FIELDS
                .iter()
                .filter(|s| s.output)
                .map(|s| s.field)
                .collect(),
            Some(names) => names
                .into_iter()
                .map(|name| {
                    let f = field(&name)?;
                    if !f.output {
                        return Err(Error::Invalid);
                    }
                    Ok(f.field)
                })
                .collect::<Result<Vec<_>>>()?,
        };
        fields.sort();
        let limit = p.limit.unwrap_or(DEFAULT_LIMIT);
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            filter,
            sort,
            fields,
            limit,
            cursor: p.cursor,
        })
    }
    /// Bounded filter with typed operands.
    pub fn filter(&self) -> Option<&Expression<Field, Scalar>> {
        self.filter.as_ref()
    }
    /// Stable ordering including its unique ID key.
    pub fn sort(&self) -> &[Sort<Field>] {
        &self.sort
    }
    /// Requested page size.
    pub fn limit(&self) -> usize {
        usize::from(self.limit)
    }
    /// Opaque continuation, never authority.
    pub fn cursor(&self) -> Option<&rss_contract::PageCursor> {
        self.cursor.as_ref()
    }
    /// Bind current product authority and all result-affecting query inputs, excluding page size.
    pub fn binding(&self, tenant: &str, instance: &str, authority: &str) -> Result<String> {
        rss_mdm_query::cursor::fingerprint(&(
            "resource-directory-v1",
            tenant,
            instance,
            authority,
            &self.filter,
            &self.sort,
            &self.fields,
        ))
    }
    /// Verify cursor shape and values against the exact query order before SQL compilation.
    pub fn validate_position(&self, position: &Position) -> Result<()> {
        if position.0.len() != self.sort.len() {
            return Err(Error::CursorInvalidated);
        }
        for (s, v) in self.sort.iter().zip(&position.0) {
            let valid = match (s.field, v) {
                (Field::Id, Scalar::Text(v)) => Id::new(v).is_ok(),
                (Field::Kind, Scalar::Text(v)) => parse_kind(v).is_ok(),
                (Field::Revision, Scalar::Integer(v)) => *v >= 0,
                _ => false,
            };
            if !valid {
                return Err(Error::CursorInvalidated);
            }
        }
        Ok(())
    }
    /// Record the full order tuple independently of the response projection.
    pub fn position(&self, row: &Record) -> Position {
        Position(
            self.sort
                .iter()
                .map(|s| match s.field {
                    Field::Id => Scalar::Text(row.id.as_str().into()),
                    Field::Kind => Scalar::Text(kind_name(row.kind).into()),
                    Field::Revision => Scalar::Integer(row.revision),
                    _ => unreachable!("Query construction only admits sortable fields"),
                })
                .collect(),
        )
    }
    /// Emit exactly the selected fields after the adapter validated the complete record.
    pub fn project(&self, row: Record) -> Map<String, Value> {
        let mut map = Map::new();
        for f in &self.fields {
            let (name, value) = match f {
                Field::Id => ("id", Value::String(row.id.as_str().into())),
                Field::Revision => ("revision", Value::from(row.revision)),
                Field::Kind => ("kind", Value::String(kind_name(row.kind).into())),
                Field::ActiveVersion => (
                    "activeVersion",
                    row.active_version
                        .as_ref()
                        .map(|v| Value::String(v.as_str().into()))
                        .unwrap_or(Value::Null),
                ),
                Field::Presentation => ("presentation", Value::Object(row.presentation.clone())),
                Field::Active => unreachable!("Query construction only admits output fields"),
            };
            map.insert(name.into(), value);
        }
        map
    }
}
/// Full typed header returned by the checked storage decoder.
pub struct Record {
    /// Canonical identity checked against the database row.
    pub id: Id,
    /// Database revision checked to be nonnegative.
    pub revision: i64,
    /// Declaration kind.
    pub kind: Kind,
    /// At most one current active version.
    pub active_version: Option<Id>,
    /// Validated bounded presentation object.
    pub presentation: Map<String, Value>,
}
/// Signed position; validated against Query before it reaches a store.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Position(pub Vec<Scalar>);
/// Stable public kind spelling, including lexical SQL ordering.
pub fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Software => "software",
        Kind::Script => "script",
        Kind::Configuration => "configuration",
        Kind::NativeCollection => "native_collection",
        Kind::AgentCollection => "agent_collection",
        Kind::TelemetryProfile => "telemetry_profile",
    }
}
fn parse_kind(v: &str) -> Result<Kind> {
    match v {
        "software" => Ok(Kind::Software),
        "script" => Ok(Kind::Script),
        "configuration" => Ok(Kind::Configuration),
        "native_collection" => Ok(Kind::NativeCollection),
        "agent_collection" => Ok(Kind::AgentCollection),
        "telemetry_profile" => Ok(Kind::TelemetryProfile),
        _ => Err(Error::Invalid),
    }
}
fn scalar(f: Field, value: String) -> Result<Scalar> {
    match f {
        Field::Id => {
            Id::new(&value).map_err(|_| Error::Invalid)?;
            Ok(Scalar::Text(value))
        }
        Field::Kind => {
            parse_kind(&value)?;
            Ok(Scalar::Text(value))
        }
        Field::Active => match value.as_str() {
            "true" => Ok(Scalar::Boolean(true)),
            "false" => Ok(Scalar::Boolean(false)),
            _ => Err(Error::Invalid),
        },
        Field::Revision if value.bytes().all(|v| v.is_ascii_digit()) => value
            .parse::<i64>()
            .map(Scalar::Integer)
            .map_err(|_| Error::Invalid),
        _ => Err(Error::Invalid),
    }
}
fn bind(expr: Expression<String, String>) -> Result<Expression<Field, Scalar>> {
    Ok(match expr {
        Expression::And(v) => Expression::And(v.into_iter().map(bind).collect::<Result<_>>()?),
        Expression::Or(v) => Expression::Or(v.into_iter().map(bind).collect::<Result<_>>()?),
        Expression::Compare {
            field: name,
            operator,
            values,
        } => {
            let f = field(&name)?;
            if operator == rss_mdm_query::Operator::Icontains
                || !f.filter
                || (operator.range() && !matches!(f.field, Field::Id | Field::Revision))
            {
                return Err(Error::Invalid);
            }
            let mut values = values
                .into_iter()
                .map(|v| scalar(f.field, v))
                .collect::<Result<Vec<_>>>()?;
            // Set order has no query meaning; normalize it before signing a continuation.
            if operator.set() {
                values.sort_by_key(|v| format!("{v:?}"));
                values.dedup();
            }
            Expression::Compare {
                field: f.field,
                operator,
                values,
            }
        }
    })
}

/// Nested version metadata has its own query identity; the aggregate remains its sole owner.
pub static VERSION_SCHEMA: rss_mdm_query::directory::Schema = rss_mdm_query::directory::Schema {
    id: "software_versions",
    keys: &["version"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        rss_mdm_query::directory::Field::scalar("version", rss_mdm_query::directory::Kind::Text),
        rss_mdm_query::directory::Field::scalar(
            "state",
            rss_mdm_query::directory::Kind::Enum(&["frozen", "active", "deprecated", "archived"]),
        ),
        rss_mdm_query::directory::Field::output("resource"),
    ],
};
