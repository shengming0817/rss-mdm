//! Executable field capabilities. Operators are derived here and used by both binding and export.
use crate::Operator;
use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Kind {
    Text,
    Uuid,
    Integer,
    Number,
    Boolean,
    Enum(Vec<String>),
    EnumSet(Vec<String>),
    TextSet,
    UuidSet,
    IntegerSet,
    NumberSet,
    BooleanSet,
    Object,
    ObjectSet,
}
impl Kind {
    pub fn enumeration(values: &[&str]) -> Self {
        Self::Enum(values.iter().map(|v| (*v).into()).collect())
    }
    pub fn enum_set(values: &[&str]) -> Self {
        Self::EnumSet(values.iter().map(|v| (*v).into()).collect())
    }
    pub fn collection(&self) -> bool {
        matches!(
            self,
            Self::EnumSet(_)
                | Self::TextSet
                | Self::UuidSet
                | Self::IntegerSet
                | Self::NumberSet
                | Self::BooleanSet
        )
    }
    pub fn scalar(&self) -> Self {
        match self {
            Self::EnumSet(v) => Self::Enum(v.clone()),
            Self::TextSet => Self::Text,
            Self::UuidSet => Self::Uuid,
            Self::IntegerSet => Self::Integer,
            Self::NumberSet => Self::Number,
            Self::BooleanSet => Self::Boolean,
            other => other.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub kind: Kind,
    pub filter: bool,
    pub sort: bool,
    pub output: bool,
    pub nullable: bool,
    pub(crate) range: bool,
    pub(crate) exact: bool,
    pub(crate) constraints: Value,
    pub(crate) reason: Option<String>,
    pub(crate) validator: Option<fn(&Value) -> bool>,
    pub(crate) sort_bytes: Option<usize>,
}
impl Field {
    pub fn scalar(name: &str, kind: Kind) -> Self {
        let sort = !kind.collection() && !matches!(kind, Kind::Object | Kind::ObjectSet);
        let sort_bytes = match &kind {
            Kind::Uuid => Some(38),
            Kind::Integer => Some(20),
            Kind::Number => Some(32),
            Kind::Boolean => Some(5),
            Kind::Enum(values) => values
                .iter()
                .filter_map(|v| serde_json::to_vec(v).ok().map(|v| v.len()))
                .max(),
            _ => None,
        };
        Self {
            name: name.into(),
            kind,
            filter: true,
            sort,
            output: true,
            nullable: false,
            range: true,
            exact: false,
            constraints: Value::Null,
            reason: None,
            validator: None,
            sort_bytes,
        }
    }
    pub fn output(name: &str) -> Self {
        let mut field = Self::scalar(name, Kind::Object);
        field.filter = false;
        field.sort = false;
        field.reason = Some(
            "Object output; filtering requires a declared scalar child or domain selector".into(),
        );
        field
    }
    pub fn filter_only(name: &str, kind: Kind) -> Self {
        let mut field = Self::scalar(name, kind);
        field.sort = false;
        field.output = false;
        field
    }
    pub fn nullable(mut self) -> Self {
        self.nullable = true;
        self
    }
    pub fn without_output(mut self) -> Self {
        self.output = false;
        self
    }
    pub fn without_range(mut self) -> Self {
        self.range = false;
        self
    }
    pub fn excluded(mut self, reason: &str) -> Self {
        self.filter = false;
        self.sort = false;
        self.reason = Some(reason.into());
        self
    }
    pub fn operations(&self) -> Vec<Operator> {
        if !self.filter {
            return Vec::new();
        }
        if self.exact { return vec![Operator::Eq, Operator::In]; }
        let mut ops = vec![Operator::Eq, Operator::Ne, Operator::In, Operator::Out];
        if self.kind.collection() {
            ops.extend([Operator::ContainsAny, Operator::ContainsAll]);
        } else {
            if self.range
                && matches!(
                    self.kind,
                    Kind::Text | Kind::Uuid | Kind::Integer | Kind::Number
                )
            {
                ops.extend([Operator::Lt, Operator::Le, Operator::Gt, Operator::Ge]);
            }
            if matches!(self.kind, Kind::Text) {
                ops.push(Operator::Icontains);
            }
        }
        if self.nullable {
            ops.extend([Operator::IsNull, Operator::IsNotNull]);
        }
        ops
    }
    pub(crate) fn model_sort(&mut self) {
        if let Kind::Enum(values) = &self.kind {
            self.sort_bytes = values
                .iter()
                .filter_map(|v| serde_json::to_vec(v).ok().map(|v| v.len()))
                .max();
        }
        if matches!(self.kind, Kind::Text) {
            self.sort_bytes = self
                .constraints
                .get("maxLength")
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .and_then(|n| n.checked_mul(6))
                .and_then(|n| n.checked_add(2));
            if let Some(bytes) = self.constraints.get("x-rss-maxUtf8Bytes").and_then(Value::as_u64).and_then(|n| usize::try_from(n).ok()) {
                // Directory text rejects controls. Only quotes/backslashes can expand beyond UTF-8.
                self.sort_bytes = bytes.checked_mul(2).and_then(|n| n.checked_add(2));
            }
        }
        if self.sort && self.sort_bytes.is_none_or(|bytes| bytes > 2300) {
            self.sort = false;
            self.reason=Some("Filtering and output are supported; the model does not bound this scalar to a transport-safe seek key".into());
        }
    }
    pub(crate) fn valid_position(&self, value: &Value) -> bool {
        let valid = if matches!(self.kind, Kind::Text) {
            text_operand(value)
                && self.validator.is_none_or(|validate| validate(value))
                && self.constrained(value)
        } else {
            self.valid(value)
        };
        valid
            && self
                .sort_bytes
                .is_none_or(|limit| serde_json::to_vec(value).is_ok_and(|v| v.len() <= limit))
    }
    pub(crate) fn valid_operand(&self, operator: Operator, value: &Value) -> bool {
        if self.kind == Kind::Text && (operator == Operator::Icontains || operator.range()) {
            // A substring or lexical boundary need not have a stored value's length.
            // Explicit domain constructors still apply to complete range values.
            text_operand(value)
                && (operator == Operator::Icontains
                    || self.validator.is_none_or(|validate| validate(value)))
        } else {
            self.valid(value)
        }
    }
    pub(crate) fn valid(&self, value: &Value) -> bool {
        let shape = match self.kind.scalar() {
            Kind::Text => text_operand(value),
            Kind::Uuid => value.as_str().is_some_and(|s| {
                uuid::Uuid::parse_str(s).is_ok_and(|v| !v.is_nil() && v.to_string() == s)
            }),
            Kind::Integer => value.as_i64().is_some(),
            Kind::Number => value.as_f64().is_some_and(f64::is_finite),
            Kind::Boolean => value.is_boolean(),
            Kind::Enum(values) => value
                .as_str()
                .is_some_and(|s| values.iter().any(|v| v == s)),
            _ => false,
        };
        shape && self.validator.is_none_or(|validate| validate(value)) && self.constrained(value)
    }
    fn constrained(&self, value: &Value) -> bool {
        let s = &self.constraints;
        if let Some(values) = s.get("enum").and_then(Value::as_array)
            && !values.contains(value)
        {
            return false;
        }
        if let Some(v) = value.as_f64()
            && (s
                .get("minimum")
                .and_then(Value::as_f64)
                .is_some_and(|min| v < min)
                || s.get("maximum")
                    .and_then(Value::as_f64)
                    .is_some_and(|max| v > max))
        {
            return false;
        }
        if let Some(v) = value.as_str() {
            if s.get("x-rss-maxUtf8Bytes").and_then(Value::as_u64).is_some_and(|n| v.len() as u64 > n) { return false; }
            let length = v.chars().count() as u64;
            if s.get("minLength")
                .and_then(Value::as_u64)
                .is_some_and(|min| length < min)
                || s.get("maxLength")
                    .and_then(Value::as_u64)
                    .is_some_and(|max| length > max)
            {
                return false;
            }
        }
        true
    }
}
impl Serialize for Field {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("Field", 10)?;
        out.serialize_field("name", &self.name)?;
        out.serialize_field("kind", &self.kind)?;
        out.serialize_field("filter", &self.filter)?;
        out.serialize_field("sort", &self.sort)?;
        out.serialize_field("output", &self.output)?;
        out.serialize_field("nullable", &self.nullable)?;
        out.serialize_field("operators", &self.operations())?;
        out.serialize_field("sortKeyMaxBytes", &self.sort_bytes)?;
        out.serialize_field(
            "nullSemantics",
            "missing and JSON null are SQL NULL; comparisons use three-valued logic",
        )?;
        out.serialize_field("limitation", &self.reason)?;
        out.end()
    }
}

fn text_operand(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| s.len() <= 4096 && !s.chars().any(char::is_control))
}
