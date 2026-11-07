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
        matches!(self, Self::EnumSet(_) | Self::TextSet | Self::UuidSet | Self::IntegerSet | Self::NumberSet | Self::BooleanSet)
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
    pub(crate) constraints: Value,
    pub(crate) reason: Option<String>,
    pub(crate) validator: Option<fn(&Value) -> bool>,
}
impl Field {
    pub fn scalar(name: &str, kind: Kind) -> Self {
        let sort = !kind.collection() && !matches!(kind, Kind::Object | Kind::ObjectSet);
        Self {
            name: name.into(), kind, filter: true, sort, output: true,
            nullable: false, range: true, constraints: Value::Null, reason: None, validator: None,
        }
    }
    pub fn output(name: &str) -> Self {
        let mut field = Self::scalar(name, Kind::Object);
        field.filter = false;
        field.sort = false;
        field.reason = Some("Object output; filtering requires a declared scalar child or domain selector".into());
        field
    }
    pub fn filter_only(name: &str, kind: Kind) -> Self {
        let mut field = Self::scalar(name, kind);
        field.sort = false;
        field.output = false;
        field
    }
    pub fn nullable(mut self) -> Self { self.nullable = true; self }
    pub fn without_output(mut self) -> Self { self.output = false; self }
    pub fn without_range(mut self) -> Self { self.range = false; self }
    pub fn excluded(mut self, reason: &str) -> Self {
        self.filter = false;
        self.sort = false;
        self.reason = Some(reason.into());
        self
    }
    pub fn operations(&self) -> Vec<Operator> {
        if !self.filter { return Vec::new(); }
        let mut ops = vec![Operator::Eq, Operator::Ne, Operator::In, Operator::Out];
        if self.kind.collection() {
            ops.extend([Operator::ContainsAny, Operator::ContainsAll]);
        } else {
            if self.range && matches!(self.kind, Kind::Text | Kind::Integer | Kind::Number) {
                ops.extend([Operator::Lt, Operator::Le, Operator::Gt, Operator::Ge]);
            }
            if matches!(self.kind, Kind::Text) { ops.push(Operator::Icontains); }
        }
        if self.nullable { ops.extend([Operator::IsNull, Operator::IsNotNull]); }
        ops
    }
    pub(crate) fn valid(&self, value: &Value) -> bool {
        let shape = match self.kind.scalar() {
            Kind::Text => value.as_str().is_some_and(|s| s.len() <= 4096 && !s.chars().any(char::is_control)),
            Kind::Uuid => value.as_str().is_some_and(|s| uuid::Uuid::parse_str(s).is_ok_and(|v| !v.is_nil() && v.to_string() == s)),
            Kind::Integer => value.as_i64().is_some(),
            Kind::Number => value.as_f64().is_some_and(f64::is_finite),
            Kind::Boolean => value.is_boolean(),
            Kind::Enum(values) => value.as_str().is_some_and(|s| values.iter().any(|v| v == s)),
            _ => false,
        };
        shape && self.validator.is_none_or(|validate| validate(value)) && self.constrained(value)
    }
    fn constrained(&self, value: &Value) -> bool {
        let s = &self.constraints;
        if let Some(values) = s.get("enum").and_then(Value::as_array) && !values.contains(value) { return false; }
        if let Some(v) = value.as_f64() {
            if s.get("minimum").and_then(Value::as_f64).is_some_and(|min| v < min)
                || s.get("maximum").and_then(Value::as_f64).is_some_and(|max| v > max) { return false; }
        }
        if let Some(v) = value.as_str() {
            let length = v.chars().count() as u64;
            if s.get("minLength").and_then(Value::as_u64).is_some_and(|min| length < min)
                || s.get("maxLength").and_then(Value::as_u64).is_some_and(|max| length > max) { return false; }
        }
        true
    }
}
impl Serialize for Field {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("Field", 9)?;
        out.serialize_field("name", &self.name)?;
        out.serialize_field("kind", &self.kind)?;
        out.serialize_field("filter", &self.filter)?;
        out.serialize_field("sort", &self.sort)?;
        out.serialize_field("output", &self.output)?;
        out.serialize_field("nullable", &self.nullable)?;
        out.serialize_field("operators", &self.operations())?;
        out.serialize_field("nullSemantics", "missing and JSON null are SQL NULL; comparisons use three-valued logic")?;
        out.serialize_field("limitation", &self.reason)?;
        out.end()
    }
}
