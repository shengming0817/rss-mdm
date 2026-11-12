//! Compile only the schema shapes emitted by product directory models, not arbitrary JSON Schema.
//! ref: schemars schemars/src/generate.rs@v1.2.2 (serialization contract and local definitions).
use super::{Field, Kind, Schema};
use schemars::{JsonSchema, generate::SchemaSettings};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
pub struct Exclusion {
    pub path: &'static str,
    pub reason: &'static str,
}
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("directory model cannot bind {0}")]
    Unsupported(String),
    #[error("directory model has conflicting field types at {0}")]
    Conflict(String),
    #[error("directory exclusion does not identify a model property: {0}")]
    Exclusion(String),
    #[error("invalid directory identity or page configuration")]
    Configuration,
}
type Result<T> = std::result::Result<T, BuildError>;

impl Schema {
    pub fn derived<T: JsonSchema>(
        id: &'static str,
        keys: &'static [&'static str],
        default_limit: u16,
        max_limit: u16,
        exclusions: &[Exclusion],
    ) -> Result<Self> {
        let model = SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator()
            .into_root_schema_for::<T>()
            .to_value();
        let mut schema = Self::from_model(id, keys, default_limit, max_limit, &model, exclusions)?;
        schema.model_identity = T::schema_id().into_owned();
        Ok(schema)
    }
    fn from_model(
        id: &'static str,
        keys: &'static [&'static str],
        default_limit: u16,
        max_limit: u16,
        model: &Value,
        exclusions: &[Exclusion],
    ) -> Result<Self> {
        if id.is_empty() || keys.is_empty() || default_limit == 0 || default_limit > max_limit {
            return Err(BuildError::Configuration);
        }
        let mut compiler = Compiler {
            root: model,
            fields: BTreeMap::new(),
            exclusions,
            used: BTreeSet::new(),
        };
        compiler.walk(model, "", false, 0)?;
        for exclusion in exclusions {
            if exclusion.reason.trim().is_empty() || !compiler.used.contains(exclusion.path) {
                return Err(BuildError::Exclusion(exclusion.path.into()));
            }
        }
        for field in compiler.fields.values_mut() {
            field.model_sort();
        }
        let schema = Self {
            id,
            keys,
            default_limit,
            max_limit,
            fields: compiler.fields.into_values().collect(),
            model: model.clone(),
            model_identity: id.to_owned(),
            selectors: Vec::new(),
        };
        for key in keys {
            if !schema.field(key).is_ok_and(|f| f.sort && !f.nullable) {
                return Err(BuildError::Configuration);
            }
        }
        Ok(schema)
    }
    /// Retain a domain value constructor whose invariants exceed the scalar wire shape.
    pub fn validate_with(mut self, name: &str, validate: fn(&Value) -> bool) -> Result<Self> {
        let field = self
            .fields
            .iter_mut()
            .find(|f| f.name == name)
            .ok_or_else(|| BuildError::Unsupported(name.into()))?;
        field.validator = Some(validate);
        Ok(self)
    }
    /// Canonicalize an explicitly domain-owned operand before comparing it with stored facts.
    pub fn normalize_with(
        mut self,
        name: &str,
        normalize: fn(&Value) -> Option<Value>,
    ) -> Result<Self> {
        let field = self
            .fields
            .iter_mut()
            .find(|f| f.name == name)
            .ok_or_else(|| BuildError::Unsupported(name.into()))?;
        field.normalizer = Some(normalize);
        Ok(self)
    }
    pub fn no_range(mut self, name: &str) -> Result<Self> {
        let field = self
            .fields
            .iter_mut()
            .find(|f| f.name == name)
            .ok_or_else(|| BuildError::Unsupported(name.into()))?;
        field.range = false;
        Ok(self)
    }
    /// Additional business selectors are typed independently of the response, never aliases.
    pub fn with_selectors<T: JsonSchema>(mut self, reason: &'static str) -> Result<Self> {
        if reason.trim().is_empty() {
            return Err(BuildError::Configuration);
        }
        let model = SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator()
            .into_root_schema_for::<T>()
            .to_value();
        let mut compiler = Compiler {
            root: &model,
            fields: BTreeMap::new(),
            exclusions: &[],
            used: BTreeSet::new(),
        };
        compiler.walk(&model, "", false, 0)?;
        for (name, mut field) in compiler.fields {
            if !field.filter || self.fields.iter().any(|f| f.name == name) {
                return Err(BuildError::Conflict(name));
            }
            field.output = false;
            field.sort = false;
            field.reason = Some(reason.into());
            self.selectors.push(name);
            self.fields.push(field);
        }
        self.fields.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(self)
    }
    /// Restrict a domain selector whose semantics support only exact membership.
    pub fn exact(mut self, name: &str) -> Result<Self> {
        let field = self
            .fields
            .iter_mut()
            .find(|f| f.name == name)
            .ok_or_else(|| BuildError::Unsupported(name.into()))?;
        field.exact = true;
        field.sort = false;
        Ok(self)
    }
    /// A computed subtree may filter after bounded qualification without a storage seek order.
    pub fn no_sort(mut self, path: &str, reason: &'static str) -> Result<Self> {
        let mut found = false;
        if reason.trim().is_empty() {
            return Err(BuildError::Configuration);
        }
        for field in &mut self.fields {
            if field.name == path
                || field
                    .name
                    .strip_prefix(path)
                    .is_some_and(|s| s.starts_with('.'))
            {
                found = true;
                field.sort = false;
                field.reason = Some(reason.into());
            }
        }
        if !found {
            return Err(BuildError::Unsupported(path.into()));
        }
        Ok(self)
    }
}

struct Compiler<'a> {
    root: &'a Value,
    fields: BTreeMap<String, Field>,
    exclusions: &'a [Exclusion],
    used: BTreeSet<&'static str>,
}
impl Compiler<'_> {
    fn walk(&mut self, schema: &Value, path: &str, nullable: bool, depth: usize) -> Result<()> {
        if depth > 32 || path.len() > crate::MAX_SELECTOR_BYTES {
            return Err(BuildError::Unsupported(path.into()));
        }
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            let target = reference
                .strip_prefix('#')
                .and_then(|p| self.root.pointer(p))
                .ok_or_else(|| BuildError::Unsupported(path.into()))?;
            self.walk(target, path, nullable, depth + 1)?;
            if let Some(field) = self.fields.get_mut(path) {
                copy_constraints(&mut field.constraints, schema);
            }
            return Ok(());
        }
        if let Some(exclusion) = self.exclusions.iter().find(|e| e.path == path) {
            self.used.insert(exclusion.path);
            let (kind, constraints, optional) = excluded_shape(self.root, schema, path, depth + 1)?;
            let mut field = Field::scalar(path, kind).excluded(exclusion.reason);
            field.constraints = constraints;
            field.output = !path.contains('.');
            field.nullable = nullable || optional;
            return self.insert(field);
        }
        let null = nullable
            || schema
                .get("type")
                .and_then(Value::as_array)
                .is_some_and(|types| types.iter().any(|t| t == "null"));
        let types = schema.get("type").and_then(Value::as_array);
        let kind = schema.get("type").and_then(Value::as_str).or_else(|| {
            types.and_then(|v| v.iter().find_map(|t| t.as_str().filter(|t| *t != "null")))
        });
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            if !path.is_empty() {
                let mut field = Field::output(path);
                field.output = !path.contains('.');
                field.nullable = null;
                self.insert(field)?;
            }
            let required = schema.get("required").and_then(Value::as_array);
            for (name, child) in properties {
                if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') || name.is_empty()
                {
                    return Err(BuildError::Unsupported(format!("{path}.{name}")));
                }
                let child_path = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                };
                let optional = !required.is_some_and(|v| v.iter().any(|n| n == name));
                self.walk(child, &child_path, null || optional, depth + 1)?;
            }
            self.extensions(schema, path)?;
        } else if kind == Some("object") {
            if path.is_empty() {
                return Err(BuildError::Unsupported(path.into()));
            }
            let mut field = Field::output(path);
            field.output = !path.contains('.');
            field.nullable = null;
            self.insert(field)?;
            let names = schema
                .get("propertyNames")
                .map(|keys| scalar_kind(self.root, keys, path, depth + 1))
                .transpose()?;
            if let Some((Kind::Enum(names), _)) = names {
                let value = schema
                    .get("additionalProperties")
                    .ok_or_else(|| BuildError::Unsupported(path.into()))?;
                for name in names {
                    if name.is_empty()
                        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    {
                        return Err(BuildError::Unsupported(path.into()));
                    }
                    self.walk(value, &format!("{path}.{name}"), true, depth + 1)?;
                }
            } else {
                self.extensions(schema, path)?;
            }
        } else if kind == Some("array") {
            let items = schema
                .get("items")
                .ok_or_else(|| BuildError::Unsupported(path.into()))?;
            let (item_kind, constraints) = scalar_kind(self.root, items, path, depth + 1)?;
            let set = match item_kind {
                Kind::Text => Kind::TextSet,
                Kind::Uuid => Kind::UuidSet,
                Kind::Integer => Kind::IntegerSet,
                Kind::Number => Kind::NumberSet,
                Kind::Boolean => Kind::BooleanSet,
                Kind::Enum(v) => Kind::EnumSet(v),
                _ => return Err(BuildError::Unsupported(path.into())),
            };
            let mut field = Field::scalar(path, set);
            field.constraints = constraints;
            field.output = !path.contains('.');
            field.nullable = null;
            self.insert(field)?;
        } else if kind != Some("null")
            && (kind.is_some() || schema.get("enum").is_some() || schema.get("const").is_some())
        {
            let (kind, constraints) = scalar_kind(self.root, schema, path, depth + 1)?;
            let mut field = Field::scalar(path, kind);
            field.constraints = constraints;
            field.output = !path.contains('.');
            field.nullable = null;
            self.insert(field)?;
        }
        let mut branched = false;
        for keyword in ["allOf", "oneOf", "anyOf"] {
            if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
                branched = true;
                if keyword == "allOf" {
                    for branch in branches {
                        self.walk(branch, path, null, depth + 1)?;
                    }
                    continue;
                }
                let mut alternatives = Vec::new();
                let mut counts = BTreeMap::<String, usize>::new();
                for branch in branches {
                    let mut alternative = Compiler {
                        root: self.root,
                        fields: BTreeMap::new(),
                        exclusions: self.exclusions,
                        used: BTreeSet::new(),
                    };
                    alternative.walk(branch, path, null, depth + 1)?;
                    for name in alternative.fields.keys() {
                        *counts.entry(name.clone()).or_default() += 1;
                    }
                    self.used.extend(alternative.used);
                    alternatives.push(alternative.fields);
                }
                for fields in alternatives {
                    for (name, mut field) in fields {
                        field.nullable |= counts[&name] != branches.len();
                        self.insert(field)?;
                    }
                }
            }
        }
        if kind.is_none()
            && schema.get("properties").is_none()
            && !branched
            && schema.get("enum").is_none()
            && schema.get("const").is_none()
        {
            return Err(BuildError::Unsupported(path.into()));
        }
        Ok(())
    }
    fn extensions(&mut self, schema: &Value, path: &str) -> Result<()> {
        if schema
            .get("additionalProperties")
            .is_some_and(|s| s != &Value::Bool(false))
        {
            let name = if path.is_empty() {
                "*".into()
            } else {
                format!("{path}.*")
            };
            self.insert(Field::output(&name).without_output().excluded("Dynamic extension keys have no declared selector type; use the owner's field catalog when available"))?;
        }
        Ok(())
    }
    fn insert(&mut self, mut field: Field) -> Result<()> {
        if let Some(old) = self.fields.get_mut(&field.name) {
            old.kind = merge(&old.kind, &field.kind)
                .ok_or_else(|| BuildError::Conflict(field.name.clone()))?;
            old.nullable |= field.nullable;
            // Branch-specific const/enum validation is represented by the merged vocabulary.
            if matches!(old.kind, Kind::Enum(_) | Kind::EnumSet(_)) {
                old.constraints = Value::Null;
            }
            return Ok(());
        }
        if field.kind.collection() {
            field.sort = false;
        }
        self.fields.insert(field.name.clone(), field);
        Ok(())
    }
}
fn merge(a: &Kind, b: &Kind) -> Option<Kind> {
    match (a, b) {
        (Kind::Enum(a), Kind::Enum(b)) => Some(Kind::Enum(
            a.iter()
                .chain(b)
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        )),
        (Kind::EnumSet(a), Kind::EnumSet(b)) => Some(Kind::EnumSet(
            a.iter()
                .chain(b)
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        )),
        (Kind::Text, Kind::Uuid | Kind::Enum(_)) | (Kind::Uuid | Kind::Enum(_), Kind::Text) => {
            Some(Kind::Text)
        }
        (Kind::TextSet, Kind::UuidSet | Kind::EnumSet(_))
        | (Kind::UuidSet | Kind::EnumSet(_), Kind::TextSet) => Some(Kind::TextSet),
        (Kind::Integer, Kind::Number) | (Kind::Number, Kind::Integer) => Some(Kind::Number),
        _ if a == b => Some(a.clone()),
        _ => None,
    }
}
fn scalar_kind(root: &Value, schema: &Value, path: &str, depth: usize) -> Result<(Kind, Value)> {
    if depth > 32 || path.len() > crate::MAX_SELECTOR_BYTES {
        return Err(BuildError::Unsupported(path.into()));
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let value = reference
            .strip_prefix('#')
            .and_then(|p| root.pointer(p))
            .ok_or_else(|| BuildError::Unsupported(path.into()))?;
        return scalar_kind(root, value, path, depth + 1);
    }
    let vocabulary = schema
        .get("enum")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| schema.get("const").map(|v| vec![v.clone()]));
    let kind = if let Some(values) = vocabulary
        .as_ref()
        .filter(|v| !v.is_empty() && v.iter().all(Value::is_string))
    {
        Kind::Enum(
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        )
    } else {
        let name = schema["type"].as_str().or_else(|| {
            schema["type"]
                .as_array()
                .and_then(|v| v.iter().find_map(|t| t.as_str().filter(|t| *t != "null")))
        });
        match name {
            Some("string") if schema["format"] == "uuid" => Kind::Uuid,
            Some("string") => Kind::Text,
            Some("integer") => Kind::Integer,
            Some("number") => Kind::Number,
            Some("boolean") => Kind::Boolean,
            _ => {
                let branches = schema
                    .get("oneOf")
                    .or_else(|| schema.get("anyOf"))
                    .and_then(Value::as_array)
                    .ok_or_else(|| BuildError::Unsupported(path.into()))?;
                let mut kind = None;
                for branch in branches {
                    if branch["type"] == "null" {
                        continue;
                    }
                    let (next, _) = scalar_kind(root, branch, path, depth + 1)?;
                    kind = Some(match kind {
                        None => next,
                        Some(previous) => merge(&previous, &next)
                            .ok_or_else(|| BuildError::Conflict(path.into()))?,
                    });
                }
                kind.ok_or_else(|| BuildError::Unsupported(path.into()))?
            }
        }
    };
    let mut constraints = Value::Object(Default::default());
    copy_constraints(&mut constraints, schema);
    Ok((kind, constraints))
}
fn copy_constraints(target: &mut Value, schema: &Value) {
    if !target.is_object() {
        *target = Value::Object(Default::default());
    }
    for key in [
        "enum",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "x-rss-maxUtf8Bytes",
    ] {
        if let Some(value) = schema.get(key) {
            target[key] = value.clone();
        }
    }
}

// Excluding an executable capability must not change its public type or optionality.
fn excluded_shape(
    root: &Value,
    value: &Value,
    path: &str,
    depth: usize,
) -> Result<(Kind, Value, bool)> {
    if depth > 32 {
        return Err(BuildError::Unsupported(path.into()));
    }
    if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        return excluded_shape(
            root,
            reference
                .strip_prefix('#')
                .and_then(|p| root.pointer(p))
                .ok_or_else(|| BuildError::Unsupported(path.into()))?,
            path,
            depth + 1,
        );
    }
    let nullable = value
        .get("type")
        .and_then(Value::as_array)
        .is_some_and(|v| v.iter().any(|t| t == "null"));
    for keyword in ["anyOf", "oneOf"] {
        if let Some(branches) = value.get(keyword).and_then(Value::as_array) {
            let mut found: Option<(Kind, Value, bool)> = None;
            let mut null = nullable;
            for branch in branches {
                if branch["type"] == "null" {
                    null = true;
                    continue;
                }
                let (kind, constraints, optional) = excluded_shape(root, branch, path, depth + 1)?;
                null |= optional;
                found = Some(match found {
                    None => (kind, constraints, null),
                    Some((old, _, _)) => (
                        merge(&old, &kind).ok_or_else(|| BuildError::Conflict(path.into()))?,
                        Value::Null,
                        null,
                    ),
                });
            }
            return found
                .map(|(k, c, _)| (k, c, null))
                .ok_or_else(|| BuildError::Unsupported(path.into()));
        }
    }
    if value["type"] == "array"
        || value
            .get("type")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|t| t == "array"))
    {
        let (kind, constraints) = scalar_kind(root, &value["items"], path, depth + 1)
            .unwrap_or((Kind::Object, Value::Null));
        let kind = match kind {
            Kind::Text => Kind::TextSet,
            Kind::Uuid => Kind::UuidSet,
            Kind::Integer => Kind::IntegerSet,
            Kind::Number => Kind::NumberSet,
            Kind::Boolean => Kind::BooleanSet,
            Kind::Enum(v) => Kind::EnumSet(v),
            _ => Kind::ObjectSet,
        };
        return Ok((kind, constraints, nullable));
    }
    let (kind, constraints) =
        scalar_kind(root, value, path, depth + 1).unwrap_or((Kind::Object, Value::Null));
    Ok((kind, constraints, nullable))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_rejects_paths_outside_the_query_grammar_budget() {
        let child = "c".repeat(100);
        let parent = "p".repeat(50);
        let model = serde_json::json!({"type":"object","required":["id"],"properties":{"id":{"type":"integer"},parent:{"type":"object","properties":{child:{"type":"string"}}}}});
        assert!(Schema::from_model("long_path", &["id"], 1, 10, &model, &[]).is_err());
    }

    #[test]
    fn documented_closed_map_keys_keep_their_declared_types() {
        let model = serde_json::json!({"type":"object","required":["id"],"properties":{
            "id":{"type":"string","format":"uuid"},
            "packages":{"type":"object","propertyNames":{"oneOf":[
                {"type":"string","const":"windows","description":"Windows"},
                {"type":"string","const":"macos","description":"macOS"}
            ]},"additionalProperties":{"type":"string","format":"uuid"}}
        }});
        let schema = Box::leak(Box::new(
            Schema::from_model("closed_map", &["id"], 1, 10, &model, &[]).unwrap(),
        ));
        assert_eq!(schema.field("packages.windows").unwrap().kind, Kind::Uuid);
        assert!(
            schema
                .parse("filter=packages.linux==00000000-0000-0000-0000-000000000001")
                .is_err()
        );
        assert!(
            schema
                .parse("filter=id=gt=00000000-0000-0000-0000-000000000001")
                .is_ok()
        );
    }
}
