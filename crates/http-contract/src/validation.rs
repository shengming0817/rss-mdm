//! Deterministic export checks complement, and do not replace, Rust signature binding.
use crate::signature::{Schema, Signature};
use schemars::transform::{Transform, transform_subschemas};
use serde_json::Value;
use std::collections::BTreeSet;

fn walk(
    value: &Value,
    root: &Value,
    path: &str,
    seen: &mut BTreeSet<String>,
    errors: &mut BTreeSet<String>,
) {
    if value
        .get("x-rss-extension")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty())
    {
        return;
    }
    if value == &Value::Bool(true)
        || value.as_object().is_some_and(|o| {
            !o.keys().any(|k| {
                matches!(
                    k.as_str(),
                    "type"
                        | "$ref"
                        | "$dynamicRef"
                        | "enum"
                        | "const"
                        | "anyOf"
                        | "oneOf"
                        | "allOf"
                        | "not"
                        | "if"
                        | "then"
                        | "else"
                        | "properties"
                        | "patternProperties"
                        | "additionalProperties"
                        | "propertyNames"
                        | "dependentSchemas"
                        | "dependentRequired"
                        | "required"
                        | "minProperties"
                        | "maxProperties"
                        | "unevaluatedProperties"
                        | "pattern"
                        | "minLength"
                        | "maxLength"
                        | "format"
                        | "minimum"
                        | "maximum"
                        | "exclusiveMinimum"
                        | "exclusiveMaximum"
                        | "multipleOf"
                        | "items"
                        | "prefixItems"
                        | "minItems"
                        | "maxItems"
                        | "uniqueItems"
                        | "contains"
                        | "minContains"
                        | "maxContains"
                        | "unevaluatedItems"
                )
            })
        })
    {
        errors.insert(format!("{path}: unbound JSON structure; use the real owner type or an explicit extension subtree"));
    }
    if let Some(reference) = value.get("$ref").and_then(Value::as_str)
        && seen.insert(reference.to_owned())
        && let Some(target) = reference.strip_prefix('#').and_then(|p| root.pointer(p))
    {
        walk(target, root, reference, seen, errors);
    }
    // Follow only reachable definitions. Filtering a real closed response variant may leave
    // unused $defs; they do not broaden that response. All references are checked separately.
    for key in ["properties", "patternProperties", "dependentSchemas"] {
        if let Some(map) = value.get(key).and_then(Value::as_object) {
            for (name, child) in map {
                let name = name.replace('~', "~0").replace('/', "~1");
                walk(child, root, &format!("{path}/{key}/{name}"), seen, errors);
            }
        }
    }
    for key in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(items) = value.get(key).and_then(Value::as_array) {
            for (index, child) in items.iter().enumerate() {
                walk(child, root, &format!("{path}/{key}/{index}"), seen, errors);
            }
        }
    }
    for key in [
        "items",
        "additionalProperties",
        "propertyNames",
        "contains",
        "unevaluatedItems",
        "unevaluatedProperties",
        "not",
        "if",
        "then",
        "else",
        "contentSchema",
    ] {
        if let Some(child) = value.get(key) {
            walk(child, root, &format!("{path}/{key}"), seen, errors);
        }
    }
}
fn check_reference(reference: &Value, root: &Value, errors: &mut BTreeSet<String>) {
    let valid = reference
        .as_str()
        .and_then(|r| r.strip_prefix('#'))
        .is_some_and(|p| {
            root.pointer(p)
                .is_some_and(|v| v.is_object() || v.is_boolean())
        });
    if !valid {
        errors.insert(format!("unresolved schema reference: {reference}"));
    }
}
fn references(value: &Value, root: &Value, errors: &mut BTreeSet<String>) {
    struct References<'a> {
        root: &'a Value,
        errors: &'a mut BTreeSet<String>,
    }
    impl Transform for References<'_> {
        fn transform(&mut self, schema: &mut schemars::Schema) {
            if schema.get("$dynamicRef").is_some() {
                self.errors.insert("dynamic schema references are unsupported; export a self-contained local reference".into());
            }
            if let Some(reference) = schema.get("$ref") {
                check_reference(reference, self.root, self.errors);
            }
            transform_subschemas(self, schema);
        }
    }
    if let Ok(mut schema) = schemars::Schema::try_from(value.clone()) {
        References { root, errors }.transform(&mut schema);
    }
}
pub fn schema(schema: &Schema) -> Vec<String> {
    if !schema.value.is_object() && !schema.value.is_boolean() {
        return vec!["schema is neither an object nor a boolean".into()];
    }
    let mut errors = BTreeSet::new();
    references(&schema.value, &schema.value, &mut errors);
    walk(
        &schema.value,
        &schema.value,
        "#",
        &mut BTreeSet::new(),
        &mut errors,
    );
    errors.into_iter().collect()
}

pub fn signature(signature: &Signature, path: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let parameters = path
        .split('/')
        .filter(|s| s.starts_with('{') && s.ends_with('}'))
        .count();
    if (parameters > 0) != signature.request.path.is_some() {
        errors.push("mounted path and handler path extractor disagree".into());
    }
    if let Some(path_schema) = &signature.request.path {
        let mut value = &path_schema.value;
        let mut seen = BTreeSet::new();
        while let Some(reference) = value.get("$ref").and_then(Value::as_str) {
            if !seen.insert(reference) {
                break;
            }
            let Some(resolved) = reference
                .strip_prefix('#')
                .and_then(|p| path_schema.value.pointer(p))
            else {
                break;
            };
            value = resolved;
        }
        let arity = if let Some(items) = value.get("prefixItems").and_then(Value::as_array) {
            items.len()
        } else if let Some(fields) = value.get("properties").and_then(Value::as_object) {
            for capture in path
                .split('/')
                .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
            {
                if !fields.contains_key(capture.trim_start_matches('*')) {
                    errors.push(format!("path capture {capture} has no extractor field"));
                }
            }
            fields.len()
        } else {
            1
        };
        if arity != parameters {
            errors.push("mounted path capture count differs from extractor shape".into());
        }
    }
    for (name, value) in [
        ("path", signature.request.path.as_ref()),
        ("query", signature.request.query.as_ref()),
    ] {
        if let Some(value) = value {
            errors.extend(schema(value).into_iter().map(|e| format!("{name}: {e}")));
        }
    }
    if let Some(body) = &signature.request.body {
        errors.extend(
            schema(&body.schema)
                .into_iter()
                .map(|e| format!("request body: {e}")),
        );
    }
    for (name, value) in &signature.request.headers {
        errors.extend(
            schema(value)
                .into_iter()
                .map(|e| format!("request header {name}: {e}")),
        );
    }
    if signature.responses.is_empty() {
        errors.push("handler has no response contract".into());
    }
    for response in &signature.responses {
        if !(200..=599).contains(&response.status) {
            errors.push(format!("invalid status {}", response.status));
        }
        if let Some(body) = &response.body {
            if matches!(response.status, 204 | 304) {
                errors.push(format!("status {} cannot carry a body", response.status));
            }
            errors.extend(
                schema(&body.schema)
                    .into_iter()
                    .map(|e| format!("response {}: {e}", response.status)),
            );
        }
        for (name, value) in &response.headers {
            errors.extend(
                schema(value)
                    .into_iter()
                    .map(|e| format!("response header {name}: {e}")),
            );
        }
    }
    errors
}
