//! Check real mounted response rows against the model that owns executable directory fields.
use crate::{DirectoryRole, Endpoint, EndpointContract, QueryDeclaration, signature::Signature};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MARKER: &str = "x-rss-directory-model";
fn target<'a>(root: &'a Value, value: &'a Value) -> Option<&'a Value> {
    value
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|r| r.strip_prefix('#'))
        .and_then(|p| root.pointer(p))
}
fn annotation(key: &str) -> bool {
    matches!(
        key,
        "$schema" | "$defs" | "title" | "description" | "examples" | "default" | MARKER
    )
}
fn same_model(
    a: &Value,
    ar: &Value,
    b: &Value,
    br: &Value,
    seen: &mut BTreeSet<(String, String)>,
    depth: usize,
) -> bool {
    if depth > 96 {
        return false;
    }
    let at = target(ar, a);
    let bt = target(br, b);
    if at.is_some() || bt.is_some() {
        let key = (a.to_string(), b.to_string());
        if !seen.insert(key) {
            return true;
        }
        let extra = |v: &Value| {
            v.as_object()
                .is_some_and(|o| o.keys().any(|k| k != "$ref" && !annotation(k)))
        };
        if at.is_some() && bt.is_none() && extra(a) || bt.is_some() && at.is_none() && extra(b) {
            return false;
        }
        if !same_model(at.unwrap_or(a), ar, bt.unwrap_or(b), br, seen, depth + 1) {
            return false;
        }
        if at.is_none() || bt.is_none() {
            return true;
        }
    }
    match (a, b) {
        (Value::Object(a), Value::Object(b)) => {
            let keys = |v: &serde_json::Map<String, Value>| {
                v.keys()
                    .filter(|k| k.as_str() != "$ref" && !annotation(k))
                    .cloned()
                    .collect::<BTreeSet<_>>()
            };
            let ak = keys(a);
            let bk = keys(b);
            ak == bk
                && ak
                    .iter()
                    .all(|k| same_model(&a[k], ar, &b[k], br, seen, depth + 1))
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|(a, b)| same_model(a, ar, b, br, seen, depth + 1))
        }
        _ => a == b,
    }
}
fn markers<'a>(
    value: &'a Value,
    root: &'a Value,
    row: bool,
    active: &mut BTreeSet<String>,
    found: &mut Vec<&'a Value>,
) {
    if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        if active.insert(reference.into()) {
            if let Some(next) = target(root, value) {
                markers(next, root, row, active, found);
            }
            active.remove(reference);
        }
    }
    if row {
        if let Some(marker) = value.get(MARKER) {
            found.push(marker);
        }
        // Do not accept an unrelated nested collection as this directory's row.
        for key in ["allOf", "oneOf", "anyOf"] {
            if let Some(branches) = value.get(key).and_then(Value::as_array) {
                for branch in branches {
                    markers(branch, root, true, active, found);
                }
            }
        }
        return;
    }
    if let Some(properties) = value.get("properties").and_then(Value::as_object) {
        for (name, child) in properties {
            if name == "items" {
                let before = found.len();
                let array = target(root, child).unwrap_or(child);
                if let Some(item) = array.get("items") {
                    markers(item, root, true, active, found);
                }
                // An unrelated valid nested Page cannot hide an unbound primary items slot.
                if found.len() == before {
                    found.push(child);
                }
            } else {
                markers(child, root, false, active, found);
            }
        }
    }
    for key in ["allOf", "oneOf", "anyOf"] {
        if let Some(branches) = value.get(key).and_then(Value::as_array) {
            for branch in branches {
                markers(branch, root, false, active, found);
            }
        }
    }
}
pub(crate) fn signature(signature: &Signature) -> Vec<String> {
    let Some(QueryDeclaration::Directory(directory)) = signature.request.query_owner else {
        return vec![];
    };
    if directory.role == DirectoryRole::Statistics {
        return vec![];
    }
    let schema = directory.execution.schema();
    let mut errors = Vec::new();
    let mut count = 0;
    for response in signature
        .responses
        .iter()
        .filter(|r| (200..300).contains(&r.status))
    {
        let Some(body) = response
            .body
            .as_ref()
            .filter(|b| b.content_type == "application/json")
        else {
            continue;
        };
        let root = &body.schema.value;
        let mut rows = Vec::new();
        markers(root, root, false, &mut BTreeSet::new(), &mut rows);
        count += rows.len();
        for marker in rows {
            if marker.get("identity").and_then(Value::as_str) != Some(schema.model_identity())
                || !marker.get("schema").is_some_and(|actual| {
                    same_model(
                        actual,
                        root,
                        schema.model(),
                        schema.model(),
                        &mut BTreeSet::new(),
                        0,
                    )
                })
            {
                errors.push(format!(
                    "directory {} response row differs from its public model {}",
                    schema.id,
                    schema.model_identity()
                ));
            }
        }
    }
    if count == 0 {
        errors.push(format!(
            "directory {} has no bound public row at its successful response items",
            schema.id
        ));
    }
    errors
}
pub(crate) fn pairs<'a>(endpoints: impl IntoIterator<Item = &'a Endpoint>) -> Vec<String> {
    let mut owners = BTreeMap::new();
    let mut statistics = Vec::new();
    let mut errors = Vec::new();
    for endpoint in endpoints {
        let EndpointContract::Product(signature) = &endpoint.contract else {
            continue;
        };
        let Some(QueryDeclaration::Directory(directory)) = signature.request.query_owner else {
            continue;
        };
        let schema = directory.execution.schema();
        if directory.role == DirectoryRole::Statistics {
            statistics.push(schema);
        } else if let Some(previous) = owners.insert(schema.id, schema)
            && !std::ptr::eq(previous, schema)
        {
            errors.push(format!(
                "directory {} has multiple model/execution owners",
                schema.id
            ));
        }
    }
    for schema in statistics {
        if !owners
            .get(schema.id)
            .is_some_and(|list| std::ptr::eq(*list, schema))
        {
            errors.push(format!(
                "statistics {} has no list with the same model/execution owner",
                schema.id
            ));
        }
    }
    errors
}
