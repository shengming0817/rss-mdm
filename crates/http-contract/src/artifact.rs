//! Pure-data projection of the product's actual mounted routers.
use crate::Endpoint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The caller is the product composition root. This function never discovers or registers routes.
pub fn document(
    listeners: impl IntoIterator<Item = (&'static str, Vec<Endpoint>)>,
) -> Result<Value, Vec<String>> {
    let mut mounted = Vec::new();
    let mut errors = Vec::new();
    let mut external = Vec::new();
    let mut routes = BTreeSet::new();
    for (listener, endpoints) in listeners {
        if listener.is_empty() {
            errors.push("missing listener identity".into());
        }
        for endpoint in endpoints {
            let key = (listener, endpoint.method, endpoint.path.clone());
            if !routes.insert(key) {
                errors.push(format!(
                    "{listener} {} {}: duplicate mount",
                    endpoint.method, endpoint.path
                ));
            }
            let crate::EndpointContract::Product(signature) = &endpoint.contract else {
                external.push(json!({"listener":listener,"method":endpoint.method,"path":endpoint.path,"owner":endpoint.resource.owner,"protocol":endpoint.contract,"conditions":endpoint.conditions}));
                continue;
            };
            let handler_path = match &endpoint.configured_path {
                Some(binding) => endpoint
                    .path
                    .replace(&binding.capture(), "configured-static-segment"),
                None => endpoint.path.clone(),
            };
            for error in crate::validation::signature(signature, &handler_path) {
                errors.push(format!(
                    "{listener} {} {}: {error}",
                    endpoint.method, endpoint.path
                ));
            }
            mounted.push((listener, endpoint));
        }
    }
    let mut overrides = BTreeMap::new();
    for (listener, endpoint) in &mounted {
        if let Some(binding) = &endpoint.configured_path {
            let parts = endpoint.path.split('/').collect::<Vec<_>>();
            let candidates = mounted
                .iter()
                .filter(|(other_listener, other)| {
                    if other_listener != listener
                        || other.method != endpoint.method
                        || other.configured_path.is_some()
                    {
                        return false;
                    }
                    let other = other.path.split('/').collect::<Vec<_>>();
                    parts.len() == other.len()
                        && parts.iter().zip(other).all(|(a, b)| {
                            if *a == binding.capture() {
                                b.starts_with('{') && b.ends_with('}')
                            } else {
                                *a == b
                            }
                        })
                })
                .collect::<Vec<_>>();
            if candidates.len() != 1 {
                errors.push(format!("{listener} {} {}: configured static route must override exactly one capture route",endpoint.method,endpoint.path));
            } else {
                overrides.insert(
                    (
                        (*listener).to_owned(),
                        endpoint.method.to_owned(),
                        endpoint.path.clone(),
                    ),
                    format!(
                        "{listener}:{}:{}",
                        candidates[0].1.method, candidates[0].1.path
                    ),
                );
            }
        }
    }
    if mounted.is_empty() {
        errors.push("no mounted product endpoints".into());
    }
    if !errors.is_empty() {
        errors.sort();
        errors.dedup();
        return Err(errors);
    }
    mounted.sort_by(|(a, x), (b, y)| (a, x.method, &x.path).cmp(&(b, y.method, &y.path)));
    let mut schemas = BTreeMap::new();
    let endpoints = mounted.into_iter().map(|(listener, endpoint)| {
        let crate::EndpointContract::Product(signature) = &endpoint.contract else { unreachable!("product routes collected above") };
        let mut request = serde_json::to_value(&signature.request).expect("closed request description");
        for name in ["path", "query"] { intern(&mut request[name], &mut schemas); }
        if request["body"].is_object() { intern(&mut request["body"]["schema"], &mut schemas); }
        if let Some(headers) = request["headers"].as_object_mut() { for schema in headers.values_mut() { intern(schema, &mut schemas); } }
        // Rejections are already included in responses; keep one consumer-facing response set.
        request.as_object_mut().expect("request object").remove("rejections");
        let mut responses = serde_json::to_value(&signature.responses).expect("closed response description");
        for response in responses.as_array_mut().expect("responses array") {
            if response["body"].is_object() { intern(&mut response["body"]["schema"], &mut schemas); }
            for schema in response["headers"].as_object_mut().expect("response headers").values_mut() { intern(schema, &mut schemas); }
        }
        json!({
            "operationId": format!("{listener}:{}:{}", endpoint.method, endpoint.path),
            "listener":listener, "method":endpoint.method, "path":endpoint.path,
            "resource":endpoint.resource, "operations":endpoint.operations,
            "handler":endpoint.operation_id,
            "conditions":endpoint.conditions,
            "configuredPath":endpoint.configured_path.as_ref().map(|binding|json!({"kind":"configured_static","name":binding.name,"source":binding.source,"schema":binding.schema(),"selection":"configured_static_precedes_capture","overrides":overrides.get(&(listener.to_owned(),endpoint.method.to_owned(),endpoint.path.clone()))})),
            "request":request, "responses":responses,
        })
    }).collect::<Vec<_>>();
    external.sort_by(|a, b| {
        (
            a["listener"].as_str(),
            a["method"].as_str(),
            a["path"].as_str(),
        )
            .cmp(&(
                b["listener"].as_str(),
                b["method"].as_str(),
                b["path"].as_str(),
            ))
    });
    Ok(
        json!({"formatVersion":1,"schemaDialect":"https://json-schema.org/draft/2020-12/schema", "endpoints":endpoints, "schemas":schemas, "external":external}),
    )
}

fn intern(description: &mut Value, schemas: &mut BTreeMap<String, Value>) {
    let Some(object) = description.as_object_mut() else {
        return;
    };
    let Some(value) = object.remove("value") else {
        return;
    };
    let bytes = serde_json::to_vec(&value).expect("schema JSON");
    let id = format!("sha256-{:x}", Sha256::digest(bytes));
    schemas.entry(id.clone()).or_insert(value);
    object.insert("schemaId".into(), id.into());
}
