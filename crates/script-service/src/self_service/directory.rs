//! Current self-service qualification belongs to the business owner.
use super::*;
pub async fn describe_in(
    service: &ScriptService,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    proof: Option<&AuthorizedPrincipal>,
    source: wire::SelfServiceCaller,
    id: Uuid,
    now: i64,
) -> Result<Option<wire::SelfServiceDirectoryItem>> {
    let Some(policy) =
        crate::policy::current_in(&service.transactions.policy_reader, tx, id).await?
    else {
        return Ok(None);
    };
    let Some(config) = &policy.definition.self_service else {
        return Ok(None);
    };
    if !policy.state.is_enabled()
        || !config.published
        || (source == wire::SelfServiceCaller::Ai && config.allow_ai != Some(true))
    {
        return Ok(None);
    }
    let Some(basis) = access::select(config, proof)? else {
        return Ok(None);
    };
    let Some(subject) = access::qualify_in(service, tx, config, &basis).await? else {
        return Ok(None);
    };
    if !matches!(
        policy.definition.action,
        rss_mdm_policy::Action::Execution { .. }
    ) {
        return Ok(None);
    }
    let plan = crate::policy::read_in(&service.transactions, tx, policy.version).await?;
    let Some(prepared) =
        prepare_in(service, tx, &plan, &target(p), Uuid::new_v4(), None, now).await?
    else {
        return Ok(None);
    };
    let input_schema = input_schema(&plan.frozen.definition, &plan.frozen.parameters);
    let output_schema = plan.frozen.definition.spec().output.clone();
    let mut metadata = metadata(config)?;
    metadata.risk_level = effective_risk(&policy);
    Ok(Some(wire::SelfServiceDirectoryItem {
        capability: wire::CapabilityDescriptor {
            id,
            object_type: wire::CapabilityObject::Policy,
            tool_name: wire::policy_tool_name(id),
            alias: policy.definition.alias.clone(),
            scope: policy.definition.scope,
            instance: service.transactions.instance.clone(),
            tenant: checked_input(Uuid::parse_str(&p.tenant().to_string()))?,
            revision: policy.revision as u64,
            version: policy.version,
            operations: vec![wire::CapabilityOperation::Invoke],
            input_schema,
            output_schema,
        },
        policy_id: id,
        policy_revision: policy.revision as u64,
        policy_version: policy.version,
        subject,
        self_service: metadata,
        task: prepared.task.ok_or(Error::Conflict)?,
    }))
}

// Resource constraints describe the merged execution object; callers supply only Input fields.
fn input_schema(
    definition: &rss_mdm_resource::ScriptDefinition,
    sources: &rss_mdm_policy::ParameterSources,
) -> Value {
    let mut schema = definition.spec().parameters.clone();
    let inputs: Vec<_> = sources
        .0
        .iter()
        .filter_map(|(name, source)| {
            matches!(source, rss_mdm_policy::ParameterSource::Input {}).then_some(name.clone())
        })
        .collect();
    let project = |value: &Value| -> Option<Value> {
        let mut object = value.as_object()?.clone();
        object.retain(|name, _| inputs.contains(name));
        let input = Value::Object(object);
        let merged = sources.resolve(&input).ok()?;
        definition.validate_parameters(&merged).ok()?;
        Some(input)
    };
    if let Some(value) = schema.get("const") {
        let Some(value) = project(value) else {
            return Value::Bool(false);
        };
        schema["const"] = value;
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        let mut projected = Vec::new();
        for value in values.iter().filter_map(project) {
            if !projected.contains(&value) {
                projected.push(value);
            }
        }
        if projected.is_empty() {
            return Value::Bool(false);
        }
        schema["enum"] = json!(projected);
    }
    if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        properties.retain(|name, _| inputs.contains(name));
    }
    schema["required"] = json!(inputs);
    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition(parameters: Value) -> rss_mdm_resource::ScriptDefinition {
        let bindings: serde_json::Map<String, Value> = parameters["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    json!({"kind":"environment","name":format!("RSS_PARAM_{}",name.to_ascii_uppercase())}),
                )
            })
            .collect();
        serde_json::from_value(
            json!({"profile":"posix_sh","runAs":"system","encoding":"utf8",
            "parameters":parameters,"bindings":bindings,
            "output":{"type":"object","properties":{},"additionalProperties":false},
            "purpose":{"kind":"action"},"timeoutSeconds":60,"outputBytes":4096,"maxRows":1}),
        )
        .unwrap()
    }

    #[test]
    fn fixed_object_constraints_accept_empty_call_without_exposing_fixed_values() {
        let sources =
            serde_json::from_value(json!({"path":{"kind":"fixed","value":"/Applications"}}))
                .unwrap();
        for (keyword, value) in [
            ("const", json!({"path":"/Applications"})),
            (
                "enum",
                json!([{"path":"/Applications"},{"path":"/Library"}]),
            ),
        ] {
            let mut parameters = json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false});
            parameters[keyword] = value;
            let definition = definition(parameters);
            let schema = input_schema(&definition, &sources);
            let validator = jsonschema::draft202012::new(&schema).unwrap();
            assert!(validator.is_valid(&json!({})), "{schema}");
            assert!(!validator.is_valid(&json!({"path":"/Applications"})));
            definition
                .validate_parameters(&sources.resolve(&json!({})).unwrap())
                .unwrap();
        }
    }

    #[test]
    fn enum_projection_preserves_input_constraints_and_fixed_value_selection() {
        let sources = serde_json::from_value(
            json!({"path":{"kind":"fixed","value":"/Applications"},"name":{"kind":"input"}}),
        )
        .unwrap();
        let definition = definition(
            json!({"type":"object","properties":{"path":{"type":"string"},"name":{"type":"string","minLength":1}},"required":["path","name"],"additionalProperties":false,
            "enum":[{"path":"/Applications","name":"Allowed"},{"path":"/Library","name":"WrongFixed"}]}),
        );
        let schema = input_schema(&definition, &sources);
        let validator = jsonschema::draft202012::new(&schema).unwrap();
        for input in [
            json!({"name":"Allowed"}),
            json!({"name":"WrongFixed"}),
            json!({"name":""}),
            json!({}),
            json!({"name":"Allowed","path":"/Applications"}),
        ] {
            let accepted = sources
                .resolve(&input)
                .is_ok_and(|value| definition.validate_parameters(&value).is_ok());
            assert_eq!(validator.is_valid(&input), accepted, "{input}");
        }
    }
}
