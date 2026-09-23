use rss_mdm_resource::{Platform, ScriptDefinition};
use serde_json::{Value, json};

fn definition() -> Value {
    json!({"profile":"posix_sh","runAs":"system","encoding":"utf8",
        "parameters":{"type":"object","properties":{"name":{"type":"string","maxLength":32}},"required":["name"],"additionalProperties":false},
        "bindings":{"name":{"kind":"positional","index":0}},
        "output":{"type":"object","properties":{"version":{"type":"string"}},"required":["version"],"additionalProperties":false},
        "purpose":{"kind":"collection","mappings":{"custom.corporate_agent.version":"/version"}},
        "timeoutSeconds":60,"outputBytes":4096,"maxRows":1})
}

#[test]
fn script_contract_validates_parameters_output_and_platform() {
    let script: ScriptDefinition = serde_json::from_value(definition()).unwrap();
    assert!(script.validate_platform(Platform::MacOS).is_ok());
    assert!(script.validate_platform(Platform::Windows).is_err());
    assert!(
        script
            .validate_parameters(&json!({"name":"a; rm -rf /"}))
            .is_ok()
    );
    assert!(script.validate_parameters(&json!({"name":7})).is_err());
    assert!(
        script
            .validate_parameters(&json!({"name":"a","extra":true}))
            .is_err()
    );
    assert!(script.validate_output(&json!({"version":"1.2"})).is_ok());
    assert!(script.validate_output(&json!({"version":false})).is_err());
}

#[test]
fn script_contract_rejects_legacy_external_schema_and_hidden_arguments() {
    for mutate in [
        |v: &mut Value| {
            v.as_object_mut().unwrap().remove("purpose");
        },
        |v: &mut Value| {
            v["parameters"]["$ref"] = json!("https://internal/secret");
        },
        |v: &mut Value| {
            v["bindings"]["other"] = json!({"kind":"positional","index":1});
        },
        |v: &mut Value| {
            v["bindings"]["name"] = json!({"kind":"environment","name":"BASH_ENV"});
        },
        |v: &mut Value| {
            v["timeoutSeconds"] = json!(0);
        },
        |v: &mut Value| {
            v["purpose"]["mappings"] = json!({"custom.asset_tag":"/version"});
        },
    ] {
        let mut v = definition();
        mutate(&mut v);
        assert!(serde_json::from_value::<ScriptDefinition>(v).is_err());
    }
}

fn version(value: Value) -> rss_mdm_resource::Version {
    use rss_mdm_resource::*;
    Version::new(
        rss_request_context::TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap(),
        Id::new("script").unwrap(),
        Id::new("v1").unwrap(),
        Kind::Script,
        vec![Variant::new(
            Platform::MacOS,
            Architecture::Aarch64,
            Id::new("native").unwrap(),
            Declaration::Script {
                artifact: Artifact::new(Id::new("content").unwrap(), 3, Digest::of(b"abc"))
                    .unwrap(),
                definition: serde_json::from_value(value).unwrap(),
            },
        )],
    )
    .unwrap()
}

#[test]
fn frozen_digest_covers_execution_interface_and_rejects_old_script() {
    let base = version(definition());
    for mutate in [
        |v: &mut Value| {
            v["timeoutSeconds"] = json!(61);
        },
        |v: &mut Value| {
            v["outputBytes"] = json!(4097);
        },
        |v: &mut Value| {
            v["maxRows"] = json!(2);
        },
        |v: &mut Value| {
            v["profile"] = json!("bash");
        },
        |v: &mut Value| {
            v["runAs"] = json!("logged_in_user");
        },
        |v: &mut Value| {
            v["parameters"]["properties"]["name"]["maxLength"] = json!(31);
        },
        |v: &mut Value| {
            v["output"]["properties"]["version"]["maxLength"] = json!(255);
        },
        |v: &mut Value| {
            v["purpose"] = json!({"kind":"action"});
        },
        |v: &mut Value| {
            v["bindings"]["name"] = json!({"kind":"environment","name":"RSS_PARAM_NAME"});
        },
    ] {
        let mut value = definition();
        mutate(&mut value);
        assert_ne!(base.digest(), version(value).digest());
    }
    let decoded: Value = serde_json::from_str(&definition().to_string()).unwrap();
    assert_eq!(base.digest(), version(decoded).digest());
    assert!(
        serde_json::from_value::<ScriptDefinition>(
            json!({"interpreter":"sh","detect":"exit-code"})
        )
        .is_err()
    );
}

#[test]
fn successful_output_must_supply_the_declared_inventory_type() {
    let mut value = definition();
    value["output"] = json!({});
    value["purpose"]["mappings"] = json!({"custom.corporate_agent.healthy":"/healthy"});
    let script: ScriptDefinition = serde_json::from_value(value).unwrap();
    assert!(script.validate_output(&json!({"healthy":true})).is_ok());
    for bad in [
        json!({}),
        json!({"healthy":"true"}),
        json!({"healthy":null}),
    ] {
        assert!(script.validate_output(&bad).is_err());
    }
}

#[test]
fn schema_cost_and_nested_output_are_bounded_before_validation() {
    let mut value = definition();
    value["purpose"] = json!({"kind":"action"});
    value["output"] = json!({});
    let script: ScriptDefinition = serde_json::from_value(value.clone()).unwrap();
    assert!(script.validate_output(&json!({"nested":[[1,2]]})).is_err());
    assert!(script.validate_output(&json!({"nested":[[1]]})).is_ok());
    for schema in [
        json!({"pattern":"(a+)+$"}),
        json!({"oneOf":[{},{}]}),
        json!({"$ref":"#"}),
        json!({"additionalProperties":true}),
    ] {
        value["output"] = schema;
        assert!(serde_json::from_value::<ScriptDefinition>(value.clone()).is_err());
    }
}
