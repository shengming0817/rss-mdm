use rss_mdm_inventory::builtin;
use rss_mdm_resource::blueprints;
#[test]
fn agent_templates_bind_native_queries_to_existing_field_types() {
    let fields = builtin::fields();
    let mut count = 0;
    for blueprint in blueprints::catalog() {
        let blueprints::Definition::AgentCollection { template } = &blueprint.definition else {
            continue;
        };
        count += 1;
        let frozen = template
            .spec()
            .mappings
            .keys()
            .map(|name| {
                let field = fields.iter().find(|f| f.key.as_str() == name).unwrap();
                crate::collection::wire::to_wire_field(field).unwrap()
            })
            .collect::<Vec<_>>();
        rss_mdm_agent_wire::runtime::validate_native_projection(
            &frozen,
            &template.spec().mappings,
            &template.spec().plan,
            template
                .spec()
                .mappings
                .values()
                .any(|m| m.counter_normalization.is_some()),
        )
        .unwrap_or_else(|e| panic!("{}: {e:?}", blueprint.id));
        for (name, mapping) in &template.spec().mappings {
            let field = fields
                .iter()
                .find(|f| f.key.as_str() == name)
                .expect("existing field");
            assert_eq!(
                field.sources.get(&rss_mdm_inventory::Source::AgentNative),
                Some(&1)
            );
            crate::collection::native::validate_agent_mapping(field, template, mapping)
                .unwrap_or_else(|e| panic!("{} {name}: {e:?}", blueprint.id));
        }
    }
    assert!(count > 26);
    for id in [
        "windows.agent.bitlocker",
        "windows.agent.accounts",
        "windows.agent.certificates_user_my",
        "windows.agent.updates_available_online",
        "macos.agent.gatekeeper",
        "macos.agent.accounts",
        "macos.agent.certificates_login",
        "macos.agent.updates_available_online",
    ] {
        assert!(blueprints::get(id, "1").is_some(), "missing {id}");
    }
}

#[test]
fn native_admission_requires_current_os_edition_engine_and_architecture() {
    use rss_mdm_agent_wire::{CollectionEnvironment, runtime as w};
    use rss_mdm_policy::{Architecture, Platform};
    let blueprints::Definition::AgentCollection { template } =
        blueprints::get("windows.agent.bitlocker", "1")
            .unwrap()
            .definition
    else {
        unreachable!()
    };
    let mut agent=crate::collection::execution::agent_facts::Binding {
        platform:"windows".into(),architecture:"x86_64".into(),capabilities:vec![w::Capability::InventoryCollectionV1,w::Capability::InventoryNativeV1],
        execution_context:serde_json::from_value(serde_json::json!({"revision":1,"osVersion":[10,0,22621,0],"systemBroker":true,"userHelper":false,"interactiveUser":null,"msixSideload":false,"msixUnsigned":false,"sourceCredentials":[]})).unwrap(),
    };
    let mut environment = CollectionEnvironment {
        edition: Some("Professional".into()),
        tools: Default::default(),
        native_engines: template.spec().plan.requirements(),
    };
    let allowed = |a: &crate::collection::execution::agent_facts::Binding,
                   e: &CollectionEnvironment| {
        crate::collection::execution::eligibility::matches(
            a,
            Platform::Windows,
            Architecture::X86_64,
            &template,
            e,
        )
    };
    assert!(allowed(&agent, &environment));
    environment.edition = None;
    assert!(!allowed(&agent, &environment));
    environment.edition = Some("Core".into());
    assert!(!allowed(&agent, &environment));
    environment.edition = Some("Professional".into());
    agent.execution_context.os_version = [6, 3, 9600, 0];
    assert!(!allowed(&agent, &environment));
    agent.execution_context.os_version = [10, 0, 22621, 0];
    agent.architecture = "aarch64".into();
    assert!(!allowed(&agent, &environment));
    agent.architecture = "x86_64".into();
    let mut extra = template.spec().clone();
    extra.applicability.capabilities =
        ["windows.accounts".into(), "inventory.native.v1".into()].into();
    let extra = rss_mdm_resource::AgentCollectionDefinition::new(extra).unwrap();
    assert!(!crate::collection::execution::eligibility::matches(
        &agent,
        Platform::Windows,
        Architecture::X86_64,
        &extra,
        &environment
    ));
    environment
        .native_engines
        .insert(w::NativeEngine::WindowsAccounts, 1);
    assert!(crate::collection::execution::eligibility::matches(
        &agent,
        Platform::Windows,
        Architecture::X86_64,
        &extra,
        &environment
    ));
    environment.native_engines.clear();
    assert!(!allowed(&agent, &environment));
}
