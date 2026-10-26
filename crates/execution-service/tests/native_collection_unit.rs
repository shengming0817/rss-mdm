use rss_mdm_inventory::{FieldKey, builtin};
use rss_mdm_resource::blueprints;
#[test]
fn every_windows_blueprint_compiles_and_maps_only_published_fields() {
    let fields = builtin::fields();
    rss_mdm_inventory::Catalog::new(fields.clone()).unwrap();
    for blueprint in blueprints::catalog().into_iter().filter(|b| {
        b.platform == rss_mdm_resource::Platform::Windows
            && matches!(
                b.definition,
                blueprints::Definition::NativeCollection { .. }
            )
    }) {
        let rss_mdm_resource::blueprints::Definition::NativeCollection { template } =
            &blueprint.definition
        else {
            panic!("Windows native pack")
        };
        let plan = crate::input_preparation::windows_collection_plan(template)
            .unwrap_or_else(|e| panic!("{}: {e:?}", blueprint.id));
        plan.applicable(rss_mdm_windows_mdm::native::Context {
            build: Some([10, 0, 22621, 0]),
            edition: Some(48),
            scope: rss_mdm_windows_mdm::native::Scope::Device,
            enrollment: rss_mdm_windows_mdm::native::Enrollment::Primary,
        })
        .unwrap_or_else(|e| panic!("{}: {e:?}", blueprint.id));
        for (name, mapping) in &template.spec().mappings {
            let key = FieldKey::parse(name).unwrap();
            let field = fields
                .iter()
                .find(|f| f.key == key)
                .unwrap_or_else(|| panic!("{name}"));
            rss_mdm_inventory_service::collection::native::validate_mapping(
                field,
                &mapping.mapping,
            )
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        }
    }
}
#[test]
fn security_codes_and_capacity_have_exact_native_meanings() {
    use rss_mdm_inventory::{CollectedValue, NativeValue, Scalar};
    let fields = builtin::fields();
    rss_mdm_inventory::Catalog::new(fields.clone()).unwrap();
    let read = |pack: &str, key: &str, raw: &str| {
        let b = blueprints::get(pack, "1").unwrap();
        let blueprints::Definition::NativeCollection { template } = &b.definition else {
            panic!("native pack");
        };
        let field = fields.iter().find(|f| f.key.as_str() == key).unwrap();
        rss_mdm_inventory_service::collection::native::value(
            field,
            &template.spec().mappings[key],
            &serde_json::json!(raw),
        )
    };
    assert!(
        matches!(read("windows.security.firewall","device.security.windows.firewall.status","0"),NativeValue::Value(CollectedValue::Value(Scalar::String(v))) if v=="enabled")
    );
    assert!(matches!(
        read(
            "windows.security.firewall",
            "device.security.windows.firewall.status",
            "99"
        ),
        NativeValue::Invalid
    ));
    assert!(
        matches!(read("windows.security.bitlocker","device.security.windows.bitlocker.compliance_errors","0"),NativeValue::Value(CollectedValue::Value(Scalar::Array(v))) if v.is_empty())
    );
    assert!(
        matches!(read("windows.security.bitlocker","device.security.windows.bitlocker.compliance_errors","4"),NativeValue::Value(CollectedValue::Value(Scalar::Array(v))) if v.len()==1)
    );
    assert!(matches!(
        read(
            "windows.security.bitlocker",
            "device.security.windows.bitlocker.compliance_errors",
            "262144"
        ),
        NativeValue::Invalid
    ));
    assert!(matches!(
        read(
            "windows.hardware",
            "device.hardware.windows.available_memory_bytes",
            "1024"
        ),
        NativeValue::Value(CollectedValue::Value(Scalar::Integer(1073741824)))
    ));
}

#[test]
fn every_standard_pack_replays_raw_syncml_and_matches_normalized_fixture() {
    use rss_mdm_inventory::{CollectedValue, NativeValue, Scalar};
    use rss_mdm_windows_mdm::{
        CodecLimits,
        native::{Context, Enrollment, Scope, collection::Outcome},
        syncml::{self, Command},
    };
    fn plain(value: &Scalar) -> serde_json::Value {
        match value {
            Scalar::String(v) => v.clone().into(),
            Scalar::Integer(v) | Scalar::Time(v) => (*v).into(),
            Scalar::Boolean(v) => (*v).into(),
            Scalar::Number(v) => serde_json::json!(v.into_inner()),
            Scalar::Array(v) => v.iter().map(plain).collect(),
            Scalar::Object(v) => v.iter().map(|(k, v)| (k.clone(), plain(v))).collect(),
        }
    }
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/windows-collection");
    let fields = builtin::fields();
    rss_mdm_inventory::Catalog::new(fields.clone()).unwrap();
    for b in blueprints::catalog().into_iter().filter(|b| {
        b.platform == rss_mdm_resource::Platform::Windows
            && matches!(
                b.definition,
                blueprints::Definition::NativeCollection { .. }
            )
    }) {
        let id = b.id.strip_prefix("windows.").unwrap();
        let xml = std::fs::read(root.join(format!("{id}.xml"))).unwrap();
        let raw = syncml::decode(&xml, &CodecLimits::default()).unwrap();
        let values: std::collections::BTreeMap<_, _> = raw
            .commands
            .into_iter()
            .filter_map(|c| match c {
                Command::Results(v) => Some(v.items),
                _ => None,
            })
            .flatten()
            .map(|i| (i.source.unwrap(), i.data.unwrap().0))
            .collect();
        let blueprints::Definition::NativeCollection { template } = &b.definition else {
            panic!("native pack");
        };
        let plan = crate::input_preparation::windows_collection_plan(template).unwrap();
        let mut state = plan.start("RSS").unwrap();
        let context = Context {
            build: Some([10, 0, 22621, 0]),
            edition: Some(48),
            scope: Scope::Device,
            enrollment: Enrollment::Primary,
        };
        let mut outputs = std::collections::BTreeMap::new();
        for message in 1..=5 {
            let mut commands = Vec::new();
            let mut command = 1024;
            while let Some((step, q)) = state.next().unwrap() {
                let uri = q.compile(context, command).unwrap().objects[0]
                    .key()
                    .to_owned();
                state.sent(step, message, command).unwrap();
                commands.push((command, uri));
                command += 1;
            }
            for (command, uri) in commands.into_iter().rev() {
                state
                    .value(
                        message,
                        command,
                        &uri,
                        values
                            .get(&uri)
                            .unwrap_or_else(|| panic!("{} missing {uri}", b.id))
                            .clone(),
                    )
                    .unwrap();
                state.status(message, command, 200).unwrap();
            }
            state
                .advance(&plan, template.spec().output_bytes as usize)
                .unwrap();
            outputs.extend(state.outcomes(&plan).unwrap());
        }
        let mut normalized = serde_json::Map::new();
        for (key, outcome) in outputs {
            let Outcome::Value(raw) = outcome else {
                panic!("{} failed {key}", b.id)
            };
            let field = fields.iter().find(|f| f.key.as_str() == key).unwrap();
            let NativeValue::Value(CollectedValue::Value(value)) =
                rss_mdm_inventory_service::collection::native::value(
                    field,
                    &template.spec().mappings[&key],
                    &raw,
                )
            else {
                panic!("{} invalid {key}: {raw}", b.id)
            };
            normalized.insert(key, plain(&value));
        }
        let expected: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(format!("{id}.json"))).unwrap())
                .unwrap();
        assert_eq!(serde_json::Value::Object(normalized), expected, "{}", b.id);
    }
}

#[test]
fn authorization_targets_do_not_inherit_single_message_budget() {
    use crate::action_contract::{ExecutionInput, FrozenNativeCollection};
    use rss_mdm_policy::{
        Architecture, Platform,
        schedule::{Misfire, Schedule, Trigger},
    };
    let blueprint = blueprints::get("windows.software.store", "2").unwrap();
    let blueprints::Definition::NativeCollection { template } = &blueprint.definition else {
        panic!("native pack");
    };
    let mapping = template.spec().mappings.values().next().unwrap().clone();
    let field = builtin::fields()
        .into_iter()
        .find(|f| f.key.as_str() == "device.software.windows.store")
        .unwrap();
    let rss_mdm_resource::blueprints::Definition::NativeCollection { template } =
        &blueprint.definition
    else {
        panic!("native pack")
    };
    let mut spec = template.spec().clone();
    spec.mappings.clear();
    let mut fields = Vec::new();
    for i in 0..22 {
        let key = format!("custom.store_{i}");
        spec.mappings.insert(key.clone(), mapping.clone());
        let mut field = field.clone();
        field.key = FieldKey::parse(&key).unwrap();
        fields.push(field);
    }
    let definition = rss_mdm_resource::NativeCollectionDefinition::new(spec).unwrap();
    let plan = crate::input_preparation::windows_collection_plan(&definition).unwrap();
    assert!(plan.requests().unwrap().len() > rss_mdm_windows_mdm::CodecLimits::default().commands);
    let frozen = FrozenNativeCollection {
        input: ExecutionInput {
            platform: Platform::Windows,
            architecture: Architecture::X86_64,
            schedule: Schedule {
                trigger: Trigger::Manual,
                misfire: Misfire::CoalesceOne,
                not_before: 0,
                until: None,
                jitter_seconds: 0,
                window: None,
            },
            run_lifetime_seconds: 300,
        },
        definition,
        windows_plan: Some(plan),
        resource_digest: [0; 32],
        collection: rss_mdm_inventory::CollectionDefinition::new(
            "inventory",
            "many-fields",
            rss_mdm_inventory::Source::MdmWindows,
            {
                let scope = rss_mdm_inventory::CollectionScope::Device;
                let fields: Vec<rss_mdm_inventory::FieldDefinition> = fields;
                fields
                    .into_iter()
                    .map(|definition| rss_mdm_inventory::CollectionField {
                        definition,
                        scope: scope.clone(),
                    })
                    .collect()
            },
        )
        .unwrap(),
    };
    assert!(
        frozen
            .permissions()
            .unwrap()
            .contains(&crate::authorization::Permission::InventoryCollect)
    );
}

#[test]
fn apple_status_blueprints_are_real_native_configurations() {
    use rss_mdm_resource::blueprints::{self, Definition};
    for blueprint in blueprints::catalog()
        .into_iter()
        .filter(|b| b.id.starts_with("macos.ddm."))
    {
        let Definition::Configuration { content } = blueprint.definition else {
            panic!("DDM configuration");
        };
        let configuration: crate::configuration::Configuration =
            serde_json::from_value(serde_json::to_value(content).unwrap()).unwrap();
        configuration.validate().unwrap();
        assert!(!configuration.objects().unwrap().is_empty());
        use rss_mdm_apple_mdm::{
            applicability::{Channel, Context, Enrollment, Version},
            native::{Target, ddm::DeclarationSet, request::Request},
        };
        let context = Context {
            version: Some(Version::parse("27.0").unwrap()),
            channel: Channel::Device,
            enrollment: Enrollment::Device,
            supervised: Some(true),
            automated_enrollment: Some(true),
            user_approved: Some(true),
            apple_silicon: Some(true),
        };
        let target = Target {
            context: &context,
            access_rights: &[],
        };
        let crate::Task::Macos {
            request: Request::Declarations { declarations, .. },
        } = configuration.apply
        else {
            panic!("native declaration");
        };
        let compiled = declarations
            .iter()
            .map(|d| d.compile("v2", &target))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| panic!("{}: {e:?}", blueprint.id));
        DeclarationSet::new("fixture", compiled).unwrap();
    }
}

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
                rss_mdm_inventory_service::collection::wire::to_wire_field(field).unwrap()
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
            rss_mdm_inventory_service::collection::native::validate_agent_mapping(
                field, template, mapping,
            )
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
    let mut agent=crate::channels::AgentBinding {
        platform:"windows".into(),architecture:"x86_64".into(),capabilities:vec![w::Capability::InventoryCollectionV1,w::Capability::InventoryNativeV1],
        execution_context:serde_json::from_value(serde_json::json!({"revision":1,"osVersion":[10,0,22621,0],"systemBroker":true,"userHelper":false,"interactiveUser":null,"msixSideload":false,"msixUnsigned":false,"sourceCredentials":[]})).unwrap(),
    };
    let mut environment = CollectionEnvironment {
        edition: Some("Professional".into()),
        tools: Default::default(),
        native_engines: template.spec().plan.requirements(),
    };
    let allowed = |a: &crate::channels::AgentBinding, e: &CollectionEnvironment| {
        crate::agent_collection_eligibility::matches(
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
    assert!(!crate::agent_collection_eligibility::matches(
        &agent,
        Platform::Windows,
        Architecture::X86_64,
        &extra,
        &environment
    ));
    environment
        .native_engines
        .insert(w::NativeEngine::WindowsAccounts, 1);
    assert!(crate::agent_collection_eligibility::matches(
        &agent,
        Platform::Windows,
        Architecture::X86_64,
        &extra,
        &environment
    ));
    environment.native_engines.clear();
    assert!(!allowed(&agent, &environment));
}
