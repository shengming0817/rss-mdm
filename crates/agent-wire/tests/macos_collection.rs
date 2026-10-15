use rss_mdm_agent_wire::{CollectionEnvironment, CollectionScope, runtime::*};
use serde_json::json;

fn budget() -> NativeBudget {
    NativeBudget {
        timeout_seconds: 60,
        output_bytes: 65536,
        max_rows: 100,
    }
}
fn query(definition: NativeQueryDefinition) -> NativeQuery {
    let cardinality = match &definition {
        NativeQueryDefinition::MacosHardware { section } => section.cardinality(),
        _ => NativeCardinality::List,
    };
    NativeQuery {
        version: 1,
        definition,
        cardinality,
        instance_keys: if cardinality == NativeCardinality::List {
            vec!["id".into()]
        } else {
            vec![]
        },
        budget: budget(),
    }
}
fn hardware(section: MacosHardwareSection) -> NativeQuery {
    query(NativeQueryDefinition::MacosHardware { section })
}
fn answer(q: &NativeQuery, rows: Vec<serde_json::Value>) -> NativeQueryResult {
    NativeQueryResult {
        query_digest: q.digest(),
        collected_at: 10,
        status: NativeQueryStatus::Complete,
        enumeration_complete: true,
        row_count: rows.len() as u32,
        rows: rows
            .into_iter()
            .map(|r| serde_json::from_value(r).unwrap())
            .collect(),
        users: None,
    }
}
fn brew(prefix: &str) -> NativeQueryDefinition {
    NativeQueryDefinition::MacosBrew {
        prefix: prefix.into(),
        package: MacosBrewPackage::Formula,
        taps: ["homebrew/core".into()].into(),
    }
}

#[test]
fn hardware_sections_fix_schema_cardinality_and_exact_byte_units() {
    use MacosHardwareSection::*;
    for section in [
        Identity,
        Os,
        Cpu,
        Memory,
        Firmware,
        Disks,
        ApfsContainers,
        Volumes,
        Network,
        Battery,
    ] {
        let q = hardware(section);
        q.validate().unwrap();
        assert_eq!(q.definition.platform(), TaskPlatform::Macos);
        assert_eq!(q.definition.engine(), NativeEngine::MacosHardware);
        assert_eq!(q.definition.execution_identity(), ExecutionIdentity::System);
        assert!(!q.definition.properties().is_empty());
        let mut wrong = q.clone();
        wrong.cardinality = if q.cardinality == NativeCardinality::List {
            NativeCardinality::ExactlyOne
        } else {
            NativeCardinality::List
        };
        assert!(wrong.validate().is_err());
    }
    let q = hardware(Memory);
    assert!(answer(&q, vec![json!({"total_bytes":u64::MAX.to_string()})]).complete_for(&q, 10));
    assert!(!answer(&q, vec![json!({"total_bytes":u64::MAX})]).complete_for(&q, 10));
    assert!(!answer(&q, vec![json!({"total_bytes":"0123"})]).complete_for(&q, 10));
    let q = hardware(ApfsContainers);
    assert!(
        answer(
            &q,
            vec![json!({"id":"container0","size_bytes":"100","free_bytes":"60"})]
        )
        .complete_for(&q, 10)
    );
    assert!(
        !answer(
            &q,
            vec![json!({"id":"container0","size_bytes":"100","free_bytes":"101"})]
        )
        .complete_for(&q, 10)
    );
    let q = hardware(Volumes);
    // Several volumes may share one container. The contract preserves the association;
    // it does not sum shared capacities into a second physical-capacity fact.
    assert!(
        answer(
            &q,
            vec![
                json!({"id":"v1","container_id":"c1"}),
                json!({"id":"v2","container_id":"c1"})
            ]
        )
        .complete_for(&q, 10)
    );
}

#[test]
fn hardware_quality_rejects_false_complete_and_invalid_values() {
    let q = hardware(MacosHardwareSection::Battery);
    assert!(answer(&q, vec![json!({"charge_percent":0})]).complete_for(&q, 10));
    for rows in [
        vec![],
        vec![json!({"charge_percent":101})],
        vec![json!({"charge_percent":-1})],
    ] {
        assert!(!answer(&q, rows).complete_for(&q, 10));
    }
    let q = hardware(MacosHardwareSection::Cpu);
    assert!(!answer(&q, vec![json!({"physical_cores":0,"logical_cores":8})]).complete_for(&q, 10));
    let q = hardware(MacosHardwareSection::Os);
    assert!(!answer(&q, vec![json!({"architecture":"arm64"})]).complete_for(&q, 10));
    let q = hardware(MacosHardwareSection::Network);
    let row = json!({"id":"en0","name":"Ethernet","addresses":["192.0.2.1"]});
    assert!(answer(&q, vec![row.clone()]).complete_for(&q, 10));
    assert!(!answer(&q, vec![row.clone(), row.clone()]).complete_for(&q, 10));
    assert!(!answer(&q, vec![json!({"id":"en0","location":"private"})]).complete_for(&q, 10));
    let mut r = answer(&q, vec![row]);
    r.enumeration_complete = false;
    assert!(!r.complete_for(&q, 10));
    r.enumeration_complete = true;
    r.status = NativeQueryStatus::Truncated;
    assert!(!r.complete_for(&q, 10));
    assert!(answer(&q, vec![]).complete_for(&q, 10));
}

#[test]
fn software_definitions_are_closed_and_keep_distinct_evidence_shapes() {
    let app = NativeQueryDefinition::MacosApplications {
        root: MacosApplicationRoot::UserApplications,
        max_depth: 4,
    };
    assert_eq!(app.execution_identity(), ExecutionIdentity::LoggedInUser);
    assert_eq!(app.properties()["version"], NativeType::String);
    assert_eq!(app.properties()["build_version"], NativeType::String);
    assert_eq!(app.properties()["team_id"], NativeType::String);
    assert_eq!(
        NativeQueryDefinition::MacosPkgReceipts {}.properties()["install_time"],
        NativeType::Integer
    );
    for definition in [
        app,
        NativeQueryDefinition::MacosPkgReceipts {},
        brew("/opt/homebrew"),
    ] {
        definition.validate().unwrap();
        let raw = serde_json::to_value(&definition).unwrap();
        assert_eq!(
            serde_json::from_value::<NativeQueryDefinition>(raw.clone()).unwrap(),
            definition
        );
        for key in ["command", "program", "args", "runAs", "uid"] {
            let mut injected = raw.clone();
            injected[key] = json!("unapproved");
            assert!(serde_json::from_value::<NativeQueryDefinition>(injected).is_err());
        }
    }
    for depth in [0, 9, 255] {
        assert!(
            NativeQueryDefinition::MacosApplications {
                root: MacosApplicationRoot::LocalApplications,
                max_depth: depth
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        serde_json::from_value::<NativeQueryDefinition>(
            json!({"kind":"macos_applications","root":"/private","maxDepth":2})
        )
        .is_err()
    );
}

#[test]
fn brew_requires_logged_in_user_and_exact_prefix_tap_selectors() {
    let recipe = brew("/opt/homebrew");
    assert_eq!(recipe.execution_identity(), ExecutionIdentity::LoggedInUser);
    assert_eq!(recipe.engine(), NativeEngine::MacosBrew);
    for path in ["/opt/homebrew", "/usr/local", "/Users/agent/brew-prefix"] {
        brew(path).validate().unwrap();
    }
    for path in [
        "/",
        "relative",
        "~/brew",
        "/opt/../brew",
        "/opt/./brew",
        "/opt//brew",
        "/opt/brew/",
        "/opt/brew\0",
        "/opt/brew\n",
    ] {
        assert!(brew(path).validate().is_err(), "{path:?}");
    }
    for tap in [
        "homebrew",
        "homebrew/core/extra",
        "Homebrew/core",
        "../core",
        "homebrew/*",
        "homebrew/core;rm",
    ] {
        let mut d = recipe.clone();
        if let NativeQueryDefinition::MacosBrew { taps, .. } = &mut d {
            *taps = [tap.into()].into();
        }
        assert!(d.validate().is_err(), "{tap}");
    }
    assert_ne!(
        query(brew("/opt/homebrew")).digest(),
        query(brew("/usr/local")).digest()
    );
    let mut cask = recipe.clone();
    if let NativeQueryDefinition::MacosBrew { package, .. } = &mut cask {
        *package = MacosBrewPackage::Cask;
    }
    assert_ne!(query(recipe).digest(), query(cask).digest());
}

#[test]
fn definition_support_cannot_bypass_unimplemented_execution_or_range_proof() {
    // The #2726 scope and #2737 signed live-user binding are not integrated yet.
    // All macOS plans remain rejected, including Device masquerades and empty software lists.
    for d in [
        hardware(MacosHardwareSection::Memory).definition,
        NativeQueryDefinition::MacosApplications {
            root: MacosApplicationRoot::LocalApplications,
            max_depth: 2,
        },
        NativeQueryDefinition::MacosPkgReceipts {},
        brew("/opt/homebrew"),
    ] {
        let q = query(d.clone());
        q.validate().unwrap();
        for scope in [
            CollectionScope::Device,
            CollectionScope::User {
                identity: "501".into(),
            },
            CollectionScope::Prefix {
                path: "/opt/homebrew".into(),
            },
        ] {
            let input = NativePlanSpec {
                version: 1,
                scope,
                queries: [("mac".into(), q.clone())].into(),
                budget: budget(),
            };
            let json = serde_json::to_value(&input).unwrap();
            assert!(NativeCollectionPlan::new(input).is_err());
            assert!(serde_json::from_value::<NativeCollectionPlan>(json).is_err());
        }
        if !matches!(d, NativeQueryDefinition::MacosHardware { .. }) {
            assert!(!answer(&q, vec![]).complete_for(&q, 10));
        }
    }
}

#[test]
fn engine_map_is_bounded_by_closed_keys_not_a_stale_windows_count() {
    let engines = [
        NativeEngine::WindowsWmi,
        NativeEngine::WindowsRegistry,
        NativeEngine::WindowsCpu,
        NativeEngine::WindowsSoftware,
        NativeEngine::WindowsNetwork,
        NativeEngine::WindowsBattery,
        NativeEngine::MacosHardware,
        NativeEngine::MacosApplications,
        NativeEngine::MacosPkgReceipts,
        NativeEngine::MacosBrew,
    ];
    let mut environment = CollectionEnvironment {
        edition: None,
        tools: Default::default(),
        native_engines: engines.into_iter().map(|e| (e, 1)).collect(),
    };
    environment.validate().unwrap();
    environment
        .native_engines
        .insert(NativeEngine::MacosBrew, 2);
    assert!(environment.validate().is_err());
    assert!(serde_json::from_value::<NativeEngines>(json!({"macos.command":1})).is_err());
}
