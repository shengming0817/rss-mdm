#[path = "support/projection.rs"]
mod projection;
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
        version: definition.engine().contract_version(),
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
        scan: None,
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
    let mut extended = row.clone();
    extended["vendor_detail"] = json!({"location":"office"});
    assert!(answer(&q, vec![extended]).complete_for(&q, 10));

    assert!(!answer(&q, vec![row.clone(), row.clone()]).complete_for(&q, 10));
    assert!(answer(&q, vec![json!({"id":"en0","location":"private"})]).complete_for(&q, 10));
    assert!(!answer(&q, vec![json!({"location":"private"})]).complete_for(&q, 10));
    assert!(!answer(&q, vec![json!({"id":"en0","name":false})]).complete_for(&q, 10));
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
fn macos_plans_are_wire_valid_without_granting_inventory_scope_authority() {
    for definition in [
        hardware(MacosHardwareSection::Memory).definition,
        NativeQueryDefinition::MacosPkgReceipts {},
        brew("/opt/homebrew"),
    ] {
        let q = query(definition);
        let plan = NativeCollectionPlan::new(NativePlanSpec {
            version: 1,
            scope: CollectionScope::Device,
            queries: [("mac".into(), q)].into(),
            budget: budget(),
        })
        .unwrap();
        assert_eq!(plan.platform(), TaskPlatform::Macos);
        assert_eq!(
            serde_json::from_value::<NativeCollectionPlan>(serde_json::to_value(&plan).unwrap())
                .unwrap(),
            plan
        );
    }
    let q = query(NativeQueryDefinition::MacosPkgReceipts {});
    assert!(answer(&q, vec![]).complete_for(&q, 10));
}

#[test]
fn engine_map_accepts_declared_engines_and_rejects_unknown_keys() {
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
    let environment = CollectionEnvironment {
        edition: None,
        tools: Default::default(),
        native_engines: engines
            .into_iter()
            .map(|e| (e, e.contract_version()))
            .collect(),
    };
    environment.validate().unwrap();
    assert!(serde_json::from_value::<NativeEngines>(json!({"macos.command":1})).is_err());
}

fn plan(definition: NativeQueryDefinition) -> NativeCollectionPlan {
    NativeCollectionPlan::new(NativePlanSpec {
        version: 1,
        scope: CollectionScope::Device,
        queries: [("sample".into(), query(definition))].into(),
        budget: budget(),
    })
    .unwrap()
}
fn context() -> SoftwareExecutionContext {
    SoftwareExecutionContext {
        revision: 1,
        msix_sideload: false,
        msix_unsigned: false,
        os_version: [15, 0, 0, 0],
        system_broker: true,
        user_helper: true,
        interactive_user: Some(SoftwareInteractiveUser {
            windows_authority: None,
            generated_uid: Some("00000000-0000-0000-0000-000000000501".into()),
            identity: "501".into(),
            session_id: uuid::Uuid::from_u128(1),
            administrator: false,
        }),
        source_credentials: vec![],
    }
}
#[test]
fn brew_identity_requires_nonroot_live_session_and_exact_context() {
    let plan = plan(brew("/opt/homebrew"));
    let context = context();
    let binding = NativeExecutionBinding::bind(&plan, &context).unwrap();
    assert_eq!(binding.identity, ExecutionIdentity::LoggedInUser);
    for uid in ["0", "00", "0501", "-1", "root", "4294967296"] {
        let mut changed = context.clone();
        changed.interactive_user.as_mut().unwrap().identity = uid.into();
        assert!(
            NativeExecutionBinding::bind(&plan, &changed).is_err(),
            "{uid}"
        );
    }
    for change in 0..5 {
        let mut changed = context.clone();
        match change {
            0 => changed.interactive_user = None,
            1 => changed.user_helper = false,
            2 => changed.interactive_user.as_mut().unwrap().session_id = uuid::Uuid::from_u128(2),
            3 => changed.revision += 1,
            _ => changed.interactive_user.as_mut().unwrap().identity = "502".into(),
        }
        assert!(!binding.matches_context(&plan, &changed));
    }
    let mut scoped = plan.spec().clone();
    scoped.scope = CollectionScope::User {
        identity: "502".into(),
    };
    assert!(
        NativeExecutionBinding::bind(&NativeCollectionPlan::new(scoped).unwrap(), &context)
            .is_err()
    );
}
#[test]
fn signed_macos_collection_binds_identity_plan_and_permit() {
    use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
    let plan = plan(brew("/opt/homebrew"));
    let id = uuid::Uuid::from_u128(1);
    let (fields, mappings) = projection::projection(&plan);
    let task = CollectionTaskSpec {
        fields,
        mappings,
        wire_version: COLLECTION_TASK_VERSION,
        tenant_id: id,
        device_id: "mac".into(),
        platform: TaskPlatform::Macos,
        architecture: TaskArchitecture::Aarch64,
        registration_id: id,
        generation: 1,
        task_id: id,
        attempt_id: id,
        permit: TaskPermit::Offer,
        expires_at: 100,
        deadline: 200,
        resource_digest: [1; 32],
        resource: TaskResource {
            id: "mac".into(),
            version: "1".into(),
            variant: "arm".into(),
        },
        authorization: TaskAuthorization::Policy {
            policy_id: id,
            policy_version: id,
        },
        execution: NativeExecutionBinding::bind(&plan, &context()).unwrap(),
        plan_digest: plan.digest(),
        plan,
    };
    let key = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
    let signature = key.sign(&task.signing_bytes("key").unwrap());
    let verifier = UnparsedPublicKey::new(&ED25519, key.public_key().as_ref());
    for change in 0..7 {
        let mut tampered = task.clone();
        match change {
            0 => tampered.permit = TaskPermit::Start,
            1 => tampered.execution.context_revision += 1,
            2 => {
                let SoftwareExecutionTarget::User { session_id, .. } =
                    &mut tampered.execution.target
                else {
                    unreachable!()
                };
                *session_id = uuid::Uuid::from_u128(2);
            }
            3 => tampered.resource_digest[0] ^= 1,
            4 => tampered.device_id = "other".into(),
            5 => tampered.architecture = TaskArchitecture::X86_64,
            _ => {
                let mut p = tampered.plan.spec().clone();
                p.budget.timeout_seconds += 1;
                tampered.plan = NativeCollectionPlan::new(p).unwrap();
                tampered.plan_digest = tampered.plan.digest();
            }
        }
        assert!(
            verifier
                .verify(&tampered.signing_bytes("key").unwrap(), signature.as_ref())
                .is_err()
        );
    }
    let payload = TaskPayload::Collection(Box::new(task));
    let mut missing = serde_json::to_value(&payload).unwrap();
    missing["task"].as_object_mut().unwrap().remove("execution");
    assert!(serde_json::from_value::<TaskPayload>(missing).is_err());
}
#[test]
fn macos_software_rows_bind_closed_provenance_and_brew_selectors() {
    let q = query(brew("/opt/homebrew"));
    let row = json!({"id":"homebrew/core/jq","scope":"user","owner":"501","origin":"homebrew","prefix":"/opt/homebrew","tap":"homebrew/core","package_kind":"formula"});
    assert!(answer(&q, vec![row.clone()]).complete_for(&q, 10));
    for (key, value) in [
        ("owner", "0"),
        ("scope", "device"),
        ("prefix", "/usr/local"),
        ("tap", "other/core"),
        ("package_kind", "cask"),
    ] {
        let mut bad = row.clone();
        bad[key] = json!(value);
        assert!(!answer(&q, vec![bad]).complete_for(&q, 10));
    }
    let q = query(NativeQueryDefinition::MacosPkgReceipts {});
    assert!(
        answer(
            &q,
            vec![json!({"id":"pkg","scope":"device","owner":"","origin":"pkg_receipt"})]
        )
        .complete_for(&q, 10)
    );
    assert!(
        !answer(
            &q,
            vec![json!({"id":"pkg","scope":"user","owner":"501","origin":"pkg_receipt"})]
        )
        .complete_for(&q, 10)
    );
}

#[test]
fn brew_data_recipe_requires_current_engine_contract() {
    let current = query(brew("/opt/homebrew"));
    assert_eq!(current.version, 1);
    current.validate().unwrap();
    let plan = plan(current.definition.clone());
    assert!(plan.supported_by(&[(NativeEngine::MacosBrew, 1)].into()));
    for version in [0, 2] {
        assert!(!plan.supported_by(&[(NativeEngine::MacosBrew, version)].into()));
        let mut unsupported = current.clone();
        unsupported.version = version;
        assert!(unsupported.validate().is_err());
        let mut spec = plan.spec().clone();
        spec.queries.insert("sample".into(), unsupported);
        assert!(
            serde_json::from_value::<NativeCollectionPlan>(serde_json::to_value(spec).unwrap())
                .is_err()
        );
    }
}
