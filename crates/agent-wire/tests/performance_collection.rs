use rss_mdm_agent_wire::{CollectionScope, runtime::*};
use serde_json::{Value, json};

fn query(section: PerformanceSection, windows: bool) -> NativeQuery {
    NativeQuery {
        version: 1,
        definition: if windows {
            NativeQueryDefinition::WindowsPerformance { section }
        } else {
            NativeQueryDefinition::MacosPerformance { section }
        },
        cardinality: section.cardinality(),
        instance_keys: if section.cardinality() == NativeCardinality::List {
            vec!["id".into()]
        } else {
            vec![]
        },
        budget: NativeBudget {
            timeout_seconds: 1,
            output_bytes: 65536,
            max_rows: 32,
        },
    }
}

fn plan(q: NativeQuery) -> NativeCollectionPlan {
    NativeCollectionPlan::new(NativePlanSpec {
        version: 1,
        scope: CollectionScope::Device,
        budget: q.budget,
        queries: [("sample".into(), q)].into(),
    })
    .unwrap()
}

fn answer(q: &NativeQuery, row: Value) -> NativeQueryResult {
    NativeQueryResult {
        scan: None,
        query_digest: q.digest(),
        collected_at: 100,
        status: NativeQueryStatus::Complete,
        enumeration_complete: true,
        row_count: 1,
        rows: vec![serde_json::from_value(row).unwrap()],
        users: None,
    }
}

#[test]
fn performance_plans_require_exact_platform_engine_version_and_device_scope() {
    for windows in [true, false] {
        for section in [
            PerformanceSection::Cpu,
            PerformanceSection::Memory,
            PerformanceSection::FileSystems,
            PerformanceSection::Network,
        ] {
            let q = query(section, windows);
            let p = plan(q.clone());
            let engine = q.definition.engine();
            assert_eq!(p.execution_identity(), ExecutionIdentity::System);
            assert_eq!(
                p.platform(),
                if windows {
                    TaskPlatform::Windows
                } else {
                    TaskPlatform::Macos
                }
            );
            assert!(p.supported_by(&[(engine, 1)].into()));
            assert!(!p.supported_by(&Default::default()));
            assert!(!p.supported_by(&[(engine, 2)].into()));
            let other = query(section, !windows);
            assert!(!p.supported_by(&[(other.definition.engine(), 1)].into()));
            let mut mixed = p.spec().clone();
            mixed.queries.insert("other".into(), other);
            assert!(NativeCollectionPlan::new(mixed).is_err());
            let mut scoped = p.spec().clone();
            scoped.scope = CollectionScope::User {
                identity: "501".into(),
            };
            assert!(NativeCollectionPlan::new(scoped).is_err());
            let mut version = q.clone();
            version.version = 2;
            assert!(version.validate().is_err());
            let mut keys = q.clone();
            keys.instance_keys = vec!["total_bytes".into()];
            assert!(keys.validate().is_err());
            let mut cardinality = q;
            cardinality.cardinality = match section.cardinality() {
                NativeCardinality::ExactlyOne => NativeCardinality::List,
                NativeCardinality::List => NativeCardinality::ExactlyOne,
            };
            assert!(cardinality.validate().is_err());
            assert_eq!(
                serde_json::from_value::<NativeCollectionPlan>(serde_json::to_value(&p).unwrap())
                    .unwrap(),
                p
            );
        }
    }
}

#[test]
fn performance_recipe_cannot_carry_executable_or_sampling_parameters() {
    for kind in ["windows_performance", "macos_performance"] {
        let good = json!({"kind":kind,"section":"cpu"});
        assert!(serde_json::from_value::<NativeQueryDefinition>(good.clone()).is_ok());
        for key in ["command", "api", "counterPath", "sampleMillis"] {
            let mut bad = good.clone();
            bad[key] = json!("arbitrary");
            assert!(serde_json::from_value::<NativeQueryDefinition>(bad).is_err());
        }
        assert!(
            serde_json::from_value::<NativeQueryDefinition>(
                json!({"kind":kind,"section":"processes"})
            )
            .is_err()
        );
    }
    assert_eq!(
        serde_json::to_value(NativeEngine::WindowsPerformance).unwrap(),
        "windows.performance"
    );
    assert_eq!(
        serde_json::to_value(NativeEngine::MacosPerformance).unwrap(),
        "macos.performance"
    );
}

#[test]
fn performance_values_preserve_precision_and_reject_impossible_observations() {
    use PerformanceSection::*;
    for windows in [true, false] {
        for (section, good, bad) in [
            (
                Cpu,
                json!({"busy_percent":25.5}),
                json!({"busy_percent":100.1}),
            ),
            (
                Memory,
                json!({"total_bytes":u64::MAX.to_string(),"available_bytes":"1"}),
                json!({"total_bytes":"1","available_bytes":"2"}),
            ),
            (
                FileSystems,
                json!({"id":"volume-stable","total_bytes":"100","free_bytes":"0"}),
                json!({"id":"volume-stable","total_bytes":"100","free_bytes":"101"}),
            ),
            (
                Network,
                json!({"id":"interface-stable","received_bytes":u64::MAX.to_string(),"sent_bytes":"0"}),
                json!({"id":"interface-stable","received_bytes":u64::MAX,"sent_bytes":"0"}),
            ),
        ] {
            let q = query(section, windows);
            assert!(answer(&q, good.clone()).complete_for(&q, 100));
            assert!(!answer(&q, bad).complete_for(&q, 100));
            for key in q.definition.properties().keys() {
                let mut missing = good.clone();
                missing.as_object_mut().unwrap().remove(key);
                assert!(!answer(&q, missing).complete_for(&q, 100));
            }
            if section != Cpu {
                let key = if section == Network {
                    "received_bytes"
                } else {
                    "total_bytes"
                };
                for invalid in [
                    json!("01"),
                    json!("-1"),
                    json!("18446744073709551616"),
                    json!(1),
                ] {
                    let mut bad = good.clone();
                    bad[key] = invalid;
                    assert!(!answer(&q, bad).complete_for(&q, 100));
                }
            }
        }
        let q = query(Cpu, windows);
        for value in [0.0, 100.0] {
            assert!(answer(&q, json!({"busy_percent":value})).complete_for(&q, 100));
        }
        assert!(!answer(&q, json!({"busy_percent":-0.1})).complete_for(&q, 100));
        let q = query(Memory, windows);
        assert!(
            !answer(&q, json!({"total_bytes":"0","available_bytes":"0"})).complete_for(&q, 100)
        );
    }
}

#[test]
fn performance_enumerations_require_complete_distinct_stable_resource_ids() {
    for section in [PerformanceSection::FileSystems, PerformanceSection::Network] {
        let q = query(section, true);
        let row = match section {
            PerformanceSection::FileSystems => {
                json!({"id":"volume-id","total_bytes":"100","free_bytes":"20"})
            }
            _ => json!({"id":"interface-id","received_bytes":"100","sent_bytes":"20"}),
        };
        let mut result = answer(&q, row.clone());
        assert!(result.complete_for(&q, 100));
        result.rows.push(result.rows[0].clone());
        result.row_count = 2;
        assert!(!result.complete_for(&q, 100));
        result.rows.clear();
        result.row_count = 0;
        assert!(result.complete_for(&q, 100));
        result.enumeration_complete = false;
        assert!(!result.complete_for(&q, 100));
        for id in ["", "interface\nname", "interface\0name"] {
            let mut bad = row.clone();
            bad["id"] = json!(id);
            assert!(!answer(&q, bad).complete_for(&q, 100));
        }
    }
}

#[test]
fn missing_cpu_and_partial_performance_results_never_become_complete_facts() {
    let q = query(PerformanceSection::Cpu, false);
    let p = plan(q.clone());
    for status in [
        NativeQueryStatus::Missing,
        NativeQueryStatus::Partial,
        NativeQueryStatus::Failed,
    ] {
        let mut result = answer(&q, json!({"busy_percent":50.0}));
        result.status = status;
        assert!(!result.complete_for(&q, 100));
        let envelope = |r| NativeCollectionResult {
            plan_digest: p.digest(),
            collected_at: 100,
            queries: [("sample".into(), r)].into(),
        };
        assert!(envelope(result.clone()).validate_for(&p, 100).is_ok());
        result.rows[0].insert("busy_percent".into(), json!(200));
        assert!(envelope(result.clone()).validate_for(&p, 100).is_err());
        result.rows.clear();
        result.row_count = 0;
        assert!(envelope(result).validate_for(&p, 100).is_ok());
    }
    let mut complete_empty = answer(&q, json!({"busy_percent":0}));
    complete_empty.rows.clear();
    complete_empty.row_count = 0;
    assert!(!complete_empty.complete_for(&q, 100));
}
