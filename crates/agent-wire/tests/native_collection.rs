use rss_mdm_agent_wire::{CollectionEnvironment, CollectionScope, runtime::*};
use serde_json::json;
use std::collections::BTreeMap;
fn budget() -> NativeBudget {
    NativeBudget {
        timeout_seconds: 60,
        output_bytes: 65536,
        max_rows: 100,
    }
}
fn query() -> NativeQuery {
    NativeQuery {
        version: 1,
        definition: NativeQueryDefinition::WindowsWmi {
            namespace: "root\\vendor".into(),
            class: "Acme_Device".into(),
            properties: [
                (
                    "ID".into(),
                    WmiProperty {
                        cim_type: CimType::String,
                        array: false,
                    },
                ),
                (
                    "Size".into(),
                    WmiProperty {
                        cim_type: CimType::Uint64,
                        array: false,
                    },
                ),
            ]
            .into(),
            filter: None,
        },
        cardinality: NativeCardinality::List,
        instance_keys: vec!["ID".into()],
        budget: budget(),
    }
}
fn plan(q: NativeQuery) -> NativeCollectionPlan {
    NativeCollectionPlan::new(NativePlanSpec {
        version: 1,
        scope: CollectionScope::Device,
        queries: [("disk".into(), q)].into(),
        budget: budget(),
    })
    .unwrap()
}
fn result(q: &NativeQuery) -> NativeQueryResult {
    NativeQueryResult {
        query_digest: q.digest(),
        collected_at: 10,
        status: NativeQueryStatus::Complete,
        enumeration_complete: true,
        row_count: 1,
        rows: vec![
            [
                ("ID".into(), json!("disk0")),
                ("Size".into(), json!(u64::MAX.to_string())),
            ]
            .into(),
        ],
        users: None,
    }
}
#[test]
fn vendor_classes_and_exact_values_do_not_require_agent_class_allowlists() {
    let q = query();
    let p = plan(q.clone());
    let r = result(&q);
    assert!(r.complete_for(&q, 10));
    assert!(p.supported_by(&[(NativeEngine::WindowsWmi, 1)].into()));
    assert!(!p.supported_by(&BTreeMap::new()));
    assert!(!p.supported_by(&[(NativeEngine::WindowsWmi, 2)].into()));
    assert!(
        serde_json::from_value::<NativeCollectionPlan>(serde_json::to_value(p).unwrap()).is_ok()
    );
}
#[test]
fn unsafe_or_unbounded_query_recipes_fail_before_publication() {
    for class in ["Win32_Product", "win32_product", "SELECT *", "A;DROP"] {
        let mut q = query();
        if let NativeQueryDefinition::WindowsWmi { class: c, .. } = &mut q.definition {
            *c = class.into();
        }
        assert!(q.validate().is_err());
    }
    let mut q = query();
    if let NativeQueryDefinition::WindowsWmi { namespace, .. } = &mut q.definition {
        *namespace = "\\\\remote\\root\\cimv2".into();
    }
    assert!(q.validate().is_err());
    let mut q = query();
    q.instance_keys = vec!["missing".into()];
    assert!(q.validate().is_err());
    let mut q = query();
    if let NativeQueryDefinition::WindowsWmi { filter, .. } = &mut q.definition {
        *filter = Some(WmiFilter::Compare {
            property: "ID".into(),
            operator: NativeComparison::Gt,
            value: json!("1"),
        });
    }
    assert!(q.validate().is_err());
    let mut p = plan(query()).spec().clone();
    p.scope = CollectionScope::User {
        identity: "S-1-5-21-1".into(),
    };
    assert!(NativeCollectionPlan::new(p).is_err());
}
#[test]
fn only_complete_distinct_lists_may_replace_facts() {
    let q = query();
    let r = result(&q);
    assert!(r.complete_for(&q, 10));
    let mut empty = r.clone();
    empty.rows.clear();
    empty.row_count = 0;
    assert!(empty.complete_for(&q, 10));
    let mut bad = r.clone();
    bad.enumeration_complete = false;
    assert!(!bad.complete_for(&q, 10));
    let mut bad = r.clone();
    bad.status = NativeQueryStatus::Truncated;
    assert!(!bad.complete_for(&q, 10));
    let mut bad = r.clone();
    bad.rows.push(r.rows[0].clone());
    bad.row_count = 2;
    assert!(!bad.complete_for(&q, 10));
    let mut bad = r.clone();
    bad.rows[0].insert("Size".into(), json!(u64::MAX));
    assert!(!bad.complete_for(&q, 10));
    let mut bad = r.clone();
    bad.row_count = 2;
    assert!(!bad.complete_for(&q, 10));
    let mut bad = r;
    bad.collected_at = 11;
    assert!(!bad.complete_for(&q, 10));
}
#[test]
fn software_requires_stable_complete_user_set_even_for_empty_list() {
    let q = NativeQuery {
        definition: NativeQueryDefinition::WindowsSoftware,
        instance_keys: vec!["id".into()],
        ..query()
    };
    let mut r = NativeQueryResult {
        rows: vec![],
        row_count: 0,
        query_digest: q.digest(),
        ..result(&query())
    };
    assert!(!r.complete_for(&q, 10));
    let s = "S-1-5-21-1".to_owned();
    r.users = Some(NativeUserCoverage {
        enumeration_complete: true,
        expected: [s.clone()].into(),
        observed: [s.clone()].into(),
        completed: [s].into(),
    });
    assert!(r.complete_for(&q, 10));
    r.users.as_mut().unwrap().completed.clear();
    assert!(!r.complete_for(&q, 10));
}
#[test]
fn plan_and_query_fingerprints_bind_results_and_engine_contract() {
    let q = query();
    let p = plan(q.clone());
    let mut r = NativeCollectionResult {
        plan_digest: p.digest(),
        collected_at: 10,
        queries: [("disk".into(), result(&q))].into(),
    };
    r.validate_for(&p, 10).unwrap();
    r.queries.get_mut("disk").unwrap().status = NativeQueryStatus::Denied;
    r.validate_for(&p, 10).unwrap();
    r.plan_digest[0] ^= 1;
    assert!(r.validate_for(&p, 10).is_err());
}
#[test]
fn registry_view_type_and_literal_paths_are_explicit() {
    let mut d = NativeQueryDefinition::WindowsRegistry {
        hive: RegistryHive::LocalMachine,
        view: RegistryView::Registry64,
        path: "SOFTWARE\\Acme".into(),
        enumerate_subkeys: false,
        values: [(
            "value".into(),
            RegistryValue {
                name: "".into(),
                value_type: RegistryType::Qword,
            },
        )]
        .into(),
    };
    d.validate().unwrap();
    assert_eq!(d.properties()["value"], NativeType::UInt64);
    if let NativeQueryDefinition::WindowsRegistry { path, .. } = &mut d {
        *path = "SOFTWARE\\..\\SAM".into();
    }
    assert!(d.validate().is_err());
    assert!(serde_json::from_value::<RegistryHive>(json!({"kind":"current_user"})).is_err());
}
#[test]
fn native_capabilities_are_not_software_and_claim_evidence_is_required() {
    assert!(!Capability::InventoryNativeV1.is_software());
    assert!(
        serde_json::from_value::<CollectionEnvironment>(json!({"edition":null,"tools":{}}))
            .is_err()
    );
    assert!(
        serde_json::from_value::<CollectionEnvironment>(
            json!({"edition":null,"tools":{},"nativeEngines":{}})
        )
        .is_ok()
    );
}
#[test]
fn manifest_transport_rejects_missing_conflicting_or_corrupt_chunks() {
    use sha2::{Digest, Sha256};
    let bytes = b"{\"result\":true}";
    let manifest = OutputManifest::new(bytes.len() as u32, Sha256::digest(bytes).into()).unwrap();
    let chunk = OutputChunk::new(manifest.clone(), 0, bytes).unwrap();
    assert_eq!(manifest.assemble(vec![chunk.clone()]).unwrap(), bytes);
    assert!(manifest.assemble(vec![]).is_err());
    assert!(manifest.assemble(vec![chunk.clone(), chunk]).is_err());
    let bad = OutputChunk::new(manifest.clone(), 0, b"{\"result\":null}").unwrap();
    assert!(manifest.assemble(vec![bad]).is_err());
}

#[test]
fn fixed_native_vectors_bind_permit_plan_and_domain() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
    use sha2::{Digest, Sha256};
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/native-v2-vectors.json")).unwrap();
    for vectors in vectors.as_array().unwrap() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
        let plan: NativeCollectionPlan = serde_json::from_value(vectors["plan"].clone()).unwrap();
        let result: NativeCollectionResult =
            serde_json::from_value(vectors["result"].clone()).unwrap();
        result.validate_for(&plan, 100).unwrap();
        assert_eq!(json!(result.digest()), vectors["resultDigest"]);
        for item in vectors["tasks"].as_array().unwrap() {
            let payload: TaskPayload =
                serde_json::from_str(item["payloadJson"].as_str().unwrap()).unwrap();
            let bytes = payload.signing_bytes("vector-key").unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(&bytes)),
                item["signingBytesSha256"]
            );
            let signature = URL_SAFE_NO_PAD
                .decode(item["signature"].as_str().unwrap())
                .unwrap();
            UnparsedPublicKey::new(&ED25519, key.public_key().as_ref())
                .verify(&bytes, &signature)
                .unwrap();
            let mut changed = payload.clone();
            let TaskPayload::Collection(spec) = &mut changed else {
                panic!("wrong family")
            };
            spec.permit = if spec.permit == TaskPermit::Offer {
                TaskPermit::Start
            } else {
                TaskPermit::Offer
            };
            assert!(
                UnparsedPublicKey::new(&ED25519, key.public_key().as_ref())
                    .verify(&changed.signing_bytes("vector-key").unwrap(), &signature)
                    .is_err()
            );
            let raw = serde_json::to_value(payload).unwrap();
            assert!(serde_json::from_value::<TaskPayload>(raw["task"].clone()).is_err());
        }
    }
}
