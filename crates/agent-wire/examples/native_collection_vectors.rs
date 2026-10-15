//! Reproducible current native task/result vectors for independent Agent consumers.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::Ed25519KeyPair;
use rss_mdm_agent_wire::{CollectionScope, runtime::*};
use serde_json::json;
use sha2::{Digest, Sha256};
fn main() {
    let id = uuid::Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
    let budget = NativeBudget {
        timeout_seconds: 60,
        output_bytes: 65536,
        max_rows: 100,
    };
    let query = NativeQuery {
        version: 1,
        definition: NativeQueryDefinition::WindowsRegistry {
            hive: RegistryHive::LocalMachine,
            view: RegistryView::Registry64,
            path: "SOFTWARE\\Acme".into(),
            enumerate_subkeys: false,
            values: [(
                "serial".into(),
                RegistryValue {
                    name: "Serial".into(),
                    value_type: RegistryType::Qword,
                },
            )]
            .into(),
        },
        cardinality: NativeCardinality::ExactlyOne,
        instance_keys: vec![],
        budget,
    };
    let plan = NativeCollectionPlan::new(NativePlanSpec {
        version: 1,
        scope: CollectionScope::Device,
        queries: [("identity".into(), query.clone())].into(),
        budget,
    })
    .unwrap();
    let result = NativeCollectionResult {
        plan_digest: plan.digest(),
        collected_at: 100,
        queries: [(
            "identity".into(),
            NativeQueryResult {
                query_digest: query.digest(),
                collected_at: 100,
                status: NativeQueryStatus::Complete,
                enumeration_complete: true,
                row_count: 1,
                rows: vec![[("serial".into(), json!(u64::MAX.to_string()))].into()],
                users: None,
            },
        )]
        .into(),
    };
    let key = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
    let tasks:Vec<_>=[TaskPermit::Offer,TaskPermit::Start].into_iter().map(|permit|{
        let spec=CollectionTaskSpec{wire_version:WIRE_VERSION,tenant_id:id,device_id:"device".into(),platform:TaskPlatform::Windows,architecture:TaskArchitecture::X86_64,registration_id:id,generation:7,task_id:id,attempt_id:id,permit,expires_at:110,deadline:200,resource_digest:[1;32],resource:TaskResource{id:"native".into(),version:"v1".into(),variant:"default".into()},authorization:TaskAuthorization::Policy{policy_id:id,policy_version:id},plan_digest:plan.digest(),plan:plan.clone()};
        let payload=TaskPayload::Collection(Box::new(spec));let bytes=payload.signing_bytes("vector-key").unwrap();
        json!({"payloadJson":serde_json::to_string(&payload).unwrap(),"signingBytesLength":bytes.len(),"signingBytesSha256":format!("{:x}",Sha256::digest(&bytes)),"signature":URL_SAFE_NO_PAD.encode(key.sign(&bytes).as_ref())})
    }).collect();
    println!("{}",serde_json::to_string_pretty(&json!({"keyId":"vector-key","seed":vec![42;32],"plan":plan,"planDigest":result.plan_digest,"result":result,"resultDigest":result.digest(),"tasks":tasks})).unwrap());
}
