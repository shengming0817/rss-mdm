//! Reproducible current native task/result vectors for independent Agent consumers.
#[path = "../tests/support/projection.rs"]
mod projection;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::Ed25519KeyPair;
use rss_mdm_agent_wire::{CollectionScope, runtime::*};
use serde_json::json;
use sha2::{Digest, Sha256};
fn vector(
    definition: NativeQueryDefinition,
    rows: Vec<std::collections::BTreeMap<String, serde_json::Value>>,
) -> serde_json::Value {
    let id = uuid::Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
    let budget = NativeBudget {
        timeout_seconds: 60,
        output_bytes: 65536,
        max_rows: 100,
    };
    let query = NativeQuery {
        version: definition.engine().contract_version(),
        cardinality: match &definition {
            NativeQueryDefinition::MacosBrew { .. } => NativeCardinality::List,
            NativeQueryDefinition::System { query } => query.cardinality(),
            _ => NativeCardinality::ExactlyOne,
        },
        instance_keys: if matches!(definition, NativeQueryDefinition::MacosBrew { .. })
            || matches!(&definition, NativeQueryDefinition::System {query} if query.cardinality()==NativeCardinality::List)
        {
            vec!["id".into()]
        } else {
            vec![]
        },
        definition,
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
                scan: match &query.definition {
                    NativeQueryDefinition::System { query } => {
                        query.scan_mode().map(|mode| NativeScanEvidence {
                            mode,
                            source: Some("configured".into()),
                            started_at: Some(80),
                            finished_at: Some(90),
                        })
                    }
                    _ => None,
                },
                query_digest: query.digest(),
                collected_at: 100,
                status: NativeQueryStatus::Complete,
                enumeration_complete: true,
                row_count: rows.len() as u32,
                rows: rows.clone(),
                users: None,
            },
        )]
        .into(),
    };
    let key = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
    let tasks:Vec<_>=[TaskPermit::Offer,TaskPermit::Start].into_iter().map(|permit|{
        let (fields,mappings)=projection::projection(&plan);
        let spec=CollectionTaskSpec{fields,mappings,wire_version:COLLECTION_TASK_VERSION,execution:NativeExecutionBinding{generated_uid:if plan.execution_identity()==ExecutionIdentity::System || plan.platform()==TaskPlatform::Windows {None}else{Some("00000000-0000-0000-0000-000000000501".into())},identity:plan.execution_identity(),context_revision:1,target:if plan.execution_identity() == ExecutionIdentity::System { SoftwareExecutionTarget::Device } else { SoftwareExecutionTarget::User { identity:if plan.platform()==TaskPlatform::Windows {"S-1-5-21-1-2-3-1001".into()}else{"501".into()},session_id:id } }},tenant_id:id,device_id:"device".into(),platform:plan.platform(),architecture:TaskArchitecture::X86_64,registration_id:id,generation:7,task_id:id,attempt_id:id,permit,expires_at:110,deadline:200,resource_digest:[1;32],resource:TaskResource{id:"native".into(),version:"v1".into(),variant:"default".into()},authorization:TaskAuthorization::Policy{policy_id:id,policy_version:id},plan_digest:plan.digest(),plan:plan.clone()};
        let payload=TaskPayload::Collection(Box::new(spec));let bytes=payload.signing_bytes("vector-key").unwrap();
        json!({"payloadJson":serde_json::to_string(&payload).unwrap(),"signingBytesLength":bytes.len(),"signingBytesSha256":format!("{:x}",Sha256::digest(&bytes)),"signature":URL_SAFE_NO_PAD.encode(key.sign(&bytes).as_ref())})
    }).collect();
    json!({"keyId":"vector-key","seed":vec![42;32],"plan":plan,"planDigest":result.plan_digest,"result":result,"resultDigest":result.digest(),"tasks":tasks})
}
fn main() {
    let cases = vec![
        vector(NativeQueryDefinition::WindowsRegistry { hive: RegistryHive::LocalMachine, view: RegistryView::Registry64, path: "SOFTWARE\\Acme".into(), enumerate_subkeys: false,
            values: [("serial".into(), RegistryValue { name: "Serial".into(), value_type: RegistryType::Qword })].into() }, vec![[("serial".into(), json!(u64::MAX.to_string()))].into()]),
        vector(NativeQueryDefinition::MacosHardware { section: MacosHardwareSection::Memory }, vec![[("total_bytes".into(), json!("8192"))].into()]),
        vector(NativeQueryDefinition::MacosBrew { prefix: "/opt/homebrew".into(), package: MacosBrewPackage::Formula, taps: ["homebrew/core".into()].into() },
            vec![serde_json::from_value(json!({"id":"homebrew/core/jq","scope":"user","owner":"501","origin":"homebrew","prefix":"/opt/homebrew","tap":"homebrew/core","package_kind":"formula"})).unwrap()]),
        vector(NativeQueryDefinition::System {query:NativeSystemQuery::WindowsCertificates {store:WindowsCertificateStore::My,user:true}},vec![serde_json::from_value(json!({"id":"a".repeat(64),"subject":"CN=User","issuer":"CN=CA","not_before":1,"not_after":200,"scope":"user","owner":"S-1-5-21-1-2-3-1001","store":"my"})).unwrap()]),
        vector(NativeQueryDefinition::System {query:NativeSystemQuery::MacosCertificates {store:MacosCertificateStore::Login}},vec![serde_json::from_value(json!({"id":"a".repeat(64),"subject":"CN=User","issuer":"CN=CA","not_before":1,"not_after":200,"scope":"user","owner":"00000000-0000-0000-0000-000000000501","store":"login"})).unwrap()]),
        vector(NativeQueryDefinition::System {query:NativeSystemQuery::WindowsUpdates {section:UpdateSection::Available,mode:UpdateScanMode::Local}},vec![]),
        vector(NativeQueryDefinition::System {query:NativeSystemQuery::MacosUpdates {section:UpdateSection::Available,mode:UpdateScanMode::Online}},vec![]),
    ];
    println!("{}", serde_json::to_string_pretty(&cases).unwrap());
}
