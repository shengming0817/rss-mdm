//! Current fixed vectors: task bytes from the recorded baseline; collection scope revised by COLLECT-M01.
//! Regenerate only when a protocol owner deliberately changes the current contract.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::Ed25519KeyPair;
use rss_mdm_agent_wire::runtime::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/v1-vectors.json")).unwrap()
}
fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap()
}
#[test]
fn current_task_families_preserve_canonical_bytes_digests_and_signatures() {
    let vectors = vectors();
    let seed: Vec<u8> = serde_json::from_value(vectors["seed"].clone()).unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let schema: Value = serde_json::from_str(include_str!(
        "../schema/runtime/task-payload-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for vector in vectors["tasks"].as_array().unwrap() {
        let payload: TaskPayload = serde_json::from_str(text(vector, "payloadJson")).unwrap();
        assert_eq!(
            serde_json::to_string(&payload).unwrap(),
            text(vector, "payloadJson")
        );
        assert!(validator.is_valid(&serde_json::to_value(&payload).unwrap()));
        let bytes = payload.signing_bytes(text(&vectors, "keyId")).unwrap();
        assert_eq!(
            bytes.len() as u64,
            vector["signingBytesLength"].as_u64().unwrap()
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            text(vector, "signingBytesSha256")
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(key.sign(&bytes).as_ref()),
            text(vector, "signature")
        );
        if let TaskPayload::Software(spec) = payload {
            assert_eq!(
                format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(&spec.steps).unwrap())
                ),
                text(&vectors, "softwareDefinitionDigest")
            );
        }
    }
}
#[test]
fn collection_reports_and_outcomes_preserve_exact_json_and_fingerprint() {
    let vectors = vectors();
    let collection: CollectionDefinition =
        serde_json::from_str(text(&vectors, "collectionJson")).unwrap();
    assert_eq!(
        serde_json::to_string(&collection).unwrap(),
        text(&vectors, "collectionJson")
    );
    assert_eq!(
        collection.fingerprint().unwrap(),
        text(&vectors, "collectionFingerprint")
    );
    let mut input: Value = serde_json::from_str(text(&vectors, "reportJson")).unwrap();
    input["collection"]["fields"]
        .as_array_mut()
        .unwrap()
        .reverse();
    input["body"]["values"].as_array_mut().unwrap().reverse();
    let report: ReportRequest = serde_json::from_value(input).unwrap();
    let bytes = report.canonical().unwrap();
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        text(&vectors, "reportJson")
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        text(&vectors, "reportSha256")
    );
    let outcomes: Vec<CollectedValue> =
        serde_json::from_str(text(&vectors, "outcomesJson")).unwrap();
    assert_eq!(
        serde_json::to_string(&outcomes).unwrap(),
        text(&vectors, "outcomesJson")
    );
    let schema: Value = serde_json::from_str(include_str!(
        "../schema/runtime/report-request-v1.schema.json"
    ))
    .unwrap();
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&serde_json::to_value(&report).unwrap())
    );
}
