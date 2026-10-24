//! Refresh the deliberately changed current collection contract; unrelated task/PKI vectors stay intact.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::Ed25519KeyPair;
use rss_mdm_agent_wire::runtime::{CollectionDefinition, ReportRequest, TaskPayload};
use serde_json::Value;
use sha2::{Digest, Sha256};
fn main() {
    let mut vectors: Value =
        serde_json::from_str(include_str!("../tests/fixtures/v1-vectors.json")).unwrap();
    let seed: Vec<u8> = serde_json::from_value(vectors["seed"].clone()).unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let key_id = vectors["keyId"].as_str().unwrap().to_owned();
    for vector in vectors["tasks"].as_array_mut().unwrap() {
        let payload: TaskPayload =
            serde_json::from_str(vector["payloadJson"].as_str().unwrap()).unwrap();
        let bytes = payload.signing_bytes(&key_id).unwrap();
        vector["payloadJson"] = serde_json::to_string(&payload).unwrap().into();
        vector["signingBytesLength"] = bytes.len().into();
        vector["signingBytesSha256"] = format!("{:x}", Sha256::digest(&bytes)).into();
        vector["signature"] = URL_SAFE_NO_PAD.encode(key.sign(&bytes).as_ref()).into();
    }
    let collection: CollectionDefinition =
        serde_json::from_str(vectors["collectionJson"].as_str().unwrap()).unwrap();
    vectors["collectionJson"] = serde_json::to_string(&collection).unwrap().into();
    vectors["collectionFingerprint"] = collection.fingerprint().unwrap().into();
    let report: ReportRequest =
        serde_json::from_str(vectors["reportJson"].as_str().unwrap()).unwrap();
    let bytes = report.canonical().unwrap();
    vectors["reportJson"] = String::from_utf8(bytes.clone()).unwrap().into();
    vectors["reportSha256"] = format!("{:x}", Sha256::digest(bytes)).into();
    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}
