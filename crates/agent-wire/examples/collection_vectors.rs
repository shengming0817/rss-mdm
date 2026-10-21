//! Refresh the deliberately changed current collection contract; unrelated task/PKI vectors stay intact.
use rss_mdm_agent_wire::runtime::{CollectionDefinition, ReportRequest};
use serde_json::Value;
use sha2::{Digest, Sha256};
fn main() {
    let mut vectors: Value =
        serde_json::from_str(include_str!("../tests/fixtures/v1-vectors.json")).unwrap();
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
