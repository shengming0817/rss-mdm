use super::*;
fn candidate() -> serde_json::Value {
    serde_json::json!({"format_version":4,"source":{"inputs_sha256":supported().inputs_sha256},"version":"rss-mdm 0.1.0","platform":"linux/arm64","migrations":crate::migration::source_manifest(),"image":format!("rss/server@sha256:{}","1".repeat(64)),"archive":{"file":"server.oci.tar","sha256":"0".repeat(64),"manifest_digest":format!("sha256:{}","1".repeat(64))},"providers":{"postgres":"fixed"},"deployment":{"deployment/compose.yaml":"0".repeat(64)}})
}
fn admitted(value: &serde_json::Value) -> bool {
    let bytes = serde_json::to_vec(value).unwrap();
    validate(&bytes, &format!("{:x}", Sha256::digest(&bytes))).is_ok()
}
#[test]
fn exact_source_and_unit_manifest_are_both_required() {
    let original = candidate();
    assert!(admitted(&original));
    for (pointer, value) in [
        ("/format_version", serde_json::json!(5)),
        ("/source/inputs_sha256", serde_json::json!("f".repeat(64))),
        ("/archive/file", serde_json::json!("../other.tar")),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(!admitted(&changed));
    }
    let mut changed = original.clone();
    changed["migrations"]["units"].as_array_mut().unwrap().pop();
    assert!(!admitted(&changed));
    let bytes = serde_json::to_vec(&original).unwrap();
    assert!(validate(&bytes, &"0".repeat(64)).is_err());
}
