use rss_mdm_agent_wire::runtime::*;
#[test]
fn output_chunks_are_bounded_complete_and_digest_bound() {
    let value = serde_json::json!([{"name":"x".repeat(OUTPUT_CHUNK_BYTES)}]);
    let result = TaskResult::new(
        Some(0),
        OutputQuality::Complete,
        value.clone(),
        TaskDiagnostics::new("".into(), "".into(), 1, 1, None).unwrap(),
        2,
    )
    .unwrap();
    let (reference, chunks) = ChunkedTaskResult::split(result).unwrap();
    assert_eq!(chunks.len(), 2);
    assert!(
        reference
            .assemble(chunks.iter().take(1).cloned().collect())
            .is_err()
    );
    assert!(
        reference
            .assemble(vec![chunks[0].clone(), chunks[0].clone()])
            .is_err()
    );
    assert_eq!(reference.assemble(chunks).unwrap().output(), &value);
}
#[test]
fn malformed_manifest_and_chunk_index_are_rejected() {
    assert!(OutputManifest::new(0, [0; 32]).is_err());
    assert!(OutputManifest::new(OUTPUT_MAX_BYTES as u32 + 1, [0; 32]).is_err());
    let manifest = OutputManifest::new(4, [0; 32]).unwrap();
    assert!(OutputChunk::new(manifest.clone(), 1, b"null").is_err());
    assert!(OutputChunk::new(manifest, 0, b"x").is_err());
    use sha2::{Digest, Sha256};
    let bytes = b"{\"result\":true}";
    let manifest = OutputManifest::new(bytes.len() as u32, Sha256::digest(bytes).into()).unwrap();
    let corrupt = OutputChunk::new(manifest.clone(), 0, b"{\"result\":null}").unwrap();
    assert!(manifest.assemble(vec![corrupt]).is_err());
}
