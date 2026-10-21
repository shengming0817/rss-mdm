//! Current runtime lease vectors are shared with independent endpoint consumers.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use rss_mdm_agent_wire::runtime::*;
use sha2::{Digest, Sha256};

#[test]
fn signed_configuration_binds_destination_authority_and_lease() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/telemetry-v1-vectors.json")).unwrap();
    let signed: SignedTelemetryConfiguration =
        serde_json::from_value(vector["signed"].clone()).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/signed-telemetry-configuration-v1.schema.json"
    ))
    .unwrap();
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&vector["signed"])
    );
    let seed: Vec<u8> = serde_json::from_value(vector["seed"].clone()).unwrap();
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let public = UnparsedPublicKey::new(&ED25519, pair.public_key().as_ref());
    let signature = URL_SAFE_NO_PAD.decode(&signed.signature).unwrap();
    let bytes = signed.configuration.signing_bytes(&signed.key_id).unwrap();
    assert_eq!(
        bytes.len() as u64,
        vector["signingBytesLength"].as_u64().unwrap()
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        vector["signingBytesSha256"].as_str().unwrap()
    );
    public.verify(&bytes, &signature).unwrap();
    for change in 0..8 {
        let mut altered = signed.configuration.clone();
        match change {
            0 => altered.tenant_id = uuid::Uuid::new_v4(),
            1 => altered.device_id.push('x'),
            2 => altered.registration_id = uuid::Uuid::new_v4(),
            3 => altered.generation += 1,
            4 => altered.source_epoch = uuid::Uuid::new_v4(),
            5 => altered.policy_version = uuid::Uuid::new_v4(),
            6 => altered.expires_at -= 1,
            _ => altered.binding = "b".repeat(64),
        }
        assert!(
            public
                .verify(&altered.signing_bytes(&signed.key_id).unwrap(), &signature)
                .is_err()
        );
    }
    assert!(
        public
            .verify(
                &signed.configuration.signing_bytes("another-key").unwrap(),
                &signature
            )
            .is_err()
    );
    let mut invalid = signed.configuration.clone();
    invalid.expires_at = invalid.issued_at + 301;
    assert!(invalid.signing_bytes(&signed.key_id).is_err());
    invalid = signed.configuration;
    invalid.source = Source::AgentNative;
    assert!(invalid.signing_bytes(&signed.key_id).is_err());
}
