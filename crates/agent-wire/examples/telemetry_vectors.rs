//! Canonical signed lease for independent consumers of the current runtime contract.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::Ed25519KeyPair;
use rss_mdm_agent_wire::runtime::*;
use serde_json::json;
use sha2::{Digest, Sha256};
fn main() {
    let id = uuid::Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
    let configuration = TelemetryConfiguration {
        resource_digest: [8; 32],
        tenant_id: id,
        device_id: "telemetry-vector".into(),
        registration_id: id,
        generation: 1,
        source_epoch: id,
        issued_at: 1000,
        expires_at: 1300,
        policy: id,
        policy_version: id,
        source: Source::AgentScript,
        binding: "a".repeat(64),
        template: TaskResource {
            id: "metric-script".into(),
            version: "v1".into(),
            variant: "default".into(),
        },
        collector: TelemetryCollector::Script {
            content: TaskContent {
                length: 4,
                sha256: [7; 32],
            },
            profile: ExecutorProfile::PosixSh,
            arguments: vec!["literal; $(ignored)".into()],
            environment: [("RSS_PARAM_DIR".into(), "/Library".into())].into(),
            sql_parameters: None,
            output_schema: json!({"type":"object","properties":{"load":{"type":"integer"}},"required":["load"],"additionalProperties":false}),
            timeout_seconds: 1,
            max_rows: 1,
            mappings: [(
                "custom.load".into(),
                ValueMapping {
                    pointer: "/load".into(),
                    conversion: Conversion::Identity,
                    columns: Default::default(),
                },
            )]
            .into(),
        },
        fields: vec![FieldDefinition {
            time_series: Some(TimeSeriesBinding {
                kind: TelemetryKind::Gauge,
                value_path: vec![],
                interval_start_path: None,
                dimensions: Default::default(),
                aggregations: [TelemetryAggregation::Mean].into(),
                retention: RetentionReference {
                    key: "standard".into(),
                    revision: 1,
                },
                max_resources: 1,
            }),
            key: FieldKey::parse("custom.load").unwrap(),
            version: 1,
            value_type: ValueType::Integer,
            nullable: false,
            manual: false,
            sources: [(Source::AgentScript, 0)].into(),
            platforms: [Platform::Macos].into(),
            sensitivity: Sensitivity::Standard,
            unit: Some("percent".into()),
            searchable: true,
            item_key: None,
        }],
        sample_millis: 5000,
        normal_sample_millis: 5000,
        boost_expires_at: None,
        upload_millis: 10000,
        max_bytes: 65536,
        max_points: 64,
        max_resources: 1,
        execution_millis: 1000,
        output_bytes: 4096,
        backfill_seconds: 3600,
    };
    let key = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
    let key_id = "vector-key";
    let bytes = configuration.signing_bytes(key_id).unwrap();
    let signed = SignedTelemetryConfiguration {
        configuration,
        key_id: key_id.into(),
        signature: URL_SAFE_NO_PAD.encode(key.sign(&bytes).as_ref()),
    };
    println!("{}",serde_json::to_string_pretty(&json!({"signed":signed,"signingBytesLength":bytes.len(),"signingBytesSha256":format!("{:x}",Sha256::digest(bytes)),"seed":vec![42u8;32]})).unwrap());
}
