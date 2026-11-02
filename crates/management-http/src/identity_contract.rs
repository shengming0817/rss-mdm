//! Schemas for fixed external serializers; Identity remains the sole authentication owner.
//! ref: rss-identity e753aec31b3e2ea8852bfdcf183909c0100b4394 identity-{core,postgres}/src/department.rs
//! ref: webauthn-rs-proto 0.5.5 src/{auth,options,extensions}.rs; base64urlsafedata 0.5.5 Serialize.
use schemars::{Schema, SchemaGenerator};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;
fn object(fields: &[(&str, Value)], required: &[&str]) -> Value {
    json!({"type":"object","properties":fields.iter().map(|(k,v)|(k.to_string(),v.clone())).collect::<serde_json::Map<_,_>>(),"required":required,"additionalProperties":false})
}
fn vocabulary<T: Serialize>(values: impl IntoIterator<Item = T>) -> Value {
    json!({"type":"string","enum":values.into_iter().map(|v|serde_json::to_value(v).expect("external enum serialization")).collect::<Vec<_>>()})
}
fn snapshot(_: &mut SchemaGenerator) -> Schema {
    let text = json!({"type":"string","minLength":1,"maxLength":256,"pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]*$","description":"Identity additionally validates the 256 UTF-8 byte budget, trimming and department tree relationships"});
    let node = object(
        &[
            ("id", text.clone()),
            ("displayName", text.clone()),
            ("parentId", json!({"anyOf":[text.clone(),{"type":"null"}]})),
        ],
        &["id", "displayName", "parentId"],
    );
    object(
        &[
            ("version", json!({"type":"integer","const":1})),
            ("sourceRevision", text.clone()),
            (
                "nodes",
                json!({"type":"array","minItems":1,"maxItems":256,"items":node}),
            ),
            (
                "memberships",
                json!({"type":"array","maxItems":16,"items":text}),
            ),
        ],
        &["version", "sourceRevision", "nodes", "memberships"],
    )
    .try_into()
    .expect("Identity department schema")
}
fn unavailable(_: &mut SchemaGenerator) -> Schema {
    use rss_identity_core::department::DepartmentUnavailableReason::*;
    vocabulary([
        LocalIdentity,
        NotConfigured,
        ClaimMissing,
        InvalidClaim,
        NotYetValid,
    ])
    .try_into()
    .expect("Identity reason schema")
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub(crate) enum Departments {
    Available {
        source: DepartmentSource,
        snapshot_id: Uuid,
        observed_at: i64,
        expires_at: i64,
        #[schemars(schema_with = "snapshot")]
        snapshot: rss_identity_core::department::DepartmentSnapshot,
    },
    Expired,
    Unavailable {
        #[schemars(schema_with = "unavailable")]
        reason: rss_identity_core::department::DepartmentUnavailableReason,
    },
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DepartmentSource {
    pub provider_id: Uuid,
    pub issuer: String,
    pub configuration_version: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn validator<T: schemars::JsonSchema>() -> jsonschema::Validator {
        let schema = schemars::generate::SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator()
            .into_root_schema_for::<T>()
            .to_value();
        jsonschema::validator_for(&schema).unwrap()
    }
    #[test]
    fn fixed_identity_department_serializer_preserves_root_null_and_closed_unavailability() {
        let snapshot=serde_json::from_value(json!({"version":1,"sourceRevision":"r1","nodes":[{"id":"root","displayName":"Root","parentId":null}],"memberships":["root"]})).unwrap();
        let response = Departments::Available {
            source: DepartmentSource {
                provider_id: Uuid::nil(),
                issuer: "https://idp.test".into(),
                configuration_version: 1,
            },
            snapshot_id: Uuid::nil(),
            observed_at: 10,
            expires_at: 20,
            snapshot,
        };
        let encoded = serde_json::to_value(response).unwrap();
        let validator = validator::<Departments>();
        assert!(validator.is_valid(&encoded));
        let mut missing = encoded;
        missing["snapshot"]["nodes"][0]
            .as_object_mut()
            .unwrap()
            .remove("parentId");
        assert!(!validator.is_valid(&missing));
        for reason in [
            rss_identity_core::department::DepartmentUnavailableReason::LocalIdentity,
            rss_identity_core::department::DepartmentUnavailableReason::NotConfigured,
            rss_identity_core::department::DepartmentUnavailableReason::ClaimMissing,
            rss_identity_core::department::DepartmentUnavailableReason::InvalidClaim,
            rss_identity_core::department::DepartmentUnavailableReason::NotYetValid,
        ] {
            assert!(
                validator
                    .is_valid(&serde_json::to_value(Departments::Unavailable { reason }).unwrap())
            );
        }
        assert!(!validator.is_valid(&json!({"status":"unavailable","reason":"future"})));
    }
}
