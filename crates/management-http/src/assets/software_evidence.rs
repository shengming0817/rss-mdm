//! Installation evidence projection; the persisted Inventory scalar remains native.
use crate::{Error, Failure, decimal::DecimalI64};
use rss_mdm_inventory::Scalar as NativeScalar;
use rss_mdm_inventory_service::assets::{AssetEnvelope, Response, software as model};
use schemars::JsonSchema;
use serde::Serialize;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum EvidenceAsset {
    Software { response: EvidenceResponse },
}
#[derive(Serialize, JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(super) enum EvidenceResponse {
    Evidence {
        task: Uuid,
        coordinates: model::Coordinates,
        items: Vec<InstallationEvidence>,
        quality: Vec<model::Quality>,
        next_cursor: Option<String>,
    },
}
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct InstallationEvidence {
    endpoint: rss_mdm_agent_wire::DeviceId,
    source: model::SoftwareSource,
    evidence: rss_mdm_inventory::Evidence,
    array_version: String,
    ordinal: usize,
    value: Scalar,
    rules: Vec<Uuid>,
    confirmed: bool,
}
#[derive(Serialize, JsonSchema)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Scalar {
    String(String),
    Integer(DecimalI64),
    Number(f64),
    Array(Vec<Scalar>),
    Object(BTreeMap<String, Scalar>),
    Boolean(bool),
    Time(i64),
}
impl From<NativeScalar> for Scalar {
    fn from(value: NativeScalar) -> Self {
        match value {
            NativeScalar::String(v) => Self::String(v),
            NativeScalar::Integer(v) => Self::Integer(v.into()),
            NativeScalar::Number(v) => Self::Number(v.into_inner()),
            NativeScalar::Array(v) => Self::Array(v.into_iter().map(Into::into).collect()),
            NativeScalar::Object(v) => {
                Self::Object(v.into_iter().map(|(k, v)| (k, v.into())).collect())
            }
            NativeScalar::Boolean(v) => Self::Boolean(v),
            NativeScalar::Time(v) => Self::Time(v),
        }
    }
}
impl From<model::InstallationEvidence> for InstallationEvidence {
    fn from(v: model::InstallationEvidence) -> Self {
        Self {
            endpoint: v.endpoint,
            source: v.source,
            evidence: v.evidence,
            array_version: v.array_version,
            ordinal: v.ordinal,
            value: v.value.into(),
            rules: v.rules,
            confirmed: v.confirmed,
        }
    }
}
pub(super) fn project(envelope: AssetEnvelope) -> Result<AssetEnvelope<EvidenceAsset>, Error> {
    let Response::Software { response } = envelope.asset else {
        return Err(Error::Unavailable(Failure::AssetsStorage));
    };
    let model::Response::Evidence {
        task,
        coordinates,
        items,
        quality,
        next_cursor,
    } = *response
    else {
        return Err(Error::Unavailable(Failure::AssetsStorage));
    };
    Ok(AssetEnvelope {
        tenant_id: envelope.tenant_id,
        asset: EvidenceAsset::Software {
            response: EvidenceResponse::Evidence {
                task,
                coordinates,
                items: items.into_iter().map(Into::into).collect(),
                quality,
                next_cursor,
            },
        },
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_observations_are_lossless_without_changing_storage_or_other_scalars() {
        let native = NativeScalar::Object(
            [(
                "values".into(),
                NativeScalar::Array(vec![
                    NativeScalar::Integer(i64::MIN),
                    NativeScalar::Integer(i64::MAX),
                    NativeScalar::Integer(1),
                    NativeScalar::Time(42),
                    NativeScalar::Boolean(false),
                    NativeScalar::String("9223372036854775807".into()),
                ]),
            )]
            .into(),
        );
        let persisted = serde_json::to_value(&native).unwrap();
        let output = serde_json::to_value(Scalar::from(native)).unwrap();
        let values = &output["value"]["values"]["value"];
        assert_eq!(values[0]["value"], i64::MIN.to_string());
        assert_eq!(values[1]["value"], i64::MAX.to_string());
        assert_eq!(values[2]["value"], "1");
        assert_eq!(values[3]["value"], 42);
        assert_eq!(values[4]["value"], false);
        assert_eq!(values[5]["kind"], "string");
        assert_eq!(persisted["value"]["values"]["value"][0]["value"], i64::MIN);
        let schema = schemars::generate::SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator()
            .into_root_schema_for::<Scalar>()
            .to_value();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(validator.is_valid(&output));
        assert!(!validator.is_valid(&persisted));
    }
}
