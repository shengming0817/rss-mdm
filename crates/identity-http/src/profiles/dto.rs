//! Private HTTP profile projections; capability/storage codecs are not wire contracts.
use rss_identity_core::profile as core;
use rss_identity_postgres as pg;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schemars(transform = require_value)]
pub(super) struct Change {
    #[schemars(
        with = "Uuid",
        regex(
            pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
        )
    )]
    operation_id: pg::ProfileOperationId,
    expected_revision: i64,
    #[serde(deserialize_with = "Option::deserialize")]
    #[schemars(with = "Option<LocalValue>")]
    value: Option<LocalValue>,
}
fn require_value(schema: &mut schemars::Schema) {
    let required = schema
        .get_mut("required")
        .and_then(Value::as_array_mut)
        .expect("profile change has required identifiers");
    required.push("value".into());
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalValue {
    display_name: Option<String>,
    username: Option<String>,
    email: Option<String>,
    extensions: ExtensionObject,
    max_age_seconds: u32,
}
impl TryFrom<Change> for pg::ProfileChange {
    type Error = core::ProfileError;
    fn try_from(v: Change) -> Result<Self, Self::Error> {
        Ok(Self {
            operation_id: v.operation_id,
            expected_revision: v.expected_revision,
            value: v
                .value
                .map(|v| {
                    Ok(core::LocalProfile {
                        display_name: v.display_name,
                        username: v.username,
                        email: v.email,
                        extensions: core::Extensions::try_from(v.extensions.0)?,
                        max_age_seconds: v.max_age_seconds,
                    })
                })
                .transpose()?,
        })
    }
}
impl From<core::LocalProfile> for LocalValue {
    fn from(v: core::LocalProfile) -> Self {
        Self {
            display_name: v.display_name,
            username: v.username,
            email: v.email,
            extensions: ExtensionObject(v.extensions.into_value()),
            max_age_seconds: v.max_age_seconds,
        }
    }
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct Local {
    revision: i64,
    value: Option<LocalValue>,
}
impl From<pg::LocalProfileView> for Local {
    fn from(v: pg::LocalProfileView) -> Self {
        Self {
            revision: v.revision,
            value: v.value.map(Into::into),
        }
    }
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct Receipt {
    #[schemars(
        with = "Uuid",
        regex(
            pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
        )
    )]
    operation_id: pg::ProfileOperationId,
    revision: i64,
}
impl From<pg::ProfileReceipt> for Receipt {
    fn from(v: pg::ProfileReceipt) -> Self {
        Self {
            operation_id: v.operation_id,
            revision: v.revision,
        }
    }
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Attribute<T> {
    NotConfigured,
    Missing,
    Invalid,
    Available { value: T },
}
fn attribute<T, U>(v: &core::Attribute<T>, convert: impl FnOnce(&T) -> U) -> Attribute<U> {
    match v {
        core::Attribute::NotConfigured => Attribute::NotConfigured,
        core::Attribute::Missing => Attribute::Missing,
        core::Attribute::Invalid => Attribute::Invalid,
        core::Attribute::Available { value } => Attribute::Available {
            value: convert(value),
        },
    }
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
struct Profile {
    display_name: Attribute<String>,
    username: Attribute<String>,
    email: Attribute<String>,
    email_verified: Attribute<bool>,
    extensions: Attribute<ExtensionObject>,
}
impl From<&core::Profile> for Profile {
    fn from(v: &core::Profile) -> Self {
        Self {
            display_name: attribute(&v.display_name, Clone::clone),
            username: attribute(&v.username, Clone::clone),
            email: attribute(&v.email, Clone::clone),
            email_verified: attribute(&v.email_verified, |v| *v),
            extensions: attribute(&v.extensions, |v| {
                ExtensionObject(Value::Object(v.object().clone()))
            }),
        }
    }
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Source {
    IdentityLocal,
    Idp { provider: String },
}
impl From<pg::ProfileSource> for Source {
    fn from(v: pg::ProfileSource) -> Self {
        match v {
            pg::ProfileSource::IdentityLocal => Self::IdentityLocal,
            pg::ProfileSource::Idp { provider } => Self::Idp {
                provider: provider.to_string(),
            },
        }
    }
}
#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct Observation {
    instance_id: String,
    tenant_id: String,
    principal_id: String,
    source: Option<Source>,
    status: &'static str,
    snapshot_id: Option<Uuid>,
    provider_config_version: Option<i64>,
    source_revision: Option<i64>,
    observed_at: Option<i64>,
    collected_at_micros: Option<i64>,
    expires_at: Option<i64>,
    profile: Option<Profile>,
}
impl From<&pg::ProfileView> for Observation {
    fn from(v: &pg::ProfileView) -> Self {
        Self {
            instance_id: v.instance_id.clone(),
            tenant_id: v.tenant_id.clone(),
            principal_id: v.principal_id.clone(),
            source: v.source.map(Into::into),
            status: match v.status {
                pg::ProfileStatus::Available => "available",
                pg::ProfileStatus::Missing => "missing",
                pg::ProfileStatus::Expired => "expired",
                pg::ProfileStatus::Unavailable => "unavailable",
            },
            snapshot_id: v.snapshot_id,
            provider_config_version: v.provider_config_version,
            source_revision: v.source_revision,
            observed_at: v.observed_at,
            collected_at_micros: v.collected_at_micros,
            expires_at: v.expires_at,
            profile: v.profile.as_ref().map(Into::into),
        }
    }
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
struct ExtensionObject(#[schemars(schema_with = "extensions_schema")] Value);
fn extensions_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type":"object","x-rss-extension":"Named tenant profile attributes validated by Identity Extensions and ProfileLimits"})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clearing_a_local_profile_requires_an_explicit_value() {
        let schema = schemars::schema_for!(Change).to_value();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let mut request =
            serde_json::json!({"operationId":pg::ProfileOperationId::now(),"expectedRevision":1});
        assert!(!validator.is_valid(&request));
        assert!(serde_json::from_value::<Change>(request.clone()).is_err());
        for value in [
            Value::Null,
            serde_json::json!({"extensions":{},"maxAgeSeconds":60}),
        ] {
            request["value"] = value;
            assert!(validator.is_valid(&request));
            assert!(serde_json::from_value::<Change>(request.clone()).is_ok());
        }
    }
}
