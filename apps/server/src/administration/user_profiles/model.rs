use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileSource {
    IdentityLocal,
    Idp { provider: Uuid },
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    String,
    Boolean,
    Number,
    Integer,
    Array,
    Object,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    #[serde(rename = "self")]
    SelfOnly,
    ProfilesRead,
    Both,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayUse {
    Profile,
    Summary,
    Hidden,
}
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefinitionValue {
    pub key: String,
    pub display_name: String,
    pub source: ProfileSource,
    pub pointer: String,
    pub value_type: ValueType,
    pub max_length: Option<u32>,
    pub max_items: Option<u32>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub enabled: bool,
    pub sensitive: bool,
    pub visibility: Visibility,
    pub display_use: DisplayUse,
    pub required: bool,
    pub use_existing_observation: bool,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub value: Option<DefinitionValue>,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum View {
    #[default]
    Current,
    Latest,
}
#[derive(schemars::JsonSchema, Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileQuery {
    #[serde(default)]
    pub view: View,
    #[serde(default)]
    pub preview: bool,
}

#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Definition {
    pub field_id: Uuid,
    pub revision: i64,
    pub collected_after_micros: i64,
    pub value: Option<DefinitionValue>,
}
#[derive(schemars::JsonSchema, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub definition: Definition,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefinitionRow {
    #[serde(flatten)]
    pub definition: Definition,
    pub key: String,
    pub display_name: String,
    pub source_kind: SourceKind,
    pub provider: Option<Uuid>,
    pub value_type: ValueType,
    pub enabled: bool,
    pub sensitive: bool,
    pub required: bool,
    pub visibility: Visibility,
    pub display_use: DisplayUse,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    IdentityLocal,
    Idp,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceView {
    pub source: ProfileSource,
    pub provider_config_version: Option<i64>,
    pub extensions_root: Option<String>,
    pub max_age_seconds: u32,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Definitions {
    pub items: Vec<rss_mdm_query::directory::Projection<DefinitionRow>>,
    pub next_cursor: Option<String>,
    pub sources: Vec<SourceView>,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Attribute<T> {
    Available { value: T },
    Missing,
    Invalid,
    NotConfigured,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fixed {
    pub display_name: Attribute<String>,
    pub username: Attribute<String>,
    pub email: Attribute<String>,
    pub email_verified: Attribute<bool>,
}
#[derive(schemars::JsonSchema, Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileStatus {
    Available,
    Missing,
    Expired,
    Unavailable,
}
#[derive(schemars::JsonSchema, Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldStatus {
    Available,
    Missing,
    Expired,
    Unavailable,
    PendingLogin,
    Invalid,
    NotConfigured,
    Redacted,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedProfile {
    pub source: Option<ProfileSource>,
    pub status: ProfileStatus,
    pub snapshot_id: Option<Uuid>,
    pub provider_config_version: Option<i64>,
    pub source_revision: Option<i64>,
    pub observed_at: Option<i64>,
    pub collected_at_micros: Option<i64>,
    pub expires_at: Option<i64>,
    pub fixed: Option<Fixed>,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldView {
    pub field_id: Uuid,
    pub revision: i64,
    pub key: String,
    pub display_name: String,
    pub source: ProfileSource,
    pub value_type: ValueType,
    pub sensitive: bool,
    pub display_use: DisplayUse,
    pub required: bool,
    pub status: FieldStatus,
    #[schemars(extend("x-rss-extension"="User-defined attribute admitted by DefinitionValue and model::conforms"))]
    pub value: Option<Value>,
}
#[derive(schemars::JsonSchema, Serialize)]
pub struct Completeness {
    pub required: u32,
    pub complete: u32,
    pub missing: u32,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub principal_id: Uuid,
    pub view: View,
    pub profiles: Vec<ObservedProfile>,
    pub fields: Vec<FieldView>,
    pub completeness: Completeness,
}
// Mapping semantics and strict JSON Pointer admission.
// ref: serde_json 1.0.151 src/value/mod.rs::pointer (RFC 6901 traversal).
use super::{Error, Value};
fn text(v: &str, max: usize) -> bool {
    !v.is_empty() && v.len() <= max && !v.chars().any(char::is_control)
}
pub(super) fn validate(v: &DefinitionValue) -> Result<(), Error> {
    if !text(&v.key, 64)
        || !v.key.as_bytes()[0].is_ascii_alphabetic()
        || !v
            .key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_')
        || matches!(
            v.key.as_str(),
            "principalId"
                | "tenantId"
                | "instanceId"
                | "sessionId"
                | "authentication"
                | "authTime"
                | "issuedAt"
                | "groups"
                | "department"
                | "displayName"
                | "username"
                | "email"
                | "emailVerified"
                | "extensions"
        )
        || !text(&v.display_name, 256)
        || !pointer(&v.pointer)
        || matches!(v.source,ProfileSource::Idp{provider} if provider.is_nil())
    {
        return Err(Error::Malformed);
    }
    if v.max_length.is_some_and(|n| n == 0 || n > 65536)
        || v.max_items.is_some_and(|n| {
            n == 0
                || n > if v.value_type == ValueType::Object {
                    256
                } else {
                    128
                }
        })
        || v.minimum.is_some_and(|n| !number(n))
        || v.maximum.is_some_and(|n| !number(n))
        || matches!((v.minimum,v.maximum),(Some(a),Some(b)) if a>b)
    {
        return Err(Error::Malformed);
    }
    if (v.max_length.is_some() && v.value_type != ValueType::String)
        || (v.max_items.is_some() && !matches!(v.value_type, ValueType::Array | ValueType::Object))
        || ((v.minimum.is_some() || v.maximum.is_some())
            && !matches!(v.value_type, ValueType::Number | ValueType::Integer))
    {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn number(n: f64) -> bool {
    n.is_finite() && (n.fract() != 0.0 || n.abs() <= 9_007_199_254_740_991.0)
}
fn pointer(value: &str) -> bool {
    if value.len() > 1024
        || value.chars().any(char::is_control)
        || (!value.is_empty() && !value.starts_with('/'))
    {
        return false;
    }
    let mut bytes = value.bytes();
    while let Some(c) = bytes.next() {
        if c == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return false;
        }
    }
    true
}
pub(super) fn mapping_changed(a: &DefinitionValue, b: &DefinitionValue) -> bool {
    a.source != b.source
        || a.pointer != b.pointer
        || a.value_type != b.value_type
        || a.max_length != b.max_length
        || a.max_items != b.max_items
        || a.minimum != b.minimum
        || a.maximum != b.maximum
        || a.use_existing_observation != b.use_existing_observation
}
pub(super) fn conforms(v: &Value, d: &DefinitionValue) -> bool {
    match d.value_type {
        ValueType::String => v
            .as_str()
            .is_some_and(|s| s.len() <= d.max_length.unwrap_or(65536) as usize),
        ValueType::Boolean => v.is_boolean(),
        ValueType::Number | ValueType::Integer => v.as_f64().is_some_and(|n| {
            number(n)
                && (d.value_type != ValueType::Integer || n.fract() == 0.0)
                && d.minimum.is_none_or(|min| n >= min)
                && d.maximum.is_none_or(|max| n <= max)
        }),
        ValueType::Array => v
            .as_array()
            .is_some_and(|v| v.len() <= d.max_items.unwrap_or(128) as usize),
        ValueType::Object => v
            .as_object()
            .is_some_and(|v| v.len() <= d.max_items.unwrap_or(256) as usize),
    }
}
pub(super) fn source(value: &ProfileSource) -> Result<rss_identity_postgres::ProfileSource, Error> {
    Ok(match value {
        ProfileSource::IdentityLocal => rss_identity_postgres::ProfileSource::IdentityLocal,
        ProfileSource::Idp { provider } => rss_identity_postgres::ProfileSource::Idp {
            provider: rss_identity_core::federation::ProviderId::parse(&provider.to_string())
                .map_err(|_| Error::Malformed)?,
        },
    })
}
pub(super) fn source_dto(value: rss_identity_postgres::ProfileSource) -> ProfileSource {
    match value {
        rss_identity_postgres::ProfileSource::IdentityLocal => ProfileSource::IdentityLocal,
        rss_identity_postgres::ProfileSource::Idp { provider } => ProfileSource::Idp {
            provider: Uuid::parse_str(&provider.to_string()).expect("validated provider id"),
        },
    }
}
