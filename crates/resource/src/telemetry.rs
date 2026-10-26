//! Immutable periodic sampling configuration; execution remains owned by referenced templates.
use crate::{Architecture, Error, Id, Platform};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Explicit projection destinations, independent of the retention policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryProjection {
    /// Update the existing Observation/Inventory owner only.
    Current,
    /// Store observations as time-series samples only.
    History,
    /// Deliver each effect independently using the same sealed input.
    Both,
}
/// Exact Resource template; no moving latest pointer or arbitrary executable input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryTemplate {
    /// Existing Resource identity.
    pub resource: String,
    /// Published immutable version.
    pub version: String,
    /// Exact platform-specific variant.
    pub variant: String,
    /// Native operating system.
    #[schemars(with = "rss_mdm_agent_wire::runtime::TaskPlatform")]
    pub platform: Platform,
    /// Actual processor architecture.
    #[schemars(with = "rss_mdm_agent_wire::runtime::TaskArchitecture")]
    pub architecture: Architecture,
}
/// All limits are explicit and checked before a profile is published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryBudget {
    /// Maximum points in an uploaded batch.
    pub points: u32,
    /// Maximum uncompressed complete JSON input bytes.
    pub bytes: u32,
    /// Maximum expanded resources across all fields in a sample.
    pub resources: u32,
    /// Maximum template execution duration.
    pub execution_millis: u32,
    /// Maximum output bytes produced by one execution.
    pub output_bytes: u32,
}
/// Temporary sampling override; expiration uses absolute UTC, never a renewed lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryBoost {
    /// Faster sampling cadence.
    pub sample_millis: u32,
    /// Original UTC expiration in Unix seconds.
    pub expires_at: i64,
}
/// Authored input frozen by ordinary Resource publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryProfileSpec {
    /// Exact native/script/osquery template reference.
    pub template: TelemetryTemplate,
    /// Literal inputs validated by the exact script template; empty for native collection.
    #[schemars(extend("maxProperties" = 64, "x-rss-extension" = "Literal arguments validated against the exact frozen script template schema; native templates require an empty map"))]
    pub parameters: BTreeMap<String, serde_json::Value>,
    /// Exact field versions, resolved by the publishing application.
    pub fields: Vec<TelemetryFieldReference>,
    /// Current and/or historical effects.
    pub projection: TelemetryProjection,
    /// Normal sampling cadence.
    pub sample_millis: u32,
    /// Maximum time between uploads.
    pub upload_millis: u32,
    /// Resource limits for this profile.
    pub budget: TelemetryBudget,
    /// Optional temporary override.
    pub boost: Option<TelemetryBoost>,
    /// Maximum historical upload age, measured against product receipt time.
    pub backfill_seconds: u32,
}
/// Exact Inventory identity. The composition owner resolves and freezes its definition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryFieldReference {
    /// Stable key owned by the Inventory catalog.
    pub key: String,
    /// Exact immutable definition version.
    pub version: u64,
}
/// Validated profile; deserialization uses the same constructor as publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "TelemetryProfileSpec", into = "TelemetryProfileSpec")]
pub struct TelemetryProfile(TelemetryProfileSpec);
impl From<TelemetryProfile> for TelemetryProfileSpec {
    fn from(p: TelemetryProfile) -> Self {
        p.0
    }
}
impl TryFrom<TelemetryProfileSpec> for TelemetryProfile {
    type Error = Error;
    fn try_from(v: TelemetryProfileSpec) -> Result<Self, Error> {
        Self::new(v)
    }
}
impl TelemetryProfile {
    /// Validate execution controls. Descriptive data belongs to Resource presentation.
    pub fn new(spec: TelemetryProfileSpec) -> Result<Self, Error> {
        let bad = || Error::InvalidInput;
        for v in [
            &spec.template.resource,
            &spec.template.version,
            &spec.template.variant,
        ] {
            Id::new(v)?;
        }
        if spec.parameters.len() > 64
            || spec.fields.is_empty()
            || spec.fields.len() > 64
            || spec.sample_millis == 0
            || spec.upload_millis < spec.sample_millis
            || spec.backfill_seconds == 0
            || !(1..=4096).contains(&spec.budget.points)
            || !(1..=4 * 1024 * 1024).contains(&spec.budget.bytes)
            || !(1..=4096).contains(&spec.budget.resources)
            || spec.budget.execution_millis == 0
            || spec.budget.execution_millis > 300_000
            || spec.budget.execution_millis > spec.sample_millis
            || spec.budget.output_bytes == 0
            || spec.budget.output_bytes > spec.budget.bytes
        {
            return Err(bad());
        }
        if spec.boost.as_ref().is_some_and(|b| {
            b.sample_millis == 0
                || b.sample_millis >= spec.sample_millis
                || b.sample_millis < spec.budget.execution_millis
                || b.expires_at <= 0
        }) {
            return Err(bad());
        }
        let mut keys = std::collections::BTreeSet::new();
        for field in &spec.fields {
            Id::new(&field.key)?;
            if field.version == 0 || field.version > i64::MAX as u64 || !keys.insert(&field.key) {
                return Err(bad());
            }
        }
        let profile = Self(spec);
        if profile.canonical().len() > 256 * 1024 {
            return Err(bad());
        }
        Ok(profile)
    }
    /// Exact immutable input.
    pub fn spec(&self) -> &TelemetryProfileSpec {
        &self.0
    }
    /// Effective sampling cadence; rereading never extends the boost.
    pub fn sample_millis(&self, now_seconds: i64) -> u32 {
        self.0
            .boost
            .as_ref()
            .filter(|b| now_seconds < b.expires_at)
            .map_or(self.0.sample_millis, |b| b.sample_millis)
    }
    /// Resource artifact bytes.
    pub fn canonical(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0).expect("typed telemetry profile")
    }
    /// Bind the enclosing variant to the referenced template coordinates.
    pub fn validate_target(
        &self,
        platform: Platform,
        architecture: Architecture,
    ) -> Result<(), Error> {
        if self.0.template.platform != platform || self.0.template.architecture != architecture {
            Err(Error::InvalidInput)
        } else {
            Ok(())
        }
    }
}
