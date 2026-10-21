//! Telemetry values carried by the current runtime protocol. No storage or authority.
use super::WireError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Numeric interpretation is immutable for a field identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryKind {
    /// Instantaneous numeric observation.
    Gauge,
    /// Nonnegative value since an explicit reset boundary.
    CumulativeCounter,
    /// Nonnegative contribution over an explicit interval.
    DeltaCounter,
    /// Boolean or declared finite string vocabulary.
    State,
}
/// Operations are selected explicitly; missing data is never filled implicitly.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryAggregation {
    /// Minimum numeric reading.
    Min,
    /// Maximum numeric reading.
    Max,
    /// Sum of Gauge readings or Delta contributions.
    Sum,
    /// Number of known readings.
    Count,
    /// Numeric arithmetic mean.
    Mean,
    /// Cumulative increase between compatible boundaries.
    Increase,
    /// Contribution divided by its actual duration.
    Rate,
    /// Finite state intervals.
    Timeline,
    /// State changes.
    Transitions,
    /// Explicitly covered duration.
    Coverage,
}
/// One bounded dimension extracted from a declared object property path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryDimension {
    /// Literal property names relative to each selected item, not executable expressions.
    pub path: Vec<String>,
    /// Closed admitted vocabulary, including numeric dimensions rendered canonically.
    pub values: BTreeSet<String>,
}
/// Product retention policy identity; duration is owned by its immutable policy version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionReference {
    /// Tenant-local policy key.
    pub key: String,
    /// Exact policy revision.
    pub revision: u64,
}
/// A field's optional history capability, validated against the Inventory catalog.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimeSeriesBinding {
    /// Numeric or finite-state interpretation.
    pub kind: TelemetryKind,
    /// Scalar property path; an array root is expanded using the field's stable item key.
    pub value_path: Vec<String>,
    /// Counter start in UTC microseconds, extracted per item for structured counters.
    pub interval_start_path: Option<Vec<String>>,
    /// Closed dimensions. Device/resource/source identities are not arbitrary dimensions.
    pub dimensions: BTreeMap<String, TelemetryDimension>,
    /// Explicit operations permitted for this field.
    pub aggregations: BTreeSet<TelemetryAggregation>,
    /// Versioned product policy, never an asset TTL.
    pub retention: RetentionReference,
    /// Maximum expanded resources per device and field.
    pub max_resources: u32,
}
fn name(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.as_bytes()[0].is_ascii_lowercase()
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn path(v: &[String]) -> bool {
    v.len() <= 6 && v.iter().all(|s| name(s))
}
impl TimeSeriesBinding {
    /// Validate bounded declarations; this does not grant field/source access.
    pub fn validate(&self) -> Result<(), WireError> {
        use TelemetryAggregation as A;
        if !path(&self.value_path)
            || self.interval_start_path.as_ref().is_some_and(|v| {
                v.is_empty()
                    || !path(v)
                    || !matches!(
                        self.kind,
                        TelemetryKind::CumulativeCounter | TelemetryKind::DeltaCounter
                    )
            })
            || self.dimensions.len() > 64
            || self.aggregations.is_empty()
            || !name(&self.retention.key)
            || self.retention.revision == 0
            || self.retention.revision > i64::MAX as u64
            || !(1..=4096).contains(&self.max_resources)
        {
            return Err(WireError::InvalidValue);
        }
        let mut combinations = u64::from(self.max_resources);
        let mut vocabulary_bytes = 0usize;
        for (key, dimension) in &self.dimensions {
            if !name(key)
                || dimension.path.is_empty()
                || !path(&dimension.path)
                || dimension.values.is_empty()
                || dimension.values.len() > 256
            {
                return Err(WireError::InvalidValue);
            }
            combinations = combinations
                .checked_mul(dimension.values.len() as u64)
                .ok_or(WireError::InvalidValue)?;
            for value in &dimension.values {
                if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                    return Err(WireError::InvalidValue);
                }
                vocabulary_bytes += value.len();
            }
        }
        if combinations > 4096 || vocabulary_bytes > 32768 {
            return Err(WireError::InvalidValue);
        }
        if self.aggregations.iter().any(|operation| !match self.kind {
            TelemetryKind::Gauge => {
                matches!(operation, A::Min | A::Max | A::Sum | A::Count | A::Mean)
            }
            TelemetryKind::CumulativeCounter => matches!(operation, A::Increase | A::Rate),
            TelemetryKind::DeltaCounter => matches!(operation, A::Sum | A::Rate),
            TelemetryKind::State => matches!(operation, A::Timeline | A::Transitions | A::Coverage),
        }) {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}

/// One immutable sampling instant. Missing readings remain explicit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryObservation {
    /// Tenant-wide sampling identity; reuse fixes the original configuration and content.
    pub id: uuid::Uuid,
    /// Monotonic producer sequence within the admitted source incarnation.
    pub sequence: u64,
    /// UTC Unix microseconds when sampled, independent of receipt time.
    pub observed_at: i64,
    /// Typed source output. Only configured fields and declared attributes become trusted facts.
    pub values: BTreeMap<super::FieldKey, TelemetryReading>,
}
/// Sampling failures do not invent values or tombstones.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "quality",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TelemetryReading {
    /// Typed producer output; explicit paths select the stored scalar.
    Valid {
        /// Typed collector output.
        value: super::Scalar,
        /// Scalar Counter interval/reset start in UTC microseconds; each field is independent.
        /// Structured counters use their declared per-item path and leave this absent.
        interval_start: Option<i64>,
    },
    /// No observation at this instant.
    Missing {
        /// Known scalar Counter start; never inferred from receipt time.
        interval_start: Option<i64>,
        /// Structured resource keys, finite dimensions and per-item Counter starts.
        /// No value from this context is treated as a valid measurement.
        context: Option<super::Scalar>,
    },
    /// Collection failed at this instant.
    Failed {
        /// Known scalar Counter start; required for historical scalar counters.
        interval_start: Option<i64>,
        /// Same exact identity context as Missing; omitted for dimensionless scalars.
        context: Option<super::Scalar>,
    },
}
/// Batch identity fixes ordered observations and the exact Policy version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryUpload {
    /// Fixed logical upload identity.
    pub batch_id: uuid::Uuid,
    /// Server-authored assignment identity, not an authorization assertion.
    pub policy: uuid::Uuid,
    /// Exact version previously obtained from the authenticated configuration endpoint.
    pub policy_version: uuid::Uuid,
    /// Exact server configuration binding. It fences cached batches across registration changes.
    pub binding: String,
    /// Fixed observation order.
    pub observations: Vec<TelemetryObservation>,
}
impl TelemetryUpload {
    /// Bound structural work before consulting authoritative product configuration.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.binding.len() != 64
            || !self
                .binding
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(WireError::InvalidValue);
        }
        if self.batch_id.is_nil()
            || self.policy.is_nil()
            || self.policy_version.is_nil()
            || self.observations.is_empty()
            || self.observations.len() > 4096
        {
            return Err(WireError::InvalidValue);
        }
        let mut ids = BTreeSet::new();
        for point in &self.observations {
            if point.id.is_nil()
                || !ids.insert(point.id)
                || point.observed_at < 0
                || point.observed_at == i64::MAX
                || point.sequence > i64::MAX as u64
                || point.values.is_empty()
                || point.values.len() > 64
            {
                return Err(WireError::InvalidValue);
            }
            for value in point.values.values() {
                let (interval_start, scalar) = match value {
                    TelemetryReading::Valid {
                        value,
                        interval_start,
                    } => (interval_start, Some(value)),
                    TelemetryReading::Missing {
                        interval_start,
                        context,
                    }
                    | TelemetryReading::Failed {
                        interval_start,
                        context,
                    } => (interval_start, context.as_ref()),
                };
                if interval_start.is_some_and(|t| t < 0 || t > point.observed_at) {
                    return Err(WireError::InvalidValue);
                }
                if let Some(value) = scalar {
                    value.validate()?;
                }
            }
        }
        Ok(())
    }
}
/// Product reception does not assert backend visibility or aggregate freshness.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryReceipt {
    /// Stable logical batch identity.
    pub batch_id: uuid::Uuid,
    /// First durable receipt time in UTC Unix microseconds.
    pub received_at: i64,
    /// Whether the original input was already received.
    pub replayed: bool,
    /// Backend publication state, independent of receipt durability.
    pub delivery: TelemetryDelivery,
}
/// Closed delivery observations. Unknown outcomes must be resolved using the original identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryDelivery {
    /// Persisted product input awaits bounded delivery.
    Pending,
    /// History storage and/or the current-asset inbox confirmed admission.
    /// Current asset projection and query/summary availability remain separate observations.
    Published,
    /// A destination outcome is uncertain.
    Unknown,
    /// Current authorization prevents further delivery.
    Blocked,
}

/// Authenticated configuration for one exact Policy version.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryConfiguration {
    /// Trusted tenant coordinate; compare with the local enrollment before execution.
    pub tenant_id: uuid::Uuid,
    /// Trusted device coordinate.
    pub device_id: String,
    /// Exact active registration incarnation.
    pub registration_id: uuid::Uuid,
    /// Exact registration generation.
    pub generation: u64,
    /// Exact source incarnation for producer sequence ownership.
    pub source_epoch: uuid::Uuid,
    /// Lease issue time in UTC Unix seconds.
    pub issued_at: i64,
    /// Stop starting collection when this signed lease expires; refresh through mTLS.
    pub expires_at: i64,
    /// Current immutable assignment identity.
    pub policy: uuid::Uuid,
    /// Uploads must retain this exact version.
    pub policy_version: uuid::Uuid,
    /// Server-selected source; producer ordering is monotonic within this source incarnation.
    pub source: super::Source,
    /// Echo unchanged in uploads; it conveys no authority without the current mTLS principal.
    pub binding: String,
    /// Exact existing collector template.
    pub template: super::TaskResource,
    /// Exact collector plan and literal execution inputs.
    pub collector: TelemetryCollector,
    /// Catalog definitions frozen at publication.
    pub fields: Vec<super::FieldDefinition>,
    /// Effective cadence at the server's current UTC time.
    pub sample_millis: u32,
    /// Normal cadence to resume when the optional boost expires.
    pub normal_sample_millis: u32,
    /// Absolute UTC seconds; rereading does not extend the boost.
    pub boost_expires_at: Option<i64>,
    /// Upload cadence.
    pub upload_millis: u32,
    /// Maximum complete decompressed request bytes admitted by every destination.
    pub max_bytes: u32,
    /// Maximum expanded points per request.
    pub max_points: u32,
    /// Maximum expanded resources per request.
    pub max_resources: u32,
    /// Maximum execution duration for the referenced collector.
    pub execution_millis: u32,
    /// Maximum collector output bytes.
    pub output_bytes: u32,
    /// Oldest admitted observation age in seconds.
    pub backfill_seconds: u32,
}

/// Independent current-asset processing status for one observation in a durable batch.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryCurrentStatus {
    /// Original batch identity.
    pub batch_id: uuid::Uuid,
    /// Original sampling identity, never generated again during retry.
    pub observation_id: uuid::Uuid,
    /// Current-asset destination and its observed progress.
    pub state: TelemetryCurrentState,
}
/// An inbox receipt does not assert that current assets were changed.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum TelemetryCurrentState {
    /// The profile requested historical storage only.
    NotRequested,
    /// The shared delivery path has not confirmed current-asset admission.
    Pending,
    /// Independently observed decisions from the existing Inventory owner.
    Observed {
        /// Observation ordering and completeness decision.
        observation: super::ObservationStatus,
        /// Independently confirmed Inventory projection state.
        projection: super::ProjectionStatus,
    },
}

/// Collector instructions carried by the existing runtime family.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TelemetryCollector {
    /// Native engine plan and exact output mappings.
    Native {
        /// Exact immutable native engine plan.
        plan: super::NativeCollectionPlan,
        /// Only configured field projections.
        /// Exact configured field projections.
        mappings: BTreeMap<String, TelemetryNativeMapping>,
    },
    /// Immutable script material served by the authenticated configuration content route.
    Script {
        /// Expected immutable script bytes.
        content: super::TaskContent,
        /// Required installed executor; no fallback.
        profile: super::ExecutorProfile,
        /// Literal positional and named arguments.
        arguments: Vec<String>,
        /// Explicit bounded parameter environment.
        environment: BTreeMap<String, String>,
        /// Separate bound SQL parameters for osquery.
        sql_parameters: Option<BTreeMap<String, serde_json::Value>>,
        /// Published self-contained output schema.
        output_schema: serde_json::Value,
        /// Effective execution deadline in seconds.
        timeout_seconds: u32,
        /// Maximum complete output rows.
        max_rows: u16,
        /// Exact configured field projections.
        mappings: BTreeMap<String, TelemetryValueMapping>,
    },
}
/// A native query's output path. Missing/failed queries remain explicit telemetry quality.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryNativeMapping {
    /// Explicit durable per-instance normalization, absent for raw native values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter_normalization: Option<NativeCounterNormalization>,
    /// Stable query identifier from the supplied plan.
    pub query: String,
    /// Explicit projection of that query's result.
    pub mapping: TelemetryValueMapping,
}
/// Closed Agent-owned normalization of native cumulative observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NativeCounterNormalization {
    /// Persist an exact baseline and UTC start for each signed field and native instance.
    LocalCumulativeV1,
}
impl TelemetryNativeMapping {
    /// Validate the signed source and destination of generated per-instance counter starts.
    pub fn validate_counter_normalization(
        &self,
        query: &super::NativeQueryDefinition,
        field: &super::FieldDefinition,
    ) -> Result<(), WireError> {
        use super::{NativeQueryDefinition as Q, PerformanceSection as S, ValueType as T};
        let fail = || WireError::InvalidValue;
        let network = matches!(
            query,
            Q::WindowsPerformance {
                section: S::Network
            } | Q::MacosPerformance {
                section: S::Network
            }
        );
        if self.counter_normalization.is_none() {
            if network
                && field
                    .time_series
                    .as_ref()
                    .is_some_and(|b| b.kind == TelemetryKind::CumulativeCounter)
            {
                return Err(fail());
            }
            return Ok(());
        }
        if !network {
            return Err(fail());
        }
        let binding = field.time_series.as_ref().ok_or_else(fail)?;
        let start = binding.interval_start_path.as_ref().ok_or_else(fail)?;
        let key = field.item_key.as_ref().ok_or_else(fail)?;
        if binding.kind != TelemetryKind::CumulativeCounter
            || binding.value_path.len() != 1
            || start.len() != 1
            || start == &binding.value_path
            || &start[0] == key
        {
            return Err(fail());
        }
        let T::Array { items, .. } = &field.value_type else {
            return Err(fail());
        };
        let T::Object { properties } = items.as_ref() else {
            return Err(fail());
        };
        if !matches!(properties.get(&start[0]), Some(T::Integer))
            || !matches!(properties.get(&binding.value_path[0]), Some(T::Integer))
        {
            return Err(fail());
        }
        let m = &self.mapping;
        if !m.pointer.is_empty()
            || m.conversion != TelemetryConversion::Identity
            || m.columns.contains_key(&start[0])
            || m.columns.len() + 1 != properties.len()
            || !m.columns.keys().all(|k| properties.contains_key(k))
        {
            return Err(fail());
        }
        let identity = |name: &str, pointers: &[&str]| {
            m.columns.get(name).is_some_and(|c| {
                c.columns.is_empty()
                    && c.conversion == TelemetryConversion::Identity
                    && pointers.contains(&c.pointer.as_str())
            })
        };
        if !identity(key, &["/id"])
            || !m.columns.get(&binding.value_path[0]).is_some_and(|c| {
                c.columns.is_empty()
                    && c.conversion == TelemetryConversion::Integer
                    && ["/received_bytes", "/sent_bytes"].contains(&c.pointer.as_str())
            })
        {
            return Err(fail());
        }
        Ok(())
    }
}
/// Closed conversions; unknown native codes never become a successful default value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TelemetryConversion {
    /// Preserve the native JSON type, including explicit null.
    Identity,
    /// Convert a fully specified CIM datetime with explicit offset to UTC Unix seconds.
    CimTime,
    /// Parse an exact decimal integer string.
    Integer,
    /// Parse a finite JSON number or decimal number string.
    Number,
    /// Explicit source code to canonical scalar, including boolean values.
    Enum {
        /// Finite exact source tokens. Unknown tokens are invalid.
        values: BTreeMap<String, serde_json::Value>,
    },
    /// Interpret membership in a complete integer array; never treat a numeric bitmask as a set.
    ArrayMember {
        /// Exact native enum member.
        member: i64,
        /// Value when present in the complete set.
        present: serde_json::Value,
        /// Value when absent from the complete set.
        absent: serde_json::Value,
    },
    /// Convert nonnegative integral units using checked exact rational arithmetic.
    Scale {
        /// Numerator.
        numerator: u64,
        /// Nonzero denominator; fractional output is rejected.
        denominator: u64,
    },
    /// Decode a finite nonnegative bitmask to a sorted list of declared flag names.
    Bitmask {
        /// Keys are decimal single-bit masks. Undeclared set bits are invalid.
        flags: BTreeMap<String, String>,
    },
}
/// Extraction relative to a response or list item. Empty pointer selects the whole value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryValueMapping {
    /// RFC 6901 pointer, never an expression.
    pub pointer: String,
    /// TelemetryConversion of a direct scalar; structured projections require identity.
    pub conversion: TelemetryConversion,
    /// Exact output properties for each array item. No undeclared attributes are copied.
    pub columns: BTreeMap<String, TelemetryValueMapping>,
}

/// Complete bounded assignment directory. A capacity failure never returns a partial list.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryDirectory {
    /// Only currently authorized assignments; an empty list withdraws earlier assignments.
    pub assignments: Vec<TelemetryAssignment>,
}
/// One exact authorized assignment and its endpoint capability result.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetryAssignment {
    /// Assigned policy identity.
    pub policy: uuid::Uuid,
    /// Exact current immutable version.
    pub version: uuid::Uuid,
    /// False means this endpoint must not execute or downgrade this assignment.
    pub supported: bool,
}

/// Current signing authority authenticates the complete periodic configuration lease.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedTelemetryConfiguration {
    /// Exact immutable configuration and trusted destination coordinates.
    pub configuration: TelemetryConfiguration,
    /// Key from the acknowledged task-trust set; never an inline untrusted public key.
    pub key_id: String,
    /// Ed25519 signature using unpadded URL-safe Base64.
    pub signature: String,
}
impl TelemetryConfiguration {
    /// Canonical bytes in a distinct runtime signing domain. Verification and local time are caller-owned.
    pub fn signing_bytes(&self, key_id: &str) -> Result<Vec<u8>, WireError> {
        if self.tenant_id.is_nil()
            || self.registration_id.is_nil()
            || self.source_epoch.is_nil()
            || self.generation == 0
            || self.device_id.is_empty()
            || self.device_id.len() > 1024
            || self.device_id.chars().any(char::is_control)
            || self.issued_at < 0
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > 300
            || self.policy.is_nil()
            || self.policy_version.is_nil()
            || self.binding.len() != 64
            || !self
                .binding
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.fields.is_empty()
            || self.fields.len() > 64
            || self.sample_millis == 0
            || self.normal_sample_millis == 0
            || self.upload_millis < self.normal_sample_millis
            || self.execution_millis == 0
            || self.execution_millis > 300_000
            || self.execution_millis > self.sample_millis
            || !(1..=4 * 1024 * 1024).contains(&self.max_bytes)
            || !(1..=4096).contains(&self.max_points)
            || !(1..=4096).contains(&self.max_resources)
            || self.output_bytes == 0
            || self.output_bytes > self.max_bytes
            || self.backfill_seconds == 0
            || !matches!(
                self.source,
                super::Source::AgentNative
                    | super::Source::AgentScript
                    | super::Source::AgentOsquery
            )
            || key_id.is_empty()
            || key_id.len() > 128
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(WireError::InvalidValue);
        }
        let collector_matches = match &self.collector {
            TelemetryCollector::Native { .. } => self.source == super::Source::AgentNative,
            TelemetryCollector::Script { profile, .. } => match profile {
                super::ExecutorProfile::Osquery => self.source == super::Source::AgentOsquery,
                _ => self.source == super::Source::AgentScript,
            },
        };
        if !collector_matches {
            return Err(WireError::InvalidValue);
        }
        let mut keys = BTreeSet::new();
        for field in &self.fields {
            field.validate()?;
            if !keys.insert(field.key) || !field.sources.contains_key(&self.source) {
                return Err(WireError::InvalidValue);
            }
        }
        if let TelemetryCollector::Native { plan, mappings } = &self.collector {
            for (key, mapping) in mappings {
                let field = self
                    .fields
                    .iter()
                    .find(|f| f.key.as_str() == key)
                    .ok_or(WireError::InvalidValue)?;
                let query = plan
                    .spec()
                    .queries
                    .get(&mapping.query)
                    .ok_or(WireError::InvalidValue)?;
                mapping.validate_counter_normalization(&query.definition, field)?;
            }
        }
        let mut bytes = b"rss-mdm-agent-telemetry-configuration-v1-ed25519\0".to_vec();
        bytes.extend((key_id.len() as u32).to_be_bytes());
        bytes.extend(key_id.as_bytes());
        bytes.extend(serde_json::to_vec(self).map_err(|_| WireError::InvalidValue)?);
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(WireError::InvalidValue);
        }
        Ok(bytes)
    }
}
