#![deny(missing_docs)]
//! Strict Agent protocol values for RSS MDM.
//!
//! This package owns JSON values only. Device authority, persistence and HTTP authentication
//! remain product responsibilities. V1 is deliberately closed: extensions require a new wire
//! version rather than an implicit compatibility path.

use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Exact supported wire major.
pub const WIRE_VERSION: u8 = 1;
/// Maximum complete JSON request accepted by the product adapter.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// Closed validation failure without retaining input values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// A value is malformed or outside the V1 profile.
    InvalidValue,
}
impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid Agent wire value")
    }
}
impl std::error::Error for WireError {}

/// Canonical 256-bit base64url secret. Debug output is always redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);
impl Secret {
    /// Parse exactly 32 bytes encoded with unpadded URL-safe base64.
    pub fn parse(value: &str) -> Result<Self, WireError> {
        if value.len() != 43
            || !base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(value)
                .is_ok_and(|bytes| bytes.len() == 32)
        {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(Zeroizing::new(value.to_owned())))
    }
    /// Expose the secret only to the credential verifier or encoder.
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.expose())
    }
}
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Zeroizing::new(String::deserialize(deserializer)?);
        Self::parse(&value).map_err(D::Error::custom)
    }
}

/// Closed V1 capability set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    /// Full/partial/failed reports for the two basic inventory fields.
    #[serde(rename = "inventory.basic.v1")]
    InventoryBasicV1,
}

/// Agent registration request. Tenant, device and generation are never device claims.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRequest {
    wire_version: u8,
    operation_id: Uuid,
    enrollment_id: Uuid,
    password: Secret,
    credential: Secret,
    capabilities: Vec<Capability>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRegistrationRequest {
    wire_version: u8,
    operation_id: Uuid,
    enrollment_id: Uuid,
    password: Secret,
    credential: Secret,
    capabilities: Vec<Capability>,
}
impl<'de> Deserialize<'de> for RegistrationRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawRegistrationRequest::deserialize(deserializer)?;
        if raw.wire_version != WIRE_VERSION || raw.capabilities != [Capability::InventoryBasicV1] {
            return Err(D::Error::custom(WireError::InvalidValue));
        }
        Self::new(
            raw.operation_id,
            raw.enrollment_id,
            raw.password,
            raw.credential,
        )
        .map_err(D::Error::custom)
    }
}
impl RegistrationRequest {
    /// Construct the only V1 registration shape and inject its fixed version and capability.
    pub fn new(
        operation_id: Uuid,
        enrollment_id: Uuid,
        password: Secret,
        credential: Secret,
    ) -> Result<Self, WireError> {
        if operation_id.is_nil() || enrollment_id.is_nil() {
            return Err(WireError::InvalidValue);
        }
        Ok(Self {
            wire_version: WIRE_VERSION,
            operation_id,
            enrollment_id,
            password,
            credential,
            capabilities: vec![Capability::InventoryBasicV1],
        })
    }
    /// Stable retry identity selected by the Agent.
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }
    /// One-time enrollment identity issued by an administrator.
    pub const fn enrollment_id(&self) -> Uuid {
        self.enrollment_id
    }
    /// One-time bootstrap secret.
    pub const fn password(&self) -> &Secret {
        &self.password
    }
    /// Agent-generated long-term device credential.
    pub const fn credential(&self) -> &Secret {
        &self.credential
    }
    /// Exact requested capabilities.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }
}

/// Server-owned report source returned after registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportSource {
    /// Built-in RSS Agent inventory collector.
    #[serde(rename = "agent.builtin")]
    AgentBuiltin,
}

/// Durable registration result. It never contains the submitted credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    /// Exact wire major.
    pub wire_version: u8,
    /// Registration operation replay identity.
    pub operation_id: Uuid,
    /// Server-owned product device identity.
    pub device_id: String,
    /// Immutable registration identity.
    pub registration_id: Uuid,
    /// Channel-local registration generation.
    pub generation: u64,
    /// Authorized report source.
    pub source: ReportSource,
    /// Observation epoch for this registration.
    pub epoch: Uuid,
    /// Exact accepted capability set.
    pub capabilities: Vec<Capability>,
}

/// Closed basic inventory field set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Field {
    /// Device model.
    #[serde(rename = "device.model")]
    Model,
    /// Operating-system version.
    #[serde(rename = "device.os.version")]
    OsVersion,
}

/// One supported collection outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum CollectedValue {
    /// Valid nonblank text of at most 256 Unicode scalar values.
    Known(String),
    /// The collector explicitly cannot produce the field.
    Unsupported,
}

/// One field and its explicit outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldValue {
    /// Field identity.
    pub field: Field,
    /// Collected outcome.
    pub value: CollectedValue,
}

/// Closed collection failure categories; raw diagnostics are never transported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FailureCode {
    /// Collector lacked operating-system permission.
    PermissionDenied,
    /// A retryable dependency was unavailable.
    TemporarilyUnavailable,
    /// Collection failed without a more specific safe category.
    CollectionFailed,
}

/// Closed V1 report body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportBody {
    /// Complete coverage. Omitted fields are absent from this source.
    Snapshot(Vec<FieldValue>),
    /// Incomplete evidence retained without projection.
    Partial(Vec<FieldValue>),
    /// Whole-collection failure retained without projection.
    Failed {
        /// Safe failure category.
        code: FailureCode,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum RawReportBody {
    Snapshot { values: Vec<FieldValue> },
    Partial { values: Vec<FieldValue> },
    Failed { code: FailureCode },
}
impl From<&ReportBody> for RawReportBody {
    fn from(value: &ReportBody) -> Self {
        match value {
            ReportBody::Snapshot(values) => Self::Snapshot {
                values: values.clone(),
            },
            ReportBody::Partial(values) => Self::Partial {
                values: values.clone(),
            },
            ReportBody::Failed { code } => Self::Failed { code: *code },
        }
    }
}
impl From<RawReportBody> for ReportBody {
    fn from(value: RawReportBody) -> Self {
        match value {
            RawReportBody::Snapshot { values } => Self::Snapshot(values),
            RawReportBody::Partial { values } => Self::Partial(values),
            RawReportBody::Failed { code } => Self::Failed { code },
        }
    }
}
impl Serialize for ReportBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        RawReportBody::from(self).serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for ReportBody {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(RawReportBody::deserialize(deserializer)?.into())
    }
}

/// Strict V1 inventory report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRequest {
    wire_version: u8,
    report_id: Uuid,
    sequence: u64,
    observed_at: i64,
    body: ReportBody,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawReportRequest {
    wire_version: u8,
    report_id: Uuid,
    sequence: u64,
    observed_at: i64,
    body: ReportBody,
}
impl<'de> Deserialize<'de> for ReportRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawReportRequest::deserialize(deserializer)?;
        if raw.wire_version != WIRE_VERSION {
            return Err(D::Error::custom(WireError::InvalidValue));
        }
        Self::new(raw.report_id, raw.sequence, raw.observed_at, raw.body).map_err(D::Error::custom)
    }
}
impl ReportRequest {
    /// Construct and canonicalize one strict V1 report.
    pub fn new(
        report_id: Uuid,
        sequence: u64,
        observed_at: i64,
        mut body: ReportBody,
    ) -> Result<Self, WireError> {
        if report_id.is_nil() || sequence > i64::MAX as u64 || observed_at < 0 {
            return Err(WireError::InvalidValue);
        }
        let values = match &mut body {
            ReportBody::Snapshot(values) | ReportBody::Partial(values) => values,
            ReportBody::Failed { .. } => {
                return Ok(Self {
                    wire_version: WIRE_VERSION,
                    report_id,
                    sequence,
                    observed_at,
                    body,
                });
            }
        };
        if values.len() > 2 || values.iter().any(|value| !Self::valid_value(value)) {
            return Err(WireError::InvalidValue);
        }
        values.sort_by_key(|value| value.field);
        if values.windows(2).any(|pair| pair[0].field == pair[1].field) {
            return Err(WireError::InvalidValue);
        }
        Ok(Self {
            wire_version: WIRE_VERSION,
            report_id,
            sequence,
            observed_at,
            body,
        })
    }
    fn valid_value(value: &FieldValue) -> bool {
        match &value.value {
            CollectedValue::Known(text) => {
                !text.trim().is_empty()
                    && text.chars().count() <= 256
                    && !text.chars().any(char::is_control)
            }
            CollectedValue::Unsupported => true,
        }
    }
    /// Immutable report identity within the authenticated registration.
    pub const fn report_id(&self) -> Uuid {
        self.report_id
    }
    /// Producer-local ordering coordinate.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Nonnegative Unix collection time.
    pub const fn observed_at(&self) -> i64 {
        self.observed_at
    }
    /// Exact closed body.
    pub const fn body(&self) -> &ReportBody {
        &self.body
    }
    /// Collected values, or an empty slice for a failed report.
    pub fn values(&self) -> &[FieldValue] {
        match &self.body {
            ReportBody::Snapshot(values) | ReportBody::Partial(values) => values,
            ReportBody::Failed { .. } => &[],
        }
    }
    /// Canonical semantic JSON used for durable duplicate detection.
    pub fn canonical(&self) -> Result<Vec<u8>, WireError> {
        let bytes = serde_json::to_vec(self).map_err(|_| WireError::InvalidValue)?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(WireError::InvalidValue);
        }
        Ok(bytes)
    }
}

/// Durable intake stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IntakeStatus {
    /// The sealed report and receipt committed to PostgreSQL.
    Durable,
}
/// Immutable durable-intake acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportAck {
    /// Exact wire major.
    pub wire_version: u8,
    /// Report identity.
    pub report_id: Uuid,
    /// Authoritative server receipt time as Unix seconds.
    pub received_at: i64,
    /// Durable intake status.
    pub intake: IntakeStatus,
}
/// Observation processing status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ObservationStatus {
    /// Awaiting the Observation worker.
    Pending,
    /// A complete snapshot established the current baseline.
    Snapshot,
    /// A partial report requires another complete snapshot.
    NeedSnapshotPartial,
    /// A collection failure requires another complete snapshot.
    NeedSnapshotCollectionFailed,
    /// The sequence did not exceed the stream high-water mark.
    Stale,
}
/// Projection processing status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProjectionStatus {
    /// Awaiting an applicable Observation decision or projection commit.
    Pending,
    /// Applicable facts committed to the asset projection.
    Applied,
    /// The Observation decision deliberately carries no projectable facts.
    NotApplicable,
}
/// Current processing status for one durably accepted report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportStatus {
    /// Immutable intake acknowledgement.
    pub ack: ReportAck,
    /// Observation decision stage.
    pub observation: ObservationStatus,
    /// Projection stage.
    pub projection: ProjectionStatus,
}

/// Closed Agent HTTP error codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// JSON or field validation failed.
    MalformedRequest,
    /// The wire major is unsupported.
    UnsupportedWire,
    /// The exact capability profile is unsupported.
    UnsupportedCapability,
    /// Bootstrap or long-term device identity was rejected.
    InvalidIdentity,
    /// A referenced durable report does not exist for this principal.
    ReportNotFound,
    /// An idempotent identity was reused with different semantic content.
    OperationConflict,
    /// Commit outcome is unknown; retry the exact request.
    OperationUnknown,
    /// A required service is temporarily unavailable.
    ServiceUnavailable,
}
/// Stable JSON error body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    /// Closed machine-readable code.
    pub code: ErrorCode,
}
