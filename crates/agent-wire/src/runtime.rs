#![deny(missing_docs)]
//! Strict Agent protocol values for RSS MDM.
//!
//! This package owns JSON values only. Device authority, persistence and HTTP authentication
//! remain product responsibilities. V1 binds script and software tasks to one strict major.

#[path = "device_access.rs"]
mod device_access;
pub use device_access::*;

#[path = "unmanage.rs"]
mod unmanage;
pub use unmanage::*;
#[path = "onboarding.rs"]
mod onboarding;
pub use onboarding::*;
#[path = "native_collection.rs"]
mod native_collection;
#[path = "tasks.rs"]
mod tasks;
pub use crate::self_service::*;
pub use native_collection::*;
pub use tasks::*;
#[path = "recovery_credentials.rs"]
mod recovery_credentials;
pub use recovery_credentials::*;

#[path = "telemetry.rs"]
mod telemetry;
pub use telemetry::*;
#[path = "telemetry_gap.rs"]
mod telemetry_gap;
pub use telemetry_gap::*;

#[path = "current_user.rs"]
mod current_user;
pub use current_user::*;

use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Independent runtime HTTP API version.
pub const API_VERSION: u8 = 1;
/// Exact supported wire major.
pub const WIRE_VERSION: u8 = 1;
/// Maximum complete JSON request accepted by the product adapter.
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
/// Canonical manifest for every public Agent V1 JSON shape.
pub const SCHEMA_MANIFEST: &str = include_str!("../schema/runtime/agent-v1.schema-manifest.json");
/// SHA-256 of the ordered schema payloads named by [`SCHEMA_MANIFEST`].
pub const SCHEMA_FINGERPRINT: &str =
    "d04bc4339bf12c7b93e72255acc369a5f1b01534132fbd62a847ee7f91f288c0";

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

pub(crate) mod strict_uuid {
    use super::*;

    pub fn serialize<S: Serializer>(value: &Uuid, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.hyphenated().to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Uuid, D::Error> {
        let value = String::deserialize(deserializer)?;
        let bytes = value.as_bytes();
        let lexical = bytes.len() == 36
            && bytes.iter().enumerate().all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => *byte == b'-',
                _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
            });
        lexical
            .then(|| Uuid::parse_str(&value).ok())
            .flatten()
            .filter(|uuid| !uuid.is_nil())
            .ok_or_else(|| D::Error::custom(WireError::InvalidValue))
    }
}

/// Canonical 256-bit base64url secret. Debug output is always redacted.
#[derive(Clone, PartialEq, Eq, schemars::JsonSchema)]
#[schemars(with = "String", extend("minLength" = 43, "maxLength" = 43, "pattern" = "^[A-Za-z0-9_-]{43}$"))]
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
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub enum Capability {
    /// Full/partial/failed reports for the two basic inventory fields.
    #[serde(rename = "inventory.collect.v1")]
    InventoryCollectionV1,
    /// Receive and execute signed task offers.
    #[serde(rename = "task.execute.v1")]
    TaskExecuteV1,
    /// Execute the exact software.msi.system.v1 profile.
    #[serde(rename = "software.msi.system.v1")]
    SoftwareMsiSystemV1,
    /// Execute the exact software.msi.user.v1 profile.
    #[serde(rename = "software.msi.user.v1")]
    SoftwareMsiUserV1,
    /// Execute the exact software.pkg.system.v1 profile.
    #[serde(rename = "software.pkg.system.v1")]
    SoftwarePkgSystemV1,
    /// Execute the exact software.bundle.windows.system.v1 profile.
    #[serde(rename = "software.bundle.windows.system.v1")]
    SoftwareBundleWindowsSystemV1,
    /// Execute the exact software.bundle.windows.user.v1 profile.
    #[serde(rename = "software.bundle.windows.user.v1")]
    SoftwareBundleWindowsUserV1,
    /// Execute the exact software.bundle.macos.system.v1 profile.
    #[serde(rename = "software.bundle.macos.system.v1")]
    SoftwareBundleMacosSystemV1,
    /// Execute the exact software.bundle.macos.user.v1 profile.
    #[serde(rename = "software.bundle.macos.user.v1")]
    SoftwareBundleMacosUserV1,
    /// Execute the exact software.winget.system.v1 profile.
    #[serde(rename = "software.winget.system.v1")]
    SoftwareWingetSystemV1,
    /// Execute the exact software.winget.user.v1 profile.
    #[serde(rename = "software.winget.user.v1")]
    SoftwareWingetUserV1,
    /// Execute the exact software.brew.bottle.user.v1 profile.
    #[serde(rename = "software.brew.bottle.user.v1")]
    SoftwareBrewBottleUserV1,
    /// Execute the exact software.exe.system.v1 profile.
    #[serde(rename = "software.exe.system.v1")]
    SoftwareExeSystemV1,
    /// Execute the exact software.exe.user.v1 profile.
    #[serde(rename = "software.exe.user.v1")]
    SoftwareExeUserV1,
    /// Execute the exact software.dmg.app.system.v1 profile.
    #[serde(rename = "software.dmg.app.system.v1")]
    SoftwareDmgAppSystemV1,
    /// Execute the exact software.dmg.app.user.v1 profile.
    #[serde(rename = "software.dmg.app.user.v1")]
    SoftwareDmgAppUserV1,
    /// Execute the exact software.dmg.pkg.system.v1 profile.
    #[serde(rename = "software.dmg.pkg.system.v1")]
    SoftwareDmgPkgSystemV1,
    /// Execute the exact software.msix.registration.user.v1 profile.
    #[serde(rename = "software.msix.registration.user.v1")]
    SoftwareMsixRegistrationUserV1,
    /// Execute the exact software.msix.provisioning.system.v1 profile.
    #[serde(rename = "software.msix.provisioning.system.v1")]
    SoftwareMsixProvisioningSystemV1,
    /// Open the standard MDM enrollment entry with OS/user approval.
    #[serde(rename = "mdm.enrollment.v1")]
    MdmEnrollmentV1,
    /// Administrator-authorized Agent retirement.
    #[serde(rename = "device.unmanage.v1")]
    DeviceUnmanageV1,
    /// Execute signed declarative native inventory tasks.
    #[serde(rename = "inventory.native.v1")]
    InventoryNativeV1,
    /// Native Windows recovery material execution and encrypted escrow.
    #[serde(rename = "credentials.windows.v1")]
    CredentialsWindowsV1,
    /// Periodic typed observations using published telemetry profiles.
    #[serde(rename = "telemetry.collect.v1")]
    TelemetryCollectV1,
    /// Durable local baselines for explicitly signed native cumulative counters.
    #[serde(rename = "telemetry.counter.local.v1")]
    TelemetryCounterLocalV1,
    /// Typed local-account Device Access operations.
    #[serde(rename = "device_access.v1")]
    DeviceAccessV1,
}
impl Capability {
    /// Software support always refers to one concrete native/script scope profile.
    pub fn is_software(self) -> bool {
        !matches!(
            self,
            Self::DeviceAccessV1
                | Self::InventoryCollectionV1
                | Self::TaskExecuteV1
                | Self::MdmEnrollmentV1
                | Self::DeviceUnmanageV1
                | Self::InventoryNativeV1
                | Self::CredentialsWindowsV1
                | Self::TelemetryCollectV1
                | Self::TelemetryCounterLocalV1
        )
    }
    /// Canonical persisted and queryable capability identity.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InventoryCollectionV1 => "inventory.collect.v1",
            Self::TaskExecuteV1 => "task.execute.v1",
            Self::SoftwareMsiSystemV1 => "software.msi.system.v1",
            Self::SoftwareMsiUserV1 => "software.msi.user.v1",
            Self::SoftwarePkgSystemV1 => "software.pkg.system.v1",
            Self::SoftwareBundleWindowsSystemV1 => "software.bundle.windows.system.v1",
            Self::SoftwareBundleWindowsUserV1 => "software.bundle.windows.user.v1",
            Self::SoftwareBundleMacosSystemV1 => "software.bundle.macos.system.v1",
            Self::SoftwareBundleMacosUserV1 => "software.bundle.macos.user.v1",
            Self::SoftwareWingetSystemV1 => "software.winget.system.v1",
            Self::SoftwareWingetUserV1 => "software.winget.user.v1",
            Self::SoftwareBrewBottleUserV1 => "software.brew.bottle.user.v1",
            Self::SoftwareExeSystemV1 => "software.exe.system.v1",
            Self::SoftwareExeUserV1 => "software.exe.user.v1",
            Self::SoftwareDmgAppSystemV1 => "software.dmg.app.system.v1",
            Self::SoftwareDmgAppUserV1 => "software.dmg.app.user.v1",
            Self::SoftwareDmgPkgSystemV1 => "software.dmg.pkg.system.v1",
            Self::SoftwareMsixRegistrationUserV1 => "software.msix.registration.user.v1",
            Self::SoftwareMsixProvisioningSystemV1 => "software.msix.provisioning.system.v1",
            Self::MdmEnrollmentV1 => "mdm.enrollment.v1",
            Self::DeviceUnmanageV1 => "device.unmanage.v1",
            Self::InventoryNativeV1 => "inventory.native.v1",
            Self::DeviceAccessV1 => "device_access.v1",
            Self::CredentialsWindowsV1 => "credentials.windows.v1",
            Self::TelemetryCollectV1 => "telemetry.collect.v1",
            Self::TelemetryCounterLocalV1 => "telemetry.counter.local.v1",
        }
    }
}
/// The only supported ordered capability sets for Agent V1.
pub fn supported_capabilities(value: &[Capability]) -> bool {
    value.first() == Some(&Capability::InventoryCollectionV1)
        && value.len() <= 26
        && value.windows(2).all(|pair| pair[0] < pair[1])
}

/// Server-owned report source returned after registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum ReportSource {
    /// Built-in RSS Agent inventory collector.
    #[serde(rename = "agent.builtin")]
    AgentBuiltin,
}

/// Durable registration result. It never contains the submitted credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingProfile {
    /// Exact wire major.
    #[schemars(schema_with = "crate::runtime::version_schema")]
    #[serde(deserialize_with = "tasks::version")]
    pub wire_version: u8,
    /// Registration operation replay identity.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub operation_id: Uuid,
    /// Server-owned product device identity.
    #[schemars(extend("minLength" = 1, "maxLength" = 256, "pattern" = "^(?=.*\\S)[^\\u0000-\\u001F\\u007F-\\u009F]*$"))]
    #[serde(deserialize_with = "profile_device")]
    pub device_id: String,
    /// Immutable registration identity.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub registration_id: Uuid,
    /// Channel-local registration generation.
    #[schemars(extend("minimum" = 1, "maximum" = 9223372036854775807u64))]
    #[serde(deserialize_with = "profile_generation")]
    pub generation: u64,
    /// Authorized report source.
    #[schemars(extend("const" = "agent.builtin"))]
    pub source: ReportSource,
    /// Observation epoch for this registration.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub epoch: Uuid,
    /// Exact accepted capability set.
    #[schemars(extend("minItems" = 1, "maxItems" = 22, "uniqueItems" = true))]
    #[serde(deserialize_with = "profile_capabilities")]
    pub capabilities: Vec<Capability>,
    /// Server-selected built-in collector versions for this registration.
    #[schemars(extend("minItems" = 1, "maxItems" = 16))]
    #[serde(deserialize_with = "profile_collections")]
    pub collections: Vec<CollectionDefinition>,
}

/// One field and its explicit outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldValue {
    /// Field identity.
    pub field: FieldKey,
    /// Collected outcome.
    pub value: CollectedValue,
}

/// Closed collection failure categories; raw diagnostics are never transported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Clone, Debug, PartialEq, Eq, schemars::JsonSchema)]
#[schemars(with = "RawReportBody")]
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
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum RawReportBody {
    Snapshot {
        #[schemars(extend("maxItems" = 128))]
        values: Vec<FieldValue>,
    },
    Partial {
        #[schemars(extend("maxItems" = 128))]
        values: Vec<FieldValue>,
    },
    Failed {
        code: FailureCode,
    },
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "ReportInput", into = "ReportInput")]
pub struct ReportRequest(ReportInput);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportInput {
    #[schemars(schema_with = "crate::runtime::version_schema")]
    wire_version: u8,
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    report_id: Uuid,
    #[schemars(extend("minimum" = 0, "maximum" = 9223372036854775807u64))]
    sequence: u64,
    #[schemars(extend("minimum" = 0, "maximum" = 9223372036854775807u64))]
    observed_at: i64,
    collection: CollectionDefinition,
    body: ReportBody,
}
impl From<ReportRequest> for ReportInput {
    fn from(value: ReportRequest) -> Self {
        value.0
    }
}
impl TryFrom<ReportInput> for ReportRequest {
    type Error = WireError;
    fn try_from(raw: ReportInput) -> Result<Self, WireError> {
        if raw.wire_version != WIRE_VERSION {
            return Err(WireError::InvalidValue);
        }
        Self::new(
            raw.report_id,
            raw.sequence,
            raw.observed_at,
            raw.collection,
            raw.body,
        )
    }
}
impl ReportRequest {
    /// Construct and canonicalize one strict V1 report.
    pub fn new(
        report_id: Uuid,
        sequence: u64,
        observed_at: i64,
        collection: CollectionDefinition,
        mut body: ReportBody,
    ) -> Result<Self, WireError> {
        if report_id.is_nil() || sequence > i64::MAX as u64 || observed_at < 0 {
            return Err(WireError::InvalidValue);
        }
        let values = match &mut body {
            ReportBody::Snapshot(values) | ReportBody::Partial(values) => values,
            ReportBody::Failed { .. } => {
                return Ok(Self(ReportInput {
                    wire_version: WIRE_VERSION,
                    report_id,
                    sequence,
                    observed_at,
                    collection,
                    body,
                }));
            }
        };
        if values.len() > 128
            || values
                .iter()
                .any(|value| match collection.field(value.field) {
                    Ok(field) => value.value.project(field).is_err(),
                    Err(_) => {
                        matches!(&value.value, CollectedValue::Value(v) if v.validate().is_err())
                    }
                })
        {
            return Err(WireError::InvalidValue);
        }
        values.sort_by_key(|value| value.field);
        if values.windows(2).any(|pair| pair[0].field == pair[1].field) {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(ReportInput {
            wire_version: WIRE_VERSION,
            report_id,
            sequence,
            observed_at,
            collection,
            body,
        }))
    }
    /// Frozen collector identity and field schemas, checked against the server's published version.
    pub fn collection(&self) -> &CollectionDefinition {
        &self.0.collection
    }
    /// Immutable report identity within the authenticated registration.
    pub const fn report_id(&self) -> Uuid {
        self.0.report_id
    }
    /// Producer-local ordering coordinate.
    pub const fn sequence(&self) -> u64 {
        self.0.sequence
    }
    /// Nonnegative Unix collection time.
    pub const fn observed_at(&self) -> i64 {
        self.0.observed_at
    }
    /// Exact closed body.
    pub const fn body(&self) -> &ReportBody {
        &self.0.body
    }
    /// Collected values, or an empty slice for a failed report.
    pub fn values(&self) -> &[FieldValue] {
        match &self.0.body {
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum IntakeStatus {
    /// The sealed report and receipt committed to PostgreSQL.
    Durable,
}
/// Immutable durable-intake acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportAck {
    /// Exact wire major.
    #[schemars(schema_with = "crate::runtime::version_schema")]
    #[serde(deserialize_with = "tasks::version")]
    pub wire_version: u8,
    /// Report identity.
    #[serde(with = "strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub report_id: Uuid,
    /// Authoritative server receipt time as Unix seconds.
    #[schemars(extend("minimum" = 0, "maximum" = 9223372036854775807u64))]
    #[serde(deserialize_with = "nonnegative_time")]
    pub received_at: i64,
    /// Durable intake status.
    #[schemars(extend("const" = "durable"))]
    pub intake: IntakeStatus,
}

/// Observation processing status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The active device certificate has been revoked.
    CredentialRevoked,
    /// The device certificate has expired on this request.
    CertificateExpired,
    /// A newer certificate supersedes this device certificate.
    CredentialRetired,
    /// A referenced durable report does not exist for this principal.
    ReportNotFound,
    /// The current task authorization was withdrawn or does not cover the operation.
    PermissionDenied,
    /// No task is visible at the supplied identity.
    TaskNotFound,
    /// The requested single byte range cannot be served.
    RangeNotSatisfiable,
    /// An idempotent identity was reused with different semantic content.
    OperationConflict,
    /// Commit outcome is unknown; retry the exact request.
    OperationUnknown,
    /// A required service is temporarily unavailable.
    ServiceUnavailable,
}
/// Stable JSON error body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    /// Closed machine-readable code.
    pub code: ErrorCode,
}

/// Shared field and frozen collector contracts owned by Inventory.
#[path = "collection.rs"]
mod collection;
pub use collection::{
    CollectedValue, CollectionDefinition, FieldDefinition, FieldKey, Kind, Platform, Property,
    Scalar, Sensitivity, Source, ValueType,
};

#[path = "chunks.rs"]
mod chunks;
pub use chunks::{
    ChunkedTaskResult, OUTPUT_CHUNK_BYTES, OUTPUT_MAX_BYTES, OutputChunk, OutputManifest,
};

// Canonical lexical constraints shared by every current wire coordinate.
pub(crate) fn uuid_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type":"string","format":"uuid","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","not":{"const":"00000000-0000-0000-0000-000000000000"}})
}
pub(crate) fn nullable_uuid_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"anyOf":[uuid_schema(generator),{"type":"null"}]})
}
pub(crate) fn version_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"const":WIRE_VERSION})
}

pub(crate) fn nonzero_digest_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let mut schema = generator.subschema_for::<[u8; 32]>();
    schema.insert("not".into(), serde_json::json!({"const": ([0u8; 32])}));
    schema
}

fn profile_device<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let value = String::deserialize(d)?;
    if value.trim().is_empty() || value.chars().count() > 256 || value.chars().any(char::is_control)
    {
        return Err(D::Error::custom(WireError::InvalidValue));
    }
    Ok(value)
}
fn profile_generation<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let value = u64::deserialize(d)?;
    if value == 0 || value > i64::MAX as u64 {
        return Err(D::Error::custom(WireError::InvalidValue));
    }
    Ok(value)
}
fn profile_capabilities<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Capability>, D::Error> {
    let value = Vec::deserialize(d)?;
    if !supported_capabilities(&value) {
        return Err(D::Error::custom(WireError::InvalidValue));
    }
    Ok(value)
}
fn profile_collections<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<CollectionDefinition>, D::Error> {
    let value = Vec::<CollectionDefinition>::deserialize(d)?;
    if value.is_empty()
        || value.len() > 16
        || value.iter().any(|v| v.source() != Source::AgentBuiltin)
        || value
            .iter()
            .map(|v| v.dataset())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != value.len()
    {
        return Err(D::Error::custom(WireError::InvalidValue));
    }
    Ok(value)
}
fn nonnegative_time<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    let value = i64::deserialize(d)?;
    if value < 0 {
        return Err(D::Error::custom(WireError::InvalidValue));
    }
    Ok(value)
}
