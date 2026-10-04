#![deny(missing_docs)]
//! Strict Agent protocol values for RSS MDM.
//!
//! This package owns JSON values only. Device authority, persistence and HTTP authentication
//! remain product responsibilities. V1 binds script and software tasks to one strict major.

#[path = "onboarding.rs"]
mod onboarding;
pub use onboarding::*;
#[path = "tasks.rs"]
mod tasks;
pub use crate::self_service::*;
pub use tasks::*;

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
    "3dd22024a26099bcaf9f3755544c1b9c0a0eeb739150f4244036244b63ed9ee6";

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
}
impl Capability {
    /// Software support always refers to one concrete native/script scope profile.
    pub fn is_software(self) -> bool {
        !matches!(
            self,
            Self::InventoryCollectionV1 | Self::TaskExecuteV1 | Self::MdmEnrollmentV1
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
        }
    }
}
/// The only supported ordered capability sets for Agent V1.
pub fn supported_capabilities(value: &[Capability]) -> bool {
    value.first() == Some(&Capability::InventoryCollectionV1)
        && value.len() <= 20
        && value.windows(2).all(|pair| pair[0] < pair[1])
}

/// Server-owned report source returned after registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportSource {
    /// Built-in RSS Agent inventory collector.
    #[serde(rename = "agent.builtin")]
    AgentBuiltin,
}

/// Durable registration result. It never contains the submitted credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingProfile {
    /// Exact wire major.
    pub wire_version: u8,
    /// Registration operation replay identity.
    #[serde(with = "strict_uuid")]
    pub operation_id: Uuid,
    /// Server-owned product device identity.
    pub device_id: String,
    /// Immutable registration identity.
    #[serde(with = "strict_uuid")]
    pub registration_id: Uuid,
    /// Channel-local registration generation.
    pub generation: u64,
    /// Authorized report source.
    pub source: ReportSource,
    /// Observation epoch for this registration.
    #[serde(with = "strict_uuid")]
    pub epoch: Uuid,
    /// Exact accepted capability set.
    pub capabilities: Vec<Capability>,
    /// Server-selected built-in collector versions for this registration.
    pub collections: Vec<CollectionDefinition>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawBindingProfile {
    wire_version: u8,
    #[serde(with = "strict_uuid")]
    operation_id: Uuid,
    device_id: String,
    #[serde(with = "strict_uuid")]
    registration_id: Uuid,
    generation: u64,
    source: ReportSource,
    #[serde(with = "strict_uuid")]
    epoch: Uuid,
    capabilities: Vec<Capability>,
    collections: Vec<CollectionDefinition>,
}
impl<'de> Deserialize<'de> for BindingProfile {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawBindingProfile::deserialize(deserializer)?;
        if raw.wire_version != WIRE_VERSION
            || raw.collections.is_empty()
            || raw.collections.len() > 16
            || raw
                .collections
                .iter()
                .any(|d| d.source() != rss_mdm_inventory::Source::AgentBuiltin)
            || raw
                .collections
                .iter()
                .map(|d| d.dataset())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != raw.collections.len()
            || raw.generation == 0
            || raw.generation > i64::MAX as u64
            || !supported_capabilities(&raw.capabilities)
            || raw.device_id.trim().is_empty()
            || raw.device_id.chars().count() > 256
            || raw.device_id.chars().any(char::is_control)
        {
            return Err(D::Error::custom(WireError::InvalidValue));
        }
        Ok(Self {
            wire_version: raw.wire_version,
            operation_id: raw.operation_id,
            device_id: raw.device_id,
            registration_id: raw.registration_id,
            generation: raw.generation,
            source: raw.source,
            epoch: raw.epoch,
            capabilities: raw.capabilities,
            collections: raw.collections,
        })
    }
}

/// One field and its explicit outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldValue {
    /// Field identity.
    pub field: FieldKey,
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
    #[serde(with = "strict_uuid")]
    report_id: Uuid,
    sequence: u64,
    observed_at: i64,
    collection: CollectionDefinition,
    body: ReportBody,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawReportRequest {
    wire_version: u8,
    #[serde(with = "strict_uuid")]
    report_id: Uuid,
    sequence: u64,
    observed_at: i64,
    collection: CollectionDefinition,
    body: ReportBody,
}
impl<'de> Deserialize<'de> for ReportRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawReportRequest::deserialize(deserializer)?;
        if raw.wire_version != WIRE_VERSION {
            return Err(D::Error::custom(WireError::InvalidValue));
        }
        Self::new(
            raw.report_id,
            raw.sequence,
            raw.observed_at,
            raw.collection,
            raw.body,
        )
        .map_err(D::Error::custom)
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
                return Ok(Self {
                    wire_version: WIRE_VERSION,
                    report_id,
                    sequence,
                    observed_at,
                    collection,
                    body,
                });
            }
        };
        if values.len() > 128
            || values.iter().any(|value| {
                !collection
                    .field(value.field)
                    .is_ok_and(|f| value.value.encode(f).is_ok())
            })
        {
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
            collection,
            body,
        })
    }
    /// Frozen collector identity and field schemas, checked against the server's published version.
    pub fn collection(&self) -> &CollectionDefinition {
        &self.collection
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportAck {
    /// Exact wire major.
    pub wire_version: u8,
    /// Report identity.
    #[serde(with = "strict_uuid")]
    pub report_id: Uuid,
    /// Authoritative server receipt time as Unix seconds.
    pub received_at: i64,
    /// Durable intake status.
    pub intake: IntakeStatus,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawReportAck {
    wire_version: u8,
    #[serde(with = "strict_uuid")]
    report_id: Uuid,
    received_at: i64,
    intake: IntakeStatus,
}
impl<'de> Deserialize<'de> for ReportAck {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawReportAck::deserialize(deserializer)?;
        if raw.wire_version != WIRE_VERSION || raw.received_at < 0 {
            return Err(D::Error::custom(WireError::InvalidValue));
        }
        Ok(Self {
            wire_version: raw.wire_version,
            report_id: raw.report_id,
            received_at: raw.received_at,
            intake: raw.intake,
        })
    }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    /// Closed machine-readable code.
    pub code: ErrorCode,
}

/// Shared field and frozen collector contracts owned by Inventory.
pub use rss_mdm_inventory::{CollectedValue, CollectionDefinition, FieldKey, Scalar};

#[path = "chunks.rs"]
mod chunks;
pub use chunks::{
    ChunkedTaskResult, OUTPUT_CHUNK_BYTES, OUTPUT_MAX_BYTES, OutputChunk, OutputManifest,
};
