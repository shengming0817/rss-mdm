//! Persistent authored assignment. A scope reference is never a frozen device list.
use crate::Error;
use crate::schedule::{Schedule, Trigger};
use crate::{Architecture, Platform};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

/// Opaque immutable resource selection, resolved by the product composition.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ResourceBinding {
    /// One exact script or configuration variant.
    Exact(ExactResourceBinding),
    /// One logical software version with exact target variants.
    Software(SoftwareResourceBinding),
}
/// Exact selection for a script or native configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactResourceBinding {
    /// Opaque resource identity.
    pub id: String,
    /// Immutable resource version identity.
    pub version: String,
    /// Requested resource platform.
    pub platform: Platform,
    /// Requested machine architecture.
    pub architecture: Architecture,
    /// Exact resource variant key.
    pub variant: String,
}
/// Supported software target coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareTarget {
    /// Windows x86-64.
    WindowsX86_64,
    /// Windows ARM64.
    WindowsAarch64,
    /// macOS x86-64.
    MacosX86_64,
    /// macOS ARM64.
    MacosAarch64,
}
impl SoftwareTarget {
    /// Select the closed coordinate for a platform and architecture.
    pub fn new(platform: Platform, architecture: Architecture) -> Self {
        match (platform, architecture) {
            (Platform::Windows, Architecture::X86_64) => Self::WindowsX86_64,
            (Platform::Windows, Architecture::Aarch64) => Self::WindowsAarch64,
            (Platform::Macos, Architecture::X86_64) => Self::MacosX86_64,
            (Platform::Macos, Architecture::Aarch64) => Self::MacosAarch64,
        }
    }
    /// Platform and architecture selected by this coordinate.
    pub fn parts(self) -> (Platform, Architecture) {
        match self {
            Self::WindowsX86_64 => (Platform::Windows, Architecture::X86_64),
            Self::WindowsAarch64 => (Platform::Windows, Architecture::Aarch64),
            Self::MacosX86_64 => (Platform::Macos, Architecture::X86_64),
            Self::MacosAarch64 => (Platform::Macos, Architecture::Aarch64),
        }
    }
}
/// Exact software variants belonging to a single immutable resource version.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareResourceBinding {
    /// Closed software resource discriminator.
    pub kind: SoftwareResourceKind,
    /// Logical resource identity.
    pub id: String,
    /// Immutable resource version.
    pub version: String,
    /// Exact variant for each supported platform and architecture.
    pub variants: BTreeMap<SoftwareTarget, String>,
}
/// Closed resource kind for software bindings.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareResourceKind {
    /// Enterprise software.
    Software,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
/// Execution-history rule evaluated when a device checks in.
pub enum Frequency {
    #[default]
    /// At most once for each immutable execution version and registration.
    OncePerVersion,
    /// At most once for each membership entry and registration.
    OncePerEntry,
    /// Each distinct due trigger, subject to outstanding execution safety.
    EveryTrigger,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
/// Supported configuration behavior when the last assignment exits.
pub enum Exit {
    #[default]
    /// Retain effects when the assignment no longer applies.
    Retain,
    /// Remove only effects that the selected resource supports removing.
    Remove,
}
/// Explicit delivery authority for the native behaviors in a software dependency closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SoftwareDelivery {
    /// Concrete installers consume approved task content directly.
    Direct,
    /// Native package managers consume already published immutable snapshots from this output source.
    Native {
        /// Exact configured logical output source; imported provenance remains separate.
        source: String,
        /// Exact enterprise publication environment.
        ring: SoftwareDeliveryRing,
    },
}
/// Explicit software publication environment selected by the deployment author.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareDeliveryRing {
    /// Test publication.
    Test,
    /// Pilot publication.
    Pilot,
    /// Production publication.
    Production,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
/// Each action owns its inputs; registration never requires a fictitious resource.
pub enum Action {
    /// A side-effecting or collection action admitted on Agent check-in.
    Execution {
        /// Exact immutable script resource.
        resource: ResourceBinding,
        /// Literal parameters validated against the selected script.
        parameters: Value,
        #[serde(default = "default_schedule")]
        /// Calendar and event conditions; defaults to check-in without an end.
        schedule: Schedule,
        #[serde(default)]
        /// History deduplication rule; defaults to once per version.
        frequency: Frequency,
        /// Maximum lifetime of each admitted run, from 60 seconds through seven days.
        run_lifetime_seconds: u32,
    },
    /// A native MDM read template using the same schedule and membership frequency.
    NativeCollection {
        /// Exact immutable native template.
        resource: ResourceBinding,
        #[serde(default = "default_schedule")]
        /// Calendar and check-in trigger.
        schedule: Schedule,
        #[serde(default)]
        /// Existing Policy execution frequency.
        frequency: Frequency,
        /// Lifetime of the accepted collection.
        run_lifetime_seconds: u32,
    },
    /// A persistent native configuration without a script schedule.
    Configuration {
        /// Exact immutable native configuration resource.
        resource: ResourceBinding,
        #[serde(default)]
        /// What to do when this configuration no longer has an owner.
        exit: Exit,
    },
    /// Enterprise software installed or removed through the Agent.
    Software {
        /// Explicit content or frozen native-source delivery authority.
        delivery: SoftwareDelivery,
        /// Approved logical software release and exact platform variants.
        resource: ResourceBinding,
        /// Required, self-service, or explicit removal semantics.
        intent: SoftwareIntent,
        /// Exact enterprise approval to freeze into this execution version.
        admission_operation: Uuid,
        /// Device execution schedule and maintenance window.
        #[serde(default = "default_schedule")]
        schedule: Schedule,
        /// Maximum lifetime of one task.
        run_lifetime_seconds: u32,
        /// Administrator-authored rollout stages.
        rollout: SoftwareRollout,
    },
    /// Install only the product's approved Agent through the source MDM channel.
    EnsureAgentInstalled {
        /// Exact approved Agent release; product identity is checked at publication.
        resource: ResourceBinding,
        /// Exact approval operation, rechecked before any side effect.
        admission_operation: Uuid,
        /// Source-channel scheduling and cooldown.
        #[serde(default = "default_schedule")]
        schedule: Schedule,
        /// Bounded lifetime of this installation and its registration handoff.
        run_lifetime_seconds: u32,
    },
    /// Ask an independently registered Agent to open the standard MDM enrollment flow.
    RequestMdmEnrollment {
        /// Target organization; the product verifies its enrollment authority.
        organization: Uuid,
        /// Source-channel scheduling and cooldown.
        #[serde(default = "default_schedule")]
        schedule: Schedule,
        /// Bounded lifetime; opening the UI does not complete enrollment.
        run_lifetime_seconds: u32,
    },
}
/// Desired software assignment behavior.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareIntent {
    /// Enforce the approved software version.
    RequiredInstall,
    /// Permit an authorized device or user to request installation.
    AvailableInstall,
    /// Explicitly request removal by a supporting definition.
    ExplicitUninstall,
}
/// Time-driven rollout; success rate is an optional additional gate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareRollout {
    /// Ordered stage scopes and opening times.
    pub stages: Vec<SoftwareRolloutStage>,
}
/// One administrator-selected stage.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareRolloutStage {
    /// Scope that becomes eligible at the opening time.
    pub scope: Uuid,
    /// UTC Unix timestamp for automatic opening.
    pub opens_at: i64,
    /// Optional verified-success threshold for the preceding stage.
    pub minimum_verified_percent: Option<u8>,
}
impl SoftwareRolloutStage {
    /// A stage opens at its configured time unless an optional previous-stage rate is unmet.
    pub fn open(&self, now: i64, previous_total: u64, previous_verified: u64) -> bool {
        if now < self.opens_at || previous_verified > previous_total {
            return false;
        }
        self.minimum_verified_percent.is_none_or(|minimum| {
            previous_total > 0
                && u128::from(previous_verified) * 100
                    >= u128::from(previous_total) * u128::from(minimum)
        })
    }
}
fn default_schedule() -> Schedule {
    Schedule {
        trigger: Trigger::CheckIn {
            minimum_seconds: 60,
        },
        misfire: Default::default(),
        not_before: 0,
        until: None,
        jitter_seconds: 0,
        window: None,
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Complete authored Policy definition, without execution progress.
pub struct Definition {
    /// Opaque Scope identity; Scope alone owns membership and entry coordinates.
    pub scope: Uuid,
    /// Closed action or configuration semantics.
    pub action: Action,
}
impl Definition {
    /// Validate closed shape, bounded identities, calendar conditions and run lifetime.
    pub fn validate(&self) -> Result<(), Error> {
        if serde_json::to_vec(self)
            .map_err(|_| Error::Malformed)?
            .len()
            > 4_194_304
        {
            return Err(Error::Malformed);
        }
        if self.scope.is_nil() {
            return Err(Error::Malformed);
        }
        self.action.validate()?;
        Ok(())
    }
}

impl ResourceBinding {
    /// Resource identity shared by both binding kinds.
    pub fn id(&self) -> &str {
        match self {
            Self::Exact(v) => &v.id,
            Self::Software(v) => &v.id,
        }
    }
    /// Immutable version identity shared by both binding kinds.
    pub fn version(&self) -> &str {
        match self {
            Self::Exact(v) => &v.version,
            Self::Software(v) => &v.version,
        }
    }
    /// Exact script or configuration binding, when applicable.
    pub fn exact(&self) -> Option<&ExactResourceBinding> {
        match self {
            Self::Exact(v) => Some(v),
            Self::Software(_) => None,
        }
    }
    /// Software binding, when applicable.
    pub fn software(&self) -> Option<&SoftwareResourceBinding> {
        match self {
            Self::Software(v) => Some(v),
            Self::Exact(_) => None,
        }
    }
    /// Exact variant for a platform and architecture, if assigned.
    pub fn variant_for(&self, platform: Platform, architecture: Architecture) -> Option<&str> {
        match self {
            Self::Exact(v) => (v.platform == platform && v.architecture == architecture)
                .then_some(v.variant.as_str()),
            Self::Software(v) => v
                .variants
                .get(&SoftwareTarget::new(platform, architecture))
                .map(String::as_str),
        }
    }
    /// Validate opaque immutable resource coordinates.
    pub fn validate(&self) -> Result<(), Error> {
        let mut ids = vec![self.id(), self.version()];
        match self {
            Self::Exact(v) => ids.push(&v.variant),
            Self::Software(v) => {
                if v.variants.is_empty() || v.variants.len() > 4 {
                    return Err(Error::Malformed);
                }
                ids.extend(v.variants.values().map(String::as_str));
            }
        }
        for id in ids {
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
                || id.split('/').any(|s| s.is_empty() || s == "." || s == "..")
            {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
}
impl Action {
    /// Closed action identity persisted alongside its optional resource coordinates.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Execution { .. } => "execution",
            Self::NativeCollection { .. } => "native_collection",
            Self::Configuration { .. } => "configuration",
            Self::Software { .. } => "software",
            Self::EnsureAgentInstalled { .. } => "ensure_agent_installed",
            Self::RequestMdmEnrollment { .. } => "request_mdm_enrollment",
        }
    }

    /// Resource reference only for actions that actually consume a resource.
    pub fn resource(&self) -> Option<&ResourceBinding> {
        match self {
            Self::NativeCollection { resource, .. }
            | Self::Execution { resource, .. }
            | Self::Configuration { resource, .. }
            | Self::Software { resource, .. }
            | Self::EnsureAgentInstalled { resource, .. } => Some(resource),
            Self::RequestMdmEnrollment { .. } => None,
        }
    }
    /// Validate calendar and lifetime semantics without owning any targets.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(resource) = self.resource() {
            resource.validate()?;
            let software = matches!(
                self,
                Self::Software { .. } | Self::EnsureAgentInstalled { .. }
            );
            if software != resource.software().is_some() {
                return Err(Error::Malformed);
            }
        }
        match self {
            Action::Execution {
                schedule,
                run_lifetime_seconds,
                ..
            }
            | Action::NativeCollection {
                schedule,
                run_lifetime_seconds,
                ..
            } => {
                schedule.validate()?;
                if !(60..=604800).contains(run_lifetime_seconds) {
                    return Err(Error::Malformed);
                }
            }
            Action::Software {
                admission_operation,
                schedule,
                run_lifetime_seconds,
                rollout,
                delivery,
                ..
            } => {
                schedule.validate()?;
                if let SoftwareDelivery::Native { source, .. } = delivery
                    && (source.is_empty()
                        || source.len() > 128
                        || !source
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
                {
                    return Err(Error::Malformed);
                }
                if admission_operation.is_nil()
                    || !(60..=604800).contains(run_lifetime_seconds)
                    || rollout.stages.is_empty()
                    || rollout.stages.len() > 32
                {
                    return Err(Error::Malformed);
                }
                if rollout.stages[0].minimum_verified_percent.is_some() {
                    return Err(Error::Malformed);
                }
                let mut previous = None;
                let mut scopes = std::collections::BTreeSet::new();
                for stage in &rollout.stages {
                    if stage.scope.is_nil()
                        || stage.opens_at < 0
                        || previous.is_some_and(|v| stage.opens_at <= v)
                        || stage.minimum_verified_percent.is_some_and(|v| v > 100)
                        || !scopes.insert(stage.scope)
                    {
                        return Err(Error::Malformed);
                    }
                    previous = Some(stage.opens_at);
                }
            }
            Action::Configuration { .. } => {}
            Action::EnsureAgentInstalled {
                admission_operation,
                schedule,
                run_lifetime_seconds,
                ..
            } => {
                schedule.validate()?;
                if admission_operation.is_nil() || !(60..=604800).contains(run_lifetime_seconds) {
                    return Err(Error::Malformed);
                }
            }
            Action::RequestMdmEnrollment {
                organization,
                schedule,
                run_lifetime_seconds,
            } => {
                schedule.validate()?;
                if organization.is_nil() || !(60..=604800).contains(run_lifetime_seconds) {
                    return Err(Error::Malformed);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn configuration() -> serde_json::Value {
        json!({"scope":"11111111-1111-1111-1111-111111111111","action": {"resource": {"id":"firewall","version":"v1","platform":"windows","architecture":"x86_64","variant":"default"},"kind":"configuration","exit":"retain"}})
    }
    #[test]
    fn configuration_cannot_accept_execution_fields() {
        let v = configuration();
        let d: Definition = serde_json::from_value(v.clone()).unwrap();
        d.validate().unwrap();
        for field in ["schedule", "frequency", "parameters", "runLifetimeSeconds"] {
            let mut invalid = v.clone();
            invalid["action"][field] = json!(null);
            assert!(
                serde_json::from_value::<Definition>(invalid).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn execution_defaults_to_checkin_once_per_version_without_an_end() {
        let mut v = configuration();
        v["action"] = json!({"resource":v["action"]["resource"],"kind":"execution","parameters":{},"runLifetimeSeconds":300});
        let d: Definition = serde_json::from_value(v).unwrap();
        d.validate().unwrap();
        let Action::Execution {
            schedule,
            frequency,
            ..
        } = d.action
        else {
            panic!()
        };
        assert!(schedule.until.is_none());
        assert!(matches!(frequency, Frequency::OncePerVersion));
    }
    #[test]
    fn policy_cannot_embed_a_device_membership_list() {
        let mut v = configuration();
        v["targets"] = json!({"kind":"devices","devices":["device"]});
        assert!(serde_json::from_value::<Definition>(v).is_err());
    }

    #[test]
    fn software_policy_selects_exact_variants_for_one_logical_application() {
        let value = json!({
            "scope": "11111111-1111-1111-1111-111111111111",
            "action": {"resource": {
                "kind": "software",
                "id": "acme.editor",
                "version": "v2",
                "variants": {
                    "windows_x86_64": "msi-x64",
                    "macos_aarch64": "pkg-arm64"
                }
            },
                "kind": "software",
                "intent": "required_install",
                "delivery": {"kind":"direct"},
                "runLifetimeSeconds": 3600,
                "admissionOperation": "22222222-2222-4222-8222-222222222222",
                "rollout": {"stages": [{"scope": "11111111-1111-1111-1111-111111111111", "opensAt": 0}]}
            }
        });
        let policy: Definition = serde_json::from_value(value).unwrap();
        policy.validate().unwrap();
        assert_eq!(
            policy
                .action
                .resource()
                .unwrap()
                .variant_for(Platform::Windows, Architecture::X86_64),
            Some("msi-x64")
        );
        assert_eq!(
            policy
                .action
                .resource()
                .unwrap()
                .variant_for(Platform::Macos, Architecture::Aarch64),
            Some("pkg-arm64")
        );
        assert_eq!(
            policy
                .action
                .resource()
                .unwrap()
                .variant_for(Platform::Windows, Architecture::Aarch64),
            None
        );
    }
    #[test]
    fn rollout_uses_time_and_only_an_explicit_success_gate() {
        let stage = SoftwareRolloutStage {
            scope: Uuid::new_v4(),
            opens_at: 100,
            minimum_verified_percent: None,
        };
        assert!(!stage.open(99, 10, 0));
        assert!(stage.open(100, 10, 0));
        let gated = SoftwareRolloutStage {
            minimum_verified_percent: Some(80),
            ..stage
        };
        assert!(!gated.open(100, 10, 7));
        assert!(gated.open(100, 10, 8));
        assert!(!gated.open(100, 0, 0));
    }
}
